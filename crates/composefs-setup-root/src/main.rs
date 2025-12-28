//! Root filesystem setup utility for composefs-based boot systems.
//!
//! This utility is designed to run during early boot to mount and configure
//! the root filesystem using composefs images. It handles overlay mounts for
//! writable directories, state management, and system integration.

use std::{
    ffi::OsString,
    fmt::Debug,
    io::ErrorKind,
    os::fd::{AsFd, OwnedFd},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::Parser;
use hex::FromHexError;
use rustix::{
    fs::{major, minor, mkdirat, openat, stat, symlink, Mode, OFlags, CWD},
    io::Errno,
    mount::{
        fsconfig_create, fsconfig_set_string, fsmount, open_tree, unmount, FsMountFlags,
        MountAttrFlags, OpenTreeFlags, UnmountFlags,
    },
};
use serde::Deserialize;

use composefs::{
    fsverity::{FsVerityHashValue, Sha256HashValue, Sha512HashValue},
    mount::{mount_at, FsHandle},
    mountcompat::{overlayfs_set_fd, overlayfs_set_lower_and_data_fds, prepare_mount},
    repository::Repository,
};
use composefs_boot::cmdline::get_cmdline_composefs;

// Config file
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum MountType {
    None,
    Bind,
    Overlay,
    Transient,
}

#[derive(Debug, Default, Deserialize)]
struct RootConfig {
    #[serde(default)]
    transient: bool,
}

#[derive(Debug, Default, Deserialize)]
struct MountConfig {
    mount: Option<MountType>,
    #[serde(default)]
    transient: bool,
}

#[derive(Deserialize, Default)]
struct Config {
    #[serde(default)]
    etc: MountConfig,
    #[serde(default)]
    var: MountConfig,
    #[serde(default)]
    root: RootConfig,
}

// Command-line arguments
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(help = "Execute this command (for testing)")]
    cmd: Vec<OsString>,

    #[arg(
        long,
        default_value = "/sysroot",
        help = "sysroot directory in initramfs"
    )]
    sysroot: PathBuf,

    #[arg(
        long,
        default_value = "/usr/lib/composefs/setup-root-conf.toml",
        help = "Config path (for testing)"
    )]
    config: PathBuf,

    // we want to test in a userns, but can't mount erofs there
    #[arg(long, help = "Bind mount root-fs from (for testing)")]
    root_fs: Option<PathBuf>,

    #[arg(long, help = "Kernel commandline args (for testing)")]
    cmdline: Option<String>,

    #[arg(long, help = "Mountpoint (don't replace sysroot, for testing)")]
    target: Option<PathBuf>,
}

// Helpers
fn open_dir(dirfd: impl AsFd, name: impl AsRef<Path> + Debug) -> rustix::io::Result<OwnedFd> {
    openat(
        dirfd,
        name.as_ref(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .inspect_err(|_| {
        eprintln!("Failed to open dir {name:?}");
    })
}

fn ensure_dir(dirfd: impl AsFd, name: &str) -> rustix::io::Result<OwnedFd> {
    match mkdirat(dirfd.as_fd(), name, 0o700.into()) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(err) => Err(err)?,
    }
    open_dir(dirfd, name)
}

fn bind_mount(fd: impl AsFd, path: &str) -> rustix::io::Result<OwnedFd> {
    open_tree(
        fd.as_fd(),
        path,
        OpenTreeFlags::OPEN_TREE_CLONE
            | OpenTreeFlags::OPEN_TREE_CLOEXEC
            | OpenTreeFlags::AT_EMPTY_PATH,
    )
    .inspect_err(|_| {
        eprintln!("Open tree failed for {path}");
    })
}

fn mount_tmpfs() -> Result<OwnedFd> {
    let tmpfs = FsHandle::open("tmpfs")?;
    fsconfig_create(tmpfs.as_fd())?;
    Ok(fsmount(
        tmpfs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?)
}

fn overlay_state(base: impl AsFd, state: impl AsFd, source: &str) -> Result<()> {
    let upper = ensure_dir(state.as_fd(), "upper")?;
    let work = ensure_dir(state.as_fd(), "work")?;

    let overlayfs = FsHandle::open("overlay")?;
    fsconfig_set_string(overlayfs.as_fd(), "source", source)?;
    overlayfs_set_fd(overlayfs.as_fd(), "workdir", work.as_fd())?;
    overlayfs_set_fd(overlayfs.as_fd(), "upperdir", upper.as_fd())?;
    overlayfs_set_lower_and_data_fds(&overlayfs, base.as_fd(), None::<OwnedFd>)?;
    fsconfig_create(overlayfs.as_fd())?;
    let fs = fsmount(
        overlayfs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?;

    Ok(mount_at(fs, base, ".")?)
}

fn overlay_transient(base: impl AsFd) -> Result<()> {
    overlay_state(base, prepare_mount(mount_tmpfs()?)?, "transient")
}

fn open_root_fs(path: &Path) -> Result<OwnedFd> {
    let rootfs = open_tree(
        CWD,
        path,
        OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
    )?;

    // https://github.com/bytecodealliance/rustix/issues/975
    // mount_setattr(rootfs.as_fd()), ..., { ... MountAttrFlags::MOUNT_ATTR_RDONLY ... }, ...)?;

    Ok(rootfs)
}

fn mount_composefs_image(sysroot: &OwnedFd, name: &str, insecure: bool) -> Result<OwnedFd> {
    let mut repo = Repository::<Sha256HashValue>::open_path(sysroot, "composefs")?;
    repo.set_insecure(insecure);
    repo.mount(name).context("Failed to mount composefs image")
}

fn mount_subdir(
    new_root: impl AsFd,
    state: impl AsFd,
    subdir: &str,
    config: MountConfig,
    default: MountType,
) -> Result<()> {
    let mount_type = match config.mount {
        Some(mt) => mt,
        None => match config.transient {
            true => MountType::Transient,
            false => default,
        },
    };

    match mount_type {
        MountType::None => Ok(()),
        MountType::Bind => Ok(mount_at(bind_mount(&state, subdir)?, &new_root, subdir)?),
        MountType::Overlay => overlay_state(
            open_dir(&new_root, subdir)?,
            open_dir(&state, subdir)?,
            "overlay",
        ),
        MountType::Transient => overlay_transient(open_dir(&new_root, subdir)?),
    }
}

fn gpt_workaround() -> Result<()> {
    // https://github.com/systemd/systemd/issues/35017
    let rootdev = stat("/dev/gpt-auto-root")?;
    let target = format!(
        "/dev/block/{}:{}",
        major(rootdev.st_rdev),
        minor(rootdev.st_rdev)
    );
    symlink(target, "/run/systemd/volatile-root")?;
    Ok(())
}

// Try parse cmdline with sha512 digest address first, if failed with invalid length, parse again with legacy sha256 digest address
fn parse_image_address(cmdline: &str) -> Result<(String, bool)> {
    match get_cmdline_composefs::<Sha512HashValue>(cmdline) {
        Ok((id, insecure)) => Ok((id.to_hex(), insecure)),
        Err(e) => {
            if let Some(FromHexError::InvalidStringLength) = e.downcast_ref::<FromHexError>() {
                let (id, insecure) = get_cmdline_composefs::<Sha256HashValue>(cmdline)?;
                Ok((id.to_hex(), insecure))
            } else {
                Err(e)
            }
        }
    }
}

fn setup_root(args: Args) -> Result<()> {
    let config = match std::fs::read_to_string(args.config) {
        Ok(text) => toml::from_str(&text)?,
        Err(err) if err.kind() == ErrorKind::NotFound => Config::default(),
        Err(err) => Err(err)?,
    };

    let sysroot = open_dir(CWD, &args.sysroot)
        .with_context(|| format!("Failed to open sysroot {:?}", args.sysroot))?;

    let cmdline = match &args.cmdline {
        Some(cmdline) => cmdline,
        None => &std::fs::read_to_string("/proc/cmdline")?,
    };

    let (image_addr, insecure) = parse_image_address(cmdline)?;

    let new_root = match args.root_fs {
        Some(path) => open_root_fs(&path).context("Failed to clone specified root fs")?,
        None => mount_composefs_image(&sysroot, &image_addr, insecure)?,
    };

    // we need to clone this before the next step to make sure we get the old one
    let sysroot_clone = bind_mount(&sysroot, "")?;

    // Ideally we build the new root filesystem together before we mount it, but that only works on
    // 6.15 and later.  Before 6.15 we can't mount into a floating tree, so mount it first.  This
    // will leave an abandoned clone of the sysroot mounted under it, but that's OK for now.
    if cfg!(feature = "pre-6.15") {
        mount_at(&new_root, CWD, &args.sysroot)?;
    }

    if config.root.transient {
        overlay_transient(&new_root)?;
    }

    match mount_at(&sysroot_clone, &new_root, "sysroot") {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(err) => Err(err)?,
    }

    // etc + var
    let state = open_dir(open_dir(&sysroot, "state/deploy")?, &image_addr)?;
    mount_subdir(&new_root, &state, "etc", config.etc, MountType::Overlay)?;
    mount_subdir(&new_root, &state, "var", config.var, MountType::Bind)?;

    if cfg!(not(feature = "pre-6.15")) {
        // Replace the /sysroot with the new composed root filesystem
        unmount(&args.sysroot, UnmountFlags::DETACH)?;
        mount_at(&new_root, CWD, &args.sysroot)?;
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let _ = gpt_workaround(); // best effort
    setup_root(args)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse() {
        let failing = ["", "foo", "composefs", "composefs=foo"];
        for case in failing {
            assert!(parse_image_address(case).is_err())
        }
        let digest_legacy = "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52";
        let cmdline_legacy = &format!("composefs={digest_legacy}");
        let (digest_cmdline_legacy, _) =
            get_cmdline_composefs::<Sha256HashValue>(cmdline_legacy).unwrap();
        similar_asserts::assert_eq!(
            digest_cmdline_legacy,
            Sha256HashValue::from_hex(digest_legacy).unwrap()
        );
        let (parsed_addr_legacy, _) = parse_image_address(cmdline_legacy).unwrap();
        assert_eq!(digest_legacy, parsed_addr_legacy);

        let digest = "6f06b5e82420abec546d6e6d3ddd612c50cfa9b707c129345b7ec16f456b92fe35df68999b042e1a6a70dfe75f2fed8cf9f67afd0bf08d2374678d75e2f65a02";
        let cmdline = &format!("composefs={digest}");
        let (digest_cmdline, _) = get_cmdline_composefs::<Sha512HashValue>(cmdline).unwrap();
        similar_asserts::assert_eq!(digest_cmdline, Sha512HashValue::from_hex(digest).unwrap());
        let (parsed_addr, _) = parse_image_address(cmdline).unwrap();
        assert_eq!(digest, parsed_addr);
    }
}
