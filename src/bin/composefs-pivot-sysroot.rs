use std::env;
use std::{
    os::fd::{OwnedFd, AsFd},
    path::{Path, PathBuf},
};

use anyhow::{bail, Result};

use rustix::{
    fs::{major, minor, stat, symlink, CWD},
    io::Errno,
    mount::{move_mount, open_tree, unmount, MoveMountFlags, OpenTreeFlags, UnmountFlags},
};

use composefs::{fsverity::Sha256HashValue, mount::composefs_fsmount, repository::Repository};

fn parse_composefs_cmdline(cmdline: &[u8]) -> Result<Sha256HashValue> {
    // TODO?: officially we need to understand quoting with double-quotes...
    for part in cmdline.split(|c| c.is_ascii_whitespace()) {
        if let Some(digest) = part.strip_prefix(b"composefs=") {
            let mut value = [0; 32];
            hex::decode_to_slice(digest, &mut value)?;
            return Ok(value);
        }
    }
    bail!("Unable to find composefs= cmdline parameter");
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

fn pivot_sysroot(image: OwnedFd, name: &str, basedir: impl AsFd, sysroot: &Path) -> Result<()> {
    let _ = gpt_workaround(); // best effort

    let mnt = composefs_fsmount(image, name, basedir)?;

    // try to move /sysroot to /sysroot/sysroot if it exists
    let prev = open_tree(CWD, sysroot, OpenTreeFlags::OPEN_TREE_CLONE)?;
    unmount(sysroot, UnmountFlags::DETACH)?;

    move_mount(
        mnt.as_fd(),
        "",
        rustix::fs::CWD,
        sysroot,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;

    match move_mount(
        prev.as_fd(),
        "",
        mnt.as_fd(),
        "sysroot",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    ) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(err) => Err(err)?,
    }

    // try to bind-mount (original) /sysroot/var to (new) /sysroot/var, if it exists
    match open_tree(prev.as_fd(), "var", OpenTreeFlags::OPEN_TREE_CLONE).and_then(|var| {
        move_mount(
            var.as_fd(),
            "",
            mnt.as_fd(),
            "var",
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
        )
    }) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(err) => Err(err)?,
    }
}

fn main() -> Result<()> {
    let root = match env::args().nth(1) {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from("/sysroot"),
    };
    let repo = Repository::open_path(CWD, root.join("composefs"))?;
    let cmdline = std::fs::read("/proc/cmdline")?;
    let image = hex::encode(parse_composefs_cmdline(&cmdline)?);
    pivot_sysroot(repo.open_image(&image)?, &image, repo.object_dir()?, &root)?;

    Ok(())
}

#[test]
fn test_parse() {
    let failing = ["", "foo", "composefs", "composefs=foo"];
    for case in failing {
        assert!(parse_composefs_cmdline(case.as_bytes()).is_err());
    }
    let digest = "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52";
    let digest_bytes = hex::decode(digest).unwrap();
    similar_asserts::assert_eq!(
        parse_composefs_cmdline(format!("composefs={digest}").as_bytes())
            .unwrap()
            .as_slice(),
        &digest_bytes
    );
}
