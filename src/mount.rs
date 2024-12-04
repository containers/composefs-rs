use std::{
    fs::canonicalize,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    path::Path,
};

use anyhow::Result;
use rustix::{
    fs::{major, minor, stat, symlink, CWD},
    io::Errno,
    mount::{
        fsconfig_create, fsconfig_set_string, fsmount, fsopen, move_mount, open_tree, unmount,
        FsMountFlags, FsOpenFlags, MountAttrFlags, MoveMountFlags, OpenTreeFlags, UnmountFlags,
    },
};

use crate::{fsverity, util};

struct FsHandle {
    pub fd: OwnedFd,
}

impl FsHandle {
    pub fn open(name: &str) -> Result<FsHandle> {
        Ok(FsHandle {
            fd: fsopen(name, FsOpenFlags::FSOPEN_CLOEXEC)?,
        })
    }
}

impl AsFd for FsHandle {
    fn as_fd(&self) -> BorrowedFd {
        self.fd.as_fd()
    }
}

impl Drop for FsHandle {
    fn drop(&mut self) {
        let mut buffer = [0u8; 1024];
        loop {
            match rustix::io::read(&self.fd, &mut buffer) {
                Err(_) => return, // ENODATA, among others?
                Ok(0) => return,
                Ok(size) => eprintln!("{}", String::from_utf8(buffer[0..size].to_vec()).unwrap()),
            }
        }
    }
}

struct TmpMount {
    pub dir: tempfile::TempDir,
}

impl TmpMount {
    pub fn mount(fs: BorrowedFd) -> Result<TmpMount> {
        let tmp = tempfile::TempDir::new()?;
        let mnt = fsmount(fs, FsMountFlags::FSMOUNT_CLOEXEC, MountAttrFlags::empty())?;
        move_mount(
            mnt.as_fd(),
            "",
            rustix::fs::CWD,
            tmp.path(),
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
        )?;
        Ok(TmpMount { dir: tmp })
    }
}

impl Drop for TmpMount {
    fn drop(&mut self) {
        unmount(self.dir.path(), UnmountFlags::DETACH).expect("umount(MNT_DETACH) failed");
    }
}

fn proc_self_fd<A: AsFd>(fd: A) -> String {
    format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd())
}

pub fn composefs_fsmount(image: impl AsFd, basedir: &Path) -> Result<OwnedFd> {
    let erofs = FsHandle::open("erofs")?;
    fsconfig_set_string(erofs.as_fd(), "source", proc_self_fd(&image))?;
    fsconfig_create(erofs.as_fd())?;

    let overlayfs = FsHandle::open("overlay")?;
    fsconfig_set_string(overlayfs.as_fd(), "metacopy", "on")?;
    fsconfig_set_string(overlayfs.as_fd(), "redirect_dir", "on")?;
    fsconfig_set_string(overlayfs.as_fd(), "verity", "require")?;

    // unfortunately we can't do this via the fd: we need a tmpdir mountpoint
    let tmp = TmpMount::mount(erofs.as_fd())?; // NB: must live until the "create" operation
    fsconfig_set_string(overlayfs.as_fd(), "lowerdir+", tmp.dir.path())?;
    fsconfig_set_string(overlayfs.as_fd(), "datadir+", basedir)?;
    fsconfig_create(overlayfs.as_fd())?;

    Ok(fsmount(
        overlayfs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?)
}

pub fn mount_fd<F: AsFd>(image: F, basedir: &Path, mountpoint: &str) -> Result<()> {
    let mnt = composefs_fsmount(image, basedir)?;

    move_mount(
        mnt.as_fd(),
        "",
        rustix::fs::CWD,
        canonicalize(mountpoint)?,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;

    Ok(())
}

pub fn pivot_sysroot(image: impl AsFd, basedir: &Path, sysroot: &Path) -> Result<()> {
    // https://github.com/systemd/systemd/issues/35017
    let rootdev = stat("/dev/gpt-auto-root")?;
    let target = format!(
        "/dev/block/{}:{}",
        major(rootdev.st_rdev),
        minor(rootdev.st_rdev)
    );
    symlink(target, "/run/systemd/volatile-root")?;

    let mnt = composefs_fsmount(image, basedir)?;

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

pub struct MountOptions<'a> {
    image: &'a str,
    basedir: &'a Path,
    digest: Option<&'a str>,
    verity: bool,
}

impl<'a> MountOptions<'a> {
    pub fn new(image: &'a str, basedir: &'a Path) -> MountOptions<'a> {
        MountOptions {
            image,
            basedir,
            digest: None,
            verity: false,
        }
    }

    pub fn set_require_verity(&mut self) {
        self.verity = true;
    }

    pub fn set_digest(&mut self, digest: &'a str) {
        self.digest = Some(digest);
    }

    pub fn mount(self, mountpoint: &str) -> Result<()> {
        let image = std::fs::File::open(self.image)?;

        if let Some(expected) = self.digest {
            let expected = util::parse_sha256(expected)?;
            fsverity::ensure_verity(&image, &expected)?;
        }

        mount_fd(image, self.basedir, mountpoint)
    }
}
