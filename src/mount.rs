use std::{
    fs::canonicalize,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
};

use anyhow::Result;
use rustix::{
    fs::{open, openat, Mode, OFlags},
    mount::{
        fsconfig_create, fsconfig_set_fd, fsconfig_set_string, fsmount, fsopen, move_mount,
        unmount, FsMountFlags, FsOpenFlags, MountAttrFlags, MoveMountFlags, UnmountFlags,
    },
};

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
    dir: tempfile::TempDir,
    fd: OwnedFd,
}

// Required before Linux 6.15: it's not possible to use floating mounts with OPEN_TREE_CLONE or
// overlayfs.  Convert them into a non-floating form by mounting them on a temporary directory and
// reopening them as an O_PATH fd.
impl TmpMount {
    pub fn fsmount(fs_fd: BorrowedFd) -> Result<impl AsFd> {
        let tmp = tempfile::TempDir::new()?;
        let mnt = fsmount(
            fs_fd,
            FsMountFlags::FSMOUNT_CLOEXEC,
            MountAttrFlags::empty(),
        )?;
        move_mount(
            mnt.as_fd(),
            "",
            rustix::fs::CWD,
            tmp.path(),
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
        )?;
        let fd = open(tmp.path(), OFlags::PATH, Mode::empty())?;
        Ok(TmpMount { dir: tmp, fd })
    }
}

impl AsFd for TmpMount {
    fn as_fd(&self) -> BorrowedFd {
        self.fd.as_fd()
    }
}

impl Drop for TmpMount {
    fn drop(&mut self) {
        unmount(self.dir.path(), UnmountFlags::DETACH).expect("umount(MNT_DETACH) failed");
    }
}

// Required before Linux 6.15: it's not possible to use O_PATH fds
fn fsconfig_set_opath_fd(fs_fd: BorrowedFd, key: &str, fd: BorrowedFd) -> Result<()> {
    let fd = openat(fd, ".", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?;
    Ok(fsconfig_set_fd(fs_fd, key, fd.as_fd())?)
}

fn proc_self_fd<A: AsFd>(fd: A) -> String {
    format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd())
}

pub fn composefs_fsmount(image: impl AsFd, name: &str, basedir: impl AsFd) -> Result<OwnedFd> {
    let erofs = FsHandle::open("erofs")?;
    fsconfig_set_string(erofs.as_fd(), "source", proc_self_fd(&image))?;
    fsconfig_create(erofs.as_fd())?;
    let erofs_mnt = TmpMount::fsmount(erofs.as_fd())?;

    let overlayfs = FsHandle::open("overlay")?;
    fsconfig_set_string(overlayfs.as_fd(), "source", format!("composefs:{name}"))?;
    fsconfig_set_string(overlayfs.as_fd(), "metacopy", "on")?;
    fsconfig_set_string(overlayfs.as_fd(), "redirect_dir", "on")?;
    fsconfig_set_string(overlayfs.as_fd(), "verity", "require")?;
    fsconfig_set_opath_fd(overlayfs.as_fd(), "lowerdir+", erofs_mnt.as_fd())?;
    fsconfig_set_opath_fd(overlayfs.as_fd(), "datadir+", basedir.as_fd())?;
    fsconfig_create(overlayfs.as_fd())?;

    Ok(fsmount(
        overlayfs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?)
}

pub fn mount_fd(image: impl AsFd, name: &str, basedir: impl AsFd, mountpoint: &str) -> Result<()> {
    let mnt = composefs_fsmount(image, name, basedir)?;

    move_mount(
        mnt.as_fd(),
        "",
        rustix::fs::CWD,
        canonicalize(mountpoint)?,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;

    Ok(())
}
