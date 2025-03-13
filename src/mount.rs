use std::{
    fs::canonicalize,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    path::Path,
};

use anyhow::Result;
use rustix::mount::{
    fsconfig_create, fsconfig_set_string, fsmount, fsopen, move_mount, unmount, FsMountFlags,
    FsOpenFlags, MountAttrFlags, MoveMountFlags, UnmountFlags,
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

pub fn composefs_fsmount(image: impl AsFd, name: &str, basedir: &Path) -> Result<OwnedFd> {
    let erofs = FsHandle::open("erofs")?;
    fsconfig_set_string(erofs.as_fd(), "source", proc_self_fd(&image))?;
    fsconfig_create(erofs.as_fd())?;

    let overlayfs = FsHandle::open("overlay")?;
    fsconfig_set_string(overlayfs.as_fd(), "source", format!("composefs:{name}"))?;
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

pub fn mount_fd<F: AsFd>(image: F, name: &str, basedir: &Path, mountpoint: &str) -> Result<()> {
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
