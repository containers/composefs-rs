use std::{
    io::Result,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

use rustix::{
    mount::{
        fsconfig_create, fsconfig_set_flag, fsconfig_set_string, fsmount, fsopen, move_mount,
        FsMountFlags, FsOpenFlags, MountAttrFlags, MoveMountFlags,
    },
    path,
};

use crate::{
    mountcompat::{make_erofs_mountable, overlayfs_set_lower_and_data_fds, prepare_mount},
    util::proc_self_fd,
};

#[derive(Debug)]
pub struct FsHandle {
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

pub fn mount_at(
    fs_fd: impl AsFd,
    dirfd: impl AsFd,
    path: impl path::Arg,
) -> rustix::io::Result<()> {
    move_mount(
        fs_fd.as_fd(),
        "",
        dirfd.as_fd(),
        path,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )
}

pub fn erofs_mount(image: OwnedFd) -> Result<OwnedFd> {
    let image = make_erofs_mountable(image)?;
    let erofs = FsHandle::open("erofs")?;
    fsconfig_set_flag(erofs.as_fd(), "ro")?;
    fsconfig_set_string(erofs.as_fd(), "source", proc_self_fd(&image))?;
    fsconfig_create(erofs.as_fd())?;
    Ok(fsmount(
        erofs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?)
}

pub fn composefs_fsmount(image: OwnedFd, name: &str, basedir: impl AsFd) -> Result<OwnedFd> {
    let erofs_mnt = prepare_mount(erofs_mount(image)?)?;

    let overlayfs = FsHandle::open("overlay")?;
    fsconfig_set_string(overlayfs.as_fd(), "source", format!("composefs:{name}"))?;
    fsconfig_set_string(overlayfs.as_fd(), "metacopy", "on")?;
    fsconfig_set_string(overlayfs.as_fd(), "redirect_dir", "on")?;
    fsconfig_set_string(overlayfs.as_fd(), "verity", "require")?;
    overlayfs_set_lower_and_data_fds(&overlayfs, &erofs_mnt, Some(&basedir))?;
    fsconfig_create(overlayfs.as_fd())?;

    Ok(fsmount(
        overlayfs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?)
}
