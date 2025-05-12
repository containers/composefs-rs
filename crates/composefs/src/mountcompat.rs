use std::{
    io::Result,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

// This file contains a bunch of helpers that deal with the pre-6.15 mount API

// First: the simple pass-through versions of all of our helpers, for 6.15 or later, along with
// documentation about why they're required.

/// Sets one of the "dir" mount options on an overlayfs to the given file descriptor.  This can
/// either be a freshly-created mount or a O_PATH file descriptor.  On 6.15 kernels this can be
/// done by directly calling `fsconfig_set_fd()`.  On pre-6.15 kernels, it needs to be done by
/// reopening the file descriptor `O_RDONLY` and calling `fsconfig_set_fd()` because `O_PATH` fds
/// are rejecdted.  On very old kernels this needs to be done by way of `fsconfig_set_string()` and
/// `/proc/self/fd/`.
#[cfg(not(feature = "pre-6.15"))]
pub fn overlayfs_set_fd(fs_fd: BorrowedFd, key: &str, fd: BorrowedFd) -> rustix::io::Result<()> {
    rustix::mount::fsconfig_set_fd(fs_fd, key, fd)
}

/// Sets the "lowerdir+" and "datadir+" mount options of an overlayfs mount to the provided file
/// descriptors.  On 6.15 kernels this can be done by directly calling `fsconfig_set_fd()`.  On
/// pre-6.15 kernels, it needs to be done by reopening the file descriptor `O_RDONLY` and calling
/// `fsconfig_set_fd()` because `O_PATH` fds are rejected.  On very old kernels this needs to be
/// done by calculating a `"lowerdir=lower::data"` string using `/proc/self/fd/` filenames and
/// setting it via `fsconfig_set_string()`.
#[cfg(not(feature = "rhel9"))]
pub fn overlayfs_set_lower_and_data_fds(
    fs_fd: impl AsFd,
    lower: impl AsFd,
    data: Option<impl AsFd>,
) -> rustix::io::Result<()> {
    overlayfs_set_fd(fs_fd.as_fd(), "lowerdir+", lower.as_fd())?;
    if let Some(data) = data {
        overlayfs_set_fd(fs_fd.as_fd(), "datadir+", data.as_fd())?;
    }
    Ok(())
}

/// Prepares an open erofs image file for mounting.  On kernels versions after 6.12 this is a
/// simple passthrough.  On older kernels (like on RHEL 9) we need to create a loopback device.
#[cfg(not(feature = "rhel9"))]
pub fn make_erofs_mountable(image: OwnedFd) -> Result<OwnedFd> {
    Ok(image)
}

/// Prepares a mounted filesystem for further use.  On 6.15 kernels this is a no-op, due to the
/// expanded number of operations which can be performed on "detached" mounts.  On earlier kernels
/// we need to create a temporary directory and mount the filesystem there to avoid failures,
/// making sure to detach the mount and remove the directory later.  This function returns an `impl
/// AsFd` which also implements the `Drop` trait in order to facilitate this cleanup.
#[cfg(not(feature = "pre-6.15"))]
pub fn prepare_mount(mnt_fd: OwnedFd) -> Result<impl AsFd> {
    Ok(mnt_fd)
}

// Now: support for pre-6.15 kernels
#[cfg(feature = "pre-6.15")]
#[cfg(not(feature = "rhel9"))]
pub fn overlayfs_set_fd(fs_fd: BorrowedFd, key: &str, fd: BorrowedFd) -> rustix::io::Result<()> {
    use rustix::fs::{openat, Mode, OFlags};
    use rustix::mount::fsconfig_set_fd;

    // We have support for setting fds but not O_PATH ones...
    fsconfig_set_fd(
        fs_fd,
        key,
        openat(
            fd,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?
        .as_fd(),
    )
}

// Required for rhel9: can't set fds directly
#[cfg(feature = "rhel9")]
pub fn overlayfs_set_fd(fs_fd: BorrowedFd, key: &str, fd: BorrowedFd) -> rustix::io::Result<()> {
    rustix::mount::fsconfig_set_string(fs_fd, key, crate::util::proc_self_fd(&fd))
}

#[cfg(feature = "rhel9")]
pub fn overlayfs_set_lower_and_data_fds(
    fs_fd: impl AsFd,
    lower: impl AsFd,
    data: Option<impl AsFd>,
) -> rustix::io::Result<()> {
    use std::os::fd::AsRawFd;

    let lower_fd = lower.as_fd().as_raw_fd().to_string();
    let arg = if let Some(data) = data {
        let data_fd = data.as_fd().as_raw_fd().to_string();
        format!("/proc/self/fd/{lower_fd}::/proc/self/fd/{data_fd}")
    } else {
        format!("/proc/self/fd/{lower_fd}")
    };
    rustix::mount::fsconfig_set_string(fs_fd.as_fd(), "lowerdir", arg)
}

#[cfg(feature = "pre-6.15")]
pub fn prepare_mount(mnt_fd: OwnedFd) -> Result<impl AsFd> {
    tmpmount::TmpMount::mount(mnt_fd)
}

#[cfg(feature = "rhel9")]
pub fn make_erofs_mountable(image: OwnedFd) -> Result<OwnedFd> {
    loopback::loopify(image)
}

// Finally, we have two submodules which do the heavy lifting for loopback devices and temporary
// mountpoints.

// Required before Linux 6.15: it's not possible to use detached mounts with OPEN_TREE_CLONE or
// overlayfs.  Convert them into a non-floating form by mounting them on a temporary directory and
// reopening them as an O_PATH fd.
#[cfg(feature = "pre-6.15")]
mod tmpmount {
    use std::{
        io::Result,
        os::fd::{AsFd, BorrowedFd, OwnedFd},
    };

    use rustix::fs::{open, Mode, OFlags};
    use rustix::mount::{move_mount, unmount, MoveMountFlags, UnmountFlags};

    pub(super) struct TmpMount {
        dir: tempfile::TempDir,
        fd: OwnedFd,
    }

    impl TmpMount {
        pub(super) fn mount(mnt_fd: OwnedFd) -> Result<impl AsFd> {
            let tmp = tempfile::TempDir::new()?;
            move_mount(
                mnt_fd.as_fd(),
                "",
                rustix::fs::CWD,
                tmp.path(),
                MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
            )?;
            let fd = open(
                tmp.path(),
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
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
            let _ = unmount(self.dir.path(), UnmountFlags::DETACH);
        }
    }
}

/// Required before 6.12: erofs can't directly mount files.
#[cfg(feature = "rhel9")]
mod loopback {
    #![allow(unsafe_code)]
    use std::{
        io::Result,
        os::fd::{AsFd, AsRawFd, OwnedFd},
    };

    use rustix::fs::{open, Mode, OFlags};

    struct LoopCtlGetFree;

    // Rustix seems to lack a built-in pattern for an ioctl that returns data by the syscall return
    // value instead of the usual return-by-reference on the args parameter.  Bake our own.
    unsafe impl rustix::ioctl::Ioctl for LoopCtlGetFree {
        type Output = std::ffi::c_int;

        const IS_MUTATING: bool = false;

        fn opcode(&self) -> u32 {
            LOOP_CTL_GET_FREE
        }

        fn as_ptr(&mut self) -> *mut std::ffi::c_void {
            std::ptr::null_mut()
        }

        unsafe fn output_from_ptr(
            out: rustix::ioctl::IoctlOutput,
            _ptr: *mut std::ffi::c_void,
        ) -> rustix::io::Result<std::ffi::c_int> {
            Ok(out)
        }
    }

    const LO_NAME_SIZE: usize = 64;
    const LO_KEY_SIZE: usize = 32;

    #[derive(Default)]
    #[repr(C)]
    struct LoopInfo {
        lo_device: u64,
        lo_inode: u64,
        lo_rdevice: u64,
        lo_offset: u64,
        lo_sizelimit: u64,
        lo_number: u32,
        lo_encrypt_type: u32,
        lo_encrypt_key_size: u32,
        lo_flags: u32,
        // HACK: default trait is only implemented up to [u8; 32]
        lo_file_name: ([u8; LO_NAME_SIZE / 2], [u8; LO_NAME_SIZE / 2]),
        lo_crypt_name: ([u8; LO_NAME_SIZE / 2], [u8; LO_NAME_SIZE / 2]),
        lo_encrypt_key: [u8; LO_KEY_SIZE],
        lo_init: [u64; 2],
    }

    #[derive(Default)]
    #[repr(C)]
    struct LoopConfig {
        fd: u32,
        block_size: u32,
        info: LoopInfo,
        reserved: [u64; 8],
    }

    const LOOP_CTL_GET_FREE: u32 = 0x4C82;
    const LOOP_CONFIGURE: u32 = 0x4C0A;
    const LO_FLAGS_READ_ONLY: u32 = 1;
    const LO_FLAGS_AUTOCLEAR: u32 = 4;
    const LO_FLAGS_DIRECT_IO: u32 = 16;

    pub fn loopify(image: OwnedFd) -> Result<OwnedFd> {
        let control = open(
            "/dev/loop-control",
            OFlags::RDWR | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let index = unsafe { rustix::ioctl::ioctl(&control, LoopCtlGetFree {})? };
        let fd = open(
            format!("/dev/loop{index}"),
            OFlags::RDWR | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let config = LoopConfig {
            fd: image.as_fd().as_raw_fd() as u32,
            block_size: 4096,
            info: LoopInfo {
                lo_flags: LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR | LO_FLAGS_DIRECT_IO,
                ..LoopInfo::default()
            },
            ..LoopConfig::default()
        };
        unsafe {
            rustix::ioctl::ioctl(
                &fd,
                rustix::ioctl::Setter::<{ LOOP_CONFIGURE }, LoopConfig>::new(config),
            )?;
        };
        Ok(fd)
    }
}
