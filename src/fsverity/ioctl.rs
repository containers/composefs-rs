use std::os::fd::AsFd;

use anyhow::Result;
use rustix::ioctl;

use super::{FsVerityHashValue, Sha256HashValue};

// See /usr/include/linux/fsverity.h
#[repr(C)]
pub struct FsVerityEnableArg {
    version: u32,
    hash_algorithm: u32,
    block_size: u32,
    salt_size: u32,
    salt_ptr: u64,
    sig_size: u32,
    __reserved1: u32,
    sig_ptr: u64,
    __reserved2: [u64; 11],
}

// #define FS_IOC_ENABLE_VERITY    _IOW('f', 133, struct fsverity_enable_arg)
type FsIocEnableVerity = ioctl::WriteOpcode<b'f', 133, FsVerityEnableArg>;

pub fn fs_ioc_enable_verity<F: AsFd, H: FsVerityHashValue>(fd: F) -> Result<()> {
    unsafe {
        ioctl::ioctl(
            fd,
            ioctl::Setter::<FsIocEnableVerity, FsVerityEnableArg>::new(FsVerityEnableArg {
                version: 1,
                hash_algorithm: H::ALGORITHM as u32,
                block_size: 4096,
                salt_size: 0,
                salt_ptr: 0,
                sig_size: 0,
                __reserved1: 0,
                sig_ptr: 0,
                __reserved2: [0; 11],
            }),
        )?;
    }

    Ok(())
}

pub fn fs_ioc_measure_verity<F: AsFd>(fd: F) -> Result<Sha256HashValue> {
    let mut digest = composefs::fsverity::Digest::new();
    composefs::fsverity::fsverity_digest_from_fd(fd.as_fd(), &mut digest)?;
    let mut r = Sha256HashValue::EMPTY;
    r.copy_from_slice(digest.get());
    Ok(r)
}
