#![allow(unsafe_code)]

use core::mem::size_of;

use std::{io::Error, os::fd::AsFd};

use rustix::{
    io::Errno,
    ioctl::{ioctl, opcode, Opcode, Setter, Updater},
};

pub use super::{EnableVerityError, FsVerityHashValue, MeasureVerityError};

// See /usr/include/linux/fsverity.h
#[repr(C)]
#[derive(Debug)]
struct FsVerityEnableArg {
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
const FS_IOC_ENABLE_VERITY: Opcode = opcode::write::<FsVerityEnableArg>(b'f', 133);

/// Enable fsverity on the target file. This is a thin safe wrapper for the underlying base `ioctl`
/// and hence all constraints apply such as requiring the file descriptor to already be `O_RDONLY`
/// etc.
pub(super) fn fs_ioc_enable_verity<H: FsVerityHashValue>(
    fd: impl AsFd,
) -> Result<(), EnableVerityError> {
    unsafe {
        match ioctl(
            fd,
            Setter::<{ FS_IOC_ENABLE_VERITY }, FsVerityEnableArg>::new(FsVerityEnableArg {
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
        ) {
            Err(Errno::NOTTY) | Err(Errno::OPNOTSUPP) => {
                Err(EnableVerityError::FilesystemNotSupported)
            }
            Err(Errno::EXIST) => Err(EnableVerityError::AlreadyEnabled),
            Err(e) => Err(Error::from(e).into()),
            Ok(_) => Ok(()),
        }
    }
}

/// Core definition of a fsverity digest.
#[repr(C)]
#[derive(Debug)]
struct FsVerityDigest<F> {
    digest_algorithm: u16,
    digest_size: u16,
    digest: F,
}

// #define FS_IOC_MEASURE_VERITY   _IORW('f', 134, struct fsverity_digest)
const FS_IOC_MEASURE_VERITY: Opcode = opcode::read_write::<FsVerityDigest<()>>(b'f', 134);

/// Measure the fsverity digest of the provided file descriptor.
pub(super) fn fs_ioc_measure_verity<H: FsVerityHashValue>(
    fd: impl AsFd,
) -> Result<H, MeasureVerityError> {
    let digest_size = size_of::<H>() as u16;
    let digest_algorithm = H::ALGORITHM as u16;

    let mut digest = FsVerityDigest::<H> {
        digest_algorithm,
        digest_size,
        digest: H::EMPTY,
    };

    let r = unsafe {
        ioctl(
            fd,
            Updater::<{ FS_IOC_MEASURE_VERITY }, FsVerityDigest<H>>::new(&mut digest),
        )
    };
    match r {
        Ok(()) => {
            if digest.digest_algorithm != digest_algorithm {
                return Err(MeasureVerityError::InvalidDigestAlgorithm {
                    expected: digest.digest_algorithm,
                    found: digest_algorithm,
                });
            }
            if digest.digest_size != digest_size {
                return Err(MeasureVerityError::InvalidDigestSize {
                    expected: digest.digest_size,
                });
            }
            Ok(digest.digest)
        }
        Err(Errno::NODATA | Errno::NOTTY | Errno::OPNOTSUPP) => {
            Err(MeasureVerityError::VerityMissing)
        }
        Err(Errno::OVERFLOW) => Err(MeasureVerityError::InvalidDigestSize {
            expected: digest.digest_size,
        }),
        Err(e) => Err(Error::from(e).into()),
    }
}

#[cfg(test)]
mod tests {
    use std::{mem::ManuallyDrop, os::fd::OwnedFd};

    use rustix::fd::FromRawFd;
    use tempfile::tempfile_in;

    use crate::fsverity::Sha256HashValue;

    use super::*;

    #[test]
    fn test_measure_verity_opt() {
        let tf = tempfile::tempfile().unwrap();
        assert!(matches!(
            fs_ioc_measure_verity::<Sha256HashValue>(&tf),
            Err(MeasureVerityError::VerityMissing)
        ));
    }

    #[test_with::path(/dev/shm)]
    #[test]
    fn test_fs_ioc_enable_verity_wrong_fs() {
        let file = tempfile_in("/dev/shm").unwrap();
        let fd = OwnedFd::from(file);
        let err = fs_ioc_enable_verity::<Sha256HashValue>(&fd).unwrap_err();
        assert!(matches!(err, EnableVerityError::FilesystemNotSupported));
        assert_eq!(err.to_string(), "Filesystem does not support fs-verity",);
    }

    #[test]
    fn test_fs_ioc_enable_verity_bad_fd() {
        let fd = ManuallyDrop::new(unsafe { OwnedFd::from_raw_fd(123456) });
        let res = fs_ioc_enable_verity::<Sha256HashValue>(fd.as_fd());
        let err = res.err().unwrap();
        assert!(matches!(err, EnableVerityError::Io(..)));
        assert_eq!(err.to_string(), "Bad file descriptor (os error 9)",);
    }
}
