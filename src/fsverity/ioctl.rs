use std::os::fd::AsFd;

use rustix::io::Errno;
use rustix::ioctl;
use thiserror::Error;

use super::FsVerityHashValue;

/// Measuring fsverity failed.
#[derive(Error, Debug)]
pub enum MeasureVerityError {
    #[error("i/o error")]
    Io(#[from] std::io::Error),
    #[error("Expected algorithm {expected}, found {found}")]
    InvalidDigestAlgorithm { expected: u16, found: u16 },
    #[error("Expected digest size {expected}")]
    InvalidDigestSize { expected: u16 },
}

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

/// Enable fsverity on the target file. This is a thin safe wrapper for the underlying base `ioctl`
/// and hence all constraints apply such as requiring the file descriptor to already be `O_RDONLY`
/// etc.
pub fn fs_ioc_enable_verity<F: AsFd, H: FsVerityHashValue>(fd: F) -> std::io::Result<()> {
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

/// Core definition of a fsverity digest.
#[repr(C)]
pub struct FsVerityDigest<F> {
    digest_algorithm: u16,
    digest_size: u16,
    digest: F,
}

// #define FS_IOC_MEASURE_VERITY   _IORW('f', 134, struct fsverity_digest)
type FsIocMeasureVerity = ioctl::ReadWriteOpcode<b'f', 134, FsVerityDigest<()>>;

/// Measure the fsverity digest of the provided file descriptor.
pub fn fs_ioc_measure_verity<F: AsFd, H: FsVerityHashValue>(
    fd: F,
) -> Result<Option<H>, MeasureVerityError> {
    let digest_size = std::mem::size_of::<H>() as u16;
    let digest_algorithm = H::ALGORITHM as u16;

    let mut digest = FsVerityDigest::<H> {
        digest_algorithm,
        digest_size,
        digest: H::EMPTY,
    };

    let r = unsafe {
        ioctl::ioctl(
            fd,
            ioctl::Updater::<FsIocMeasureVerity, FsVerityDigest<H>>::new(&mut digest),
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
            Ok(Some(digest.digest))
        }
        // This function returns Ok(None) if there's no verity digest found.
        Err(Errno::NODATA | Errno::NOTTY | Errno::OPNOTSUPP) => Ok(None),
        Err(Errno::OVERFLOW) => Err(MeasureVerityError::InvalidDigestSize {
            expected: digest.digest_size,
        }),
        Err(e) => Err(std::io::Error::from(e).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsverity::Sha256HashValue;

    #[test]
    fn test_measure_verity_opt() -> anyhow::Result<()> {
        let tf = tempfile::tempfile()?;
        assert_eq!(
            fs_ioc_measure_verity::<_, Sha256HashValue>(&tf).unwrap(),
            None
        );
        Ok(())
    }
}
