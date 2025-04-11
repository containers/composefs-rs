mod digest;
mod ioctl;

use std::{io::Error, os::fd::AsFd};

use sha2::{digest::FixedOutputReset, digest::Output, Digest, Sha256, Sha512};
use thiserror::Error;

pub trait FsVerityHashValue
where
    Self: Eq + AsRef<[u8]> + Clone,
    Self: From<Output<Self::Digest>>,
{
    type Digest: Digest + FixedOutputReset + std::fmt::Debug;
    const ALGORITHM: u8;
    const EMPTY: Self;
}

pub type Sha256HashValue = [u8; 32];

impl FsVerityHashValue for Sha256HashValue {
    type Digest = Sha256;
    const ALGORITHM: u8 = 1;
    const EMPTY: Self = [0; 32];
}

pub type Sha512HashValue = [u8; 64];

impl FsVerityHashValue for Sha512HashValue {
    type Digest = Sha512;
    const ALGORITHM: u8 = 2;
    const EMPTY: Self = [0; 64];
}

/// Measuring fsverity failed.
#[derive(Error, Debug)] // can't derive PartialEq because of std::io::Error
pub enum MeasureVerityError {
    #[error("{0}")]
    Io(#[from] Error),
    #[error("fs-verity is not enabled on file")]
    VerityMissing,
    #[error("Expected algorithm {expected}, found {found}")]
    InvalidDigestAlgorithm { expected: u16, found: u16 },
    #[error("Expected digest size {expected}")]
    InvalidDigestSize { expected: u16 },
}

/// Enabling fsverity failed.
#[derive(Error, Debug)]
pub enum EnableVerityError {
    #[error("{0}")]
    Io(#[from] Error),
    #[error("Filesystem does not support fs-verity")]
    FilesystemNotSupported,
    #[error("fs-verity is already enabled on file")]
    AlreadyEnabled,
}

/// A verity comparison failed.
#[derive(Error, Debug)]
pub enum CompareVerityError {
    #[error("failed to read verity")]
    Measure(#[from] MeasureVerityError),
    #[error("Expected digest {expected} but found {found}")]
    DigestMismatch { expected: String, found: String },
}

/// Compute the fs-verity digest for a given block of data, in userspace.
///
/// The fs-verity digest is a cryptographic hash over the fs-verity descriptor, which itself
/// contains the root hash of a Merkle tree with an arity determined by the chosen block size and
/// the output size of the chosen hash algorithm.
///
/// It's possible to choose the hash algorithm (via the generic parameter) but the blocksize is
/// currently hardcoded to 4096.  Salt is not supported.
///
/// See https://www.kernel.org/doc/html/latest/filesystems/fsverity.html#file-digest-computation
///
/// # Arguments:
///
///  * `data`: the data to hash
pub fn compute_verity<H: FsVerityHashValue>(data: &[u8]) -> H {
    digest::FsVerityHasher::<H, 12>::hash(data)
}

/// Enable fs-verity on the given file.
///
/// This essentially boils down to the FS_IOC_ENABLE_VERITY ioctl.
///
/// The file must be stored on a filesystem which supports fs-verity.  The file descriptor must be
/// opened O_RDONLY and there must be no other writable file descriptors or mappings for the file.
///
/// It's possible to choose the hash algorithm (via the generic parameter) but the blocksize is
/// currently hardcoded to 4096.  Salt is not supported.
pub fn enable_verity<H: FsVerityHashValue>(fd: impl AsFd) -> Result<(), EnableVerityError> {
    ioctl::fs_ioc_enable_verity::<H>(fd)
}

/// Measures fs-verity on the given file.
///
/// This essentially boils down to the FS_IOC_MEASURE_VERITY ioctl.
///
/// If the file has fs-verity enabled then the hash of the fs-verity descriptor is reported as the
/// successful return value.  In this case, the kernel guarantees that the file content cannot
/// possibly change for as long as the file descriptor exists.
///
/// If the file doesn't have fs-verity enabled then an error will be returned.
///
/// This function is generic over the hash algorithm, which means that you need to choose the
/// expected hash algorithm in advance.  If the file has fs-verity enabled, but with a different
/// hash algorithm, then this is also considered an error.
///
/// For a version of this function which returns an Option<> depending on if fs-verity is enabled
/// or not, see `measure_verity_opt()`.
///
/// Simply measuring the fs-verity value of a file is not a common operation: you usually want to
/// compare it to a value that you already know.  In that case, it's better to use the
/// `compare_verity()` function in this module.
pub fn measure_verity<H: FsVerityHashValue>(fd: impl AsFd) -> Result<H, MeasureVerityError> {
    ioctl::fs_ioc_measure_verity(fd)
}

/// Measures fs-verity on the given file.
///
/// This essentially boils down to the FS_IOC_MEASURE_VERITY ioctl.
///
/// This is the `_opt()` variant of `measure_verity()`.  If the file doesn't have fs-verity
/// enabled, or resides on a filesystem where fs-verity is unsupported, this function returns None.
/// Other errors are still passed through.
pub fn measure_verity_opt<H: FsVerityHashValue>(
    fd: impl AsFd,
) -> Result<Option<H>, MeasureVerityError> {
    match ioctl::fs_ioc_measure_verity(fd) {
        Ok(result) => Ok(Some(result)),
        Err(MeasureVerityError::VerityMissing) => Ok(None),
        Err(other) => Err(other),
    }
}

/// Compare the fs-verity digest of the file versus the expected digest.
///
/// This calls `measure_verity()` and verifies that the result is equal to the expected value.
///
/// If this function returns successfully then the values match.  In this case, the kernel
/// guarantees that the file content cannot possibly change for as long as the file descriptor
/// exists.
///
/// If the file doesn't have fs-verity enabled, the hash value doesn't match, or if a different
/// hash algorithm is in use, the comparison will fail.
pub fn ensure_verity_equal(
    fd: impl AsFd,
    expected: &impl FsVerityHashValue,
) -> Result<(), CompareVerityError> {
    let found = measure_verity(fd)?;
    if expected == &found {
        Ok(())
    } else {
        Err(CompareVerityError::DigestMismatch {
            expected: hex::encode(expected),
            found: hex::encode(found.as_ref()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verity_missing() {
        let tf = tempfile::tempfile().unwrap();
        match measure_verity::<Sha256HashValue>(&tf) {
            Err(MeasureVerityError::VerityMissing) => {}
            o => panic!("Unexpected {o:?}"),
        }
        let h = Sha256HashValue::default();
        match ensure_verity_equal(&tf, &h) {
            Err(CompareVerityError::Measure(MeasureVerityError::VerityMissing)) => {}
            o => panic!("Unexpected {o:?}"),
        }
    }
}
