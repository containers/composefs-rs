mod digest;
mod hashvalue;
mod ioctl;

use std::{io::Error, os::fd::AsFd};

use thiserror::Error;

pub use hashvalue::{FsVerityHashValue, Sha256HashValue, Sha512HashValue};

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
    use std::{collections::BTreeSet, io::Write};

    use crate::{
        test::tempfile,
        util::{parse_sha256, proc_self_fd},
    };
    use rustix::{
        fd::OwnedFd,
        fs::{open, Mode, OFlags},
    };
    use tempfile::tempfile_in;

    use super::*;

    fn rdonly_file_with(data: &[u8]) -> OwnedFd {
        let mut file = tempfile();
        file.write_all(data).unwrap();
        let fd = open(
            proc_self_fd(&file),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        drop(file); // can't enable verity with outstanding writable fds
        fd
    }

    #[test]
    fn test_verity_missing() {
        let tf = rdonly_file_with(b"");

        assert!(matches!(
            measure_verity::<Sha256HashValue>(&tf).unwrap_err(),
            MeasureVerityError::VerityMissing
        ));

        assert!(measure_verity_opt::<Sha256HashValue>(&tf)
            .unwrap()
            .is_none());

        assert!(matches!(
            ensure_verity_equal(&tf, &Sha256HashValue::EMPTY).unwrap_err(),
            CompareVerityError::Measure(MeasureVerityError::VerityMissing)
        ));
    }

    #[test]
    fn test_verity_simple() {
        let tf = rdonly_file_with(b"hello world");

        // first time: success
        enable_verity::<Sha256HashValue>(&tf).unwrap();

        // second time: fail with "already enabled"
        assert!(matches!(
            enable_verity::<Sha256HashValue>(&tf).unwrap_err(),
            EnableVerityError::AlreadyEnabled
        ));

        assert_eq!(
            hex::encode(measure_verity::<Sha256HashValue>(&tf).unwrap()),
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64"
        );

        assert_eq!(
            hex::encode(measure_verity_opt::<Sha256HashValue>(&tf).unwrap().unwrap()),
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64"
        );

        ensure_verity_equal(
            &tf,
            &parse_sha256("1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64")
                .unwrap(),
        )
        .unwrap();

        let Err(CompareVerityError::DigestMismatch { expected, found }) = ensure_verity_equal(
            &tf,
            &parse_sha256("1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7000000000000")
                .unwrap(),
        ) else {
            panic!("Didn't fail with expected error");
        };
        assert_eq!(
            expected,
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7000000000000"
        );
        assert_eq!(
            found,
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64"
        );
    }

    #[test_with::path(/dev/shm)]
    #[test]
    fn test_verity_error_noverity() {
        let tf = tempfile_in("/dev/shm").unwrap();

        assert!(matches!(
            enable_verity::<Sha256HashValue>(&tf).unwrap_err(),
            EnableVerityError::FilesystemNotSupported
        ));

        assert!(matches!(
            measure_verity::<Sha256HashValue>(&tf).unwrap_err(),
            MeasureVerityError::VerityMissing
        ));

        assert!(measure_verity_opt::<Sha256HashValue>(&tf)
            .unwrap()
            .is_none());

        assert!(matches!(
            ensure_verity_equal(&tf, &Sha256HashValue::EMPTY).unwrap_err(),
            CompareVerityError::Measure(MeasureVerityError::VerityMissing)
        ));
    }

    #[test]
    fn test_verity_wrongdigest_sha512_sha256() {
        let tf = rdonly_file_with(b"hello world");

        // Enable with SHA-512 but then try to read with SHA-256
        enable_verity::<Sha512HashValue>(&tf).unwrap();

        assert!(matches!(
            measure_verity::<Sha256HashValue>(&tf).unwrap_err(),
            MeasureVerityError::InvalidDigestSize { .. }
        ));

        assert!(matches!(
            measure_verity_opt::<Sha256HashValue>(&tf).unwrap_err(),
            MeasureVerityError::InvalidDigestSize { .. }
        ));

        assert!(matches!(
            ensure_verity_equal(&tf, &Sha256HashValue::EMPTY).unwrap_err(),
            CompareVerityError::Measure(MeasureVerityError::InvalidDigestSize { .. })
        ));
    }

    #[test]
    fn test_verity_wrongdigest_sha256_sha512() {
        let tf = rdonly_file_with(b"hello world");

        // Enable with SHA-256 but then try to read with SHA-512
        enable_verity::<Sha256HashValue>(&tf).unwrap();

        assert!(matches!(
            measure_verity::<Sha512HashValue>(&tf).unwrap_err(),
            MeasureVerityError::InvalidDigestAlgorithm { .. }
        ));

        assert!(matches!(
            measure_verity_opt::<Sha512HashValue>(&tf).unwrap_err(),
            MeasureVerityError::InvalidDigestAlgorithm { .. }
        ));

        assert!(matches!(
            ensure_verity_equal(&tf, &Sha512HashValue::EMPTY).unwrap_err(),
            CompareVerityError::Measure(MeasureVerityError::InvalidDigestAlgorithm { .. })
        ));
    }

    #[test]
    fn crosscheck_interesting_cases() {
        // Test the kernel against our userspace calculations.
        //
        // We try to pick some "interesting" sizes to test the edge cases.  The arity of a
        // SHA-256/4096 Merkle tree is 128 = 4096 / 32.  With SHA-512 it's 64 = 4096 / 64.
        // So we try to chose values around the page size times powers of 32 and 64.
        let mut cases = BTreeSet::new();
        for arity in [32, 64] {
            for layer4 in [/* -1, */ 0 /*, 1 */] {
                /* otherwise it's too slow */
                for layer3 in [-1, 0, 1] {
                    for layer2 in [-1, 0, 1] {
                        for layer1 in [-1, 0, 1] {
                            for layer0 in [-1, 0, 1] {
                                let candidate = layer4 * (arity * arity * arity * arity)
                                    + layer3 * (arity * arity * arity)
                                    + layer2 * (arity * arity)
                                    + layer1 * arity
                                    + layer0;
                                if let Ok(size) = usize::try_from(candidate) {
                                    cases.insert(size);
                                }
                            }
                        }
                    }
                }
            }
        }

        fn assert_kernel_equal<H: FsVerityHashValue>(data: &[u8], expected: H) {
            let fd = rdonly_file_with(data);
            enable_verity::<H>(&fd).unwrap();
            ensure_verity_equal(&fd, &expected).unwrap();
        }

        for size in cases {
            // the actual data is uninteresting
            let data = vec![0x5a; size];
            assert_kernel_equal(&data, compute_verity::<Sha256HashValue>(&data));
            assert_kernel_equal(&data, compute_verity::<Sha512HashValue>(&data));
        }
    }
}
