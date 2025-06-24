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
    #[error("fs-verity is not support by filesystem")]
    FilesystemNotSupported,
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
    #[error("File is opened for writing")]
    FileOpenedForWrite,
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
/// See <https://www.kernel.org/doc/html/latest/filesystems/fsverity.html#file-digest-computation>
///
/// # Arguments:
///
///  * `data`: the data to hash
pub fn compute_verity<H: FsVerityHashValue>(data: &[u8]) -> H {
    digest::FsVerityHasher::<H, 12>::hash(data)
}

pub trait FdVerity
where
    Self: AsFd,
{
    /// Enable fs-verity on the given file.
    ///
    /// This essentially boils down to the FS_IOC_ENABLE_VERITY ioctl.
    ///
    /// The file must be stored on a filesystem which supports fs-verity.  The file descriptor must be
    /// opened O_RDONLY and there must be no other writable file descriptors or mappings for the file.
    ///
    /// It's possible to choose the hash algorithm (via the generic parameter) but the blocksize is
    /// currently hardcoded to 4096.  Salt is not supported.
    fn enable_verity<H: FsVerityHashValue>(&self) -> Result<(), EnableVerityError> {
        ioctl::fs_ioc_enable_verity::<H>(self)
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
    fn measure_verity<H: FsVerityHashValue>(&self) -> Result<H, MeasureVerityError> {
        ioctl::fs_ioc_measure_verity(self)
    }

    /// Measures fs-verity on the given file.
    ///
    /// This essentially boils down to the FS_IOC_MEASURE_VERITY ioctl.
    ///
    /// This is the `_opt()` variant of `measure_verity()`.  If the file doesn't have fs-verity
    /// enabled, or resides on a filesystem where fs-verity is unsupported, this function returns None.
    /// Other errors are still passed through.
    fn measure_verity_opt<H: FsVerityHashValue>(&self) -> Result<Option<H>, MeasureVerityError> {
        match ioctl::fs_ioc_measure_verity(self) {
            Ok(result) => Ok(Some(result)),
            Err(MeasureVerityError::VerityMissing | MeasureVerityError::FilesystemNotSupported) => {
                Ok(None)
            }
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
    fn ensure_verity_equal<H: FsVerityHashValue>(
        &self,
        expected: &H,
    ) -> Result<(), CompareVerityError> {
        let found = Self::measure_verity(self)?;
        if expected == &found {
            Ok(())
        } else {
            Err(CompareVerityError::DigestMismatch {
                expected: expected.to_hex(),
                found: found.to_hex(),
            })
        }
    }
}

impl<T> FdVerity for T where T: AsFd {}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, io::Write};

    use rustix::{
        fd::OwnedFd,
        fs::{open, Mode, OFlags},
    };
    use tempfile::tempfile_in;

    use crate::{test::tempfile, util::proc_self_fd};

    use super::*;

    fn rdonly_file_with(data: &[u8]) -> OwnedFd {
        let mut file = tempfile();
        file.write_all(data).unwrap();
        file.sync_data().unwrap();
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
            tf.measure_verity::<Sha256HashValue>().unwrap_err(),
            MeasureVerityError::VerityMissing
        ));

        assert!(tf
            .measure_verity_opt::<Sha256HashValue>()
            .unwrap()
            .is_none());

        assert!(matches!(
            tf.ensure_verity_equal(&Sha256HashValue::EMPTY).unwrap_err(),
            CompareVerityError::Measure(MeasureVerityError::VerityMissing)
        ));
    }

    #[test]
    fn test_verity_simple() {
        let tf = rdonly_file_with(b"hello world");

        // first time: success
        tf.enable_verity::<Sha256HashValue>().unwrap();

        // second time: fail with "already enabled"
        assert!(matches!(
            tf.enable_verity::<Sha256HashValue>().unwrap_err(),
            EnableVerityError::AlreadyEnabled
        ));

        assert_eq!(
            tf.measure_verity::<Sha256HashValue>().unwrap().to_hex(),
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64"
        );

        assert_eq!(
            tf.measure_verity_opt::<Sha256HashValue>()
                .unwrap()
                .unwrap()
                .to_hex(),
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64"
        );

        tf.ensure_verity_equal(
            &Sha256HashValue::from_hex(
                "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64",
            )
            .unwrap(),
        )
        .unwrap();

        let Err(CompareVerityError::DigestMismatch { expected, found }) = tf.ensure_verity_equal(
            &Sha256HashValue::from_hex(
                "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7000000000000",
            )
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
            tf.enable_verity::<Sha256HashValue>().unwrap_err(),
            EnableVerityError::FilesystemNotSupported
        ));

        assert!(matches!(
            tf.measure_verity::<Sha256HashValue>().unwrap_err(),
            MeasureVerityError::FilesystemNotSupported
        ));

        assert!(tf
            .measure_verity_opt::<Sha256HashValue>()
            .unwrap()
            .is_none());

        assert!(matches!(
            tf.ensure_verity_equal(&Sha256HashValue::EMPTY).unwrap_err(),
            CompareVerityError::Measure(MeasureVerityError::FilesystemNotSupported)
        ));
    }

    #[test]
    fn test_verity_wrongdigest_sha512_sha256() {
        let tf = rdonly_file_with(b"hello world");

        // Enable with SHA-512 but then try to read with SHA-256
        tf.enable_verity::<Sha512HashValue>().unwrap();

        assert!(matches!(
            tf.measure_verity::<Sha256HashValue>().unwrap_err(),
            MeasureVerityError::InvalidDigestSize { .. }
        ));

        assert!(matches!(
            tf.measure_verity_opt::<Sha256HashValue>().unwrap_err(),
            MeasureVerityError::InvalidDigestSize { .. }
        ));

        assert!(matches!(
            tf.ensure_verity_equal(&Sha256HashValue::EMPTY).unwrap_err(),
            CompareVerityError::Measure(MeasureVerityError::InvalidDigestSize { .. })
        ));
    }

    #[test]
    fn test_verity_wrongdigest_sha256_sha512() {
        let tf = rdonly_file_with(b"hello world");

        // Enable with SHA-256 but then try to read with SHA-512
        tf.enable_verity::<Sha256HashValue>().unwrap();

        assert!(matches!(
            tf.measure_verity::<Sha512HashValue>().unwrap_err(),
            MeasureVerityError::InvalidDigestAlgorithm { .. }
        ));

        assert!(matches!(
            tf.measure_verity_opt::<Sha512HashValue>().unwrap_err(),
            MeasureVerityError::InvalidDigestAlgorithm { .. }
        ));

        assert!(matches!(
            tf.ensure_verity_equal(&Sha512HashValue::EMPTY).unwrap_err(),
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
            fd.enable_verity::<H>().unwrap();
            fd.ensure_verity_equal(&expected).unwrap();
        }

        for size in cases {
            // the actual data is uninteresting
            let data = vec![0x5a; size];
            assert_kernel_equal(&data, compute_verity::<Sha256HashValue>(&data));
            assert_kernel_equal(&data, compute_verity::<Sha512HashValue>(&data));
        }
    }
}
