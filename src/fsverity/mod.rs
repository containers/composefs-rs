use std::os::fd::AsFd;

use anyhow::Result;
use ioctl::MeasureVerityError;
use thiserror::Error;

pub mod digest;
pub mod ioctl;

pub trait FsVerityHashValue: Eq + AsRef<[u8]> {
    const ALGORITHM: u8;
    const EMPTY: Self;
}

pub type Sha256HashValue = [u8; 32];

impl FsVerityHashValue for Sha256HashValue {
    const ALGORITHM: u8 = 1;
    const EMPTY: Self = [0; 32];
}

pub type Sha512HashValue = [u8; 64];

impl FsVerityHashValue for Sha512HashValue {
    const ALGORITHM: u8 = 2;
    const EMPTY: Self = [0; 64];
}

/// A verity comparison failed.
#[derive(Error, Debug)]
pub enum CompareVerityError {
    #[error("failed to read verity")]
    Measure(#[from] MeasureVerityError),
    #[error("fsverity is not enabled on target file")]
    VerityMissing,
    #[error("Expected digest {expected} but found {found}")]
    DigestMismatch { expected: String, found: String },
}

/// Require the fsverity digest to be present.
pub fn measure_verity_digest<F: AsFd, H: FsVerityHashValue>(
    fd: F,
) -> Result<H, CompareVerityError> {
    match ioctl::fs_ioc_measure_verity::<_, H>(fd)? {
        Some(found) => Ok(found),
        None => Err(CompareVerityError::VerityMissing),
    }
}

/// Compare the fsverity digest of the file versus the expected digest.
pub fn ensure_verity<F: AsFd, H: FsVerityHashValue>(
    fd: F,
    expected: &H,
) -> Result<(), CompareVerityError> {
    let found = measure_verity_digest::<_, H>(fd)?;
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
    use crate::fsverity::Sha256HashValue;

    #[test]
    fn test_verity_missing() -> anyhow::Result<()> {
        let tf = tempfile::tempfile()?;
        match measure_verity_digest::<_, Sha256HashValue>(&tf) {
            Err(CompareVerityError::VerityMissing) => {}
            o => panic!("Unexpected {o:?}"),
        }
        let h = Sha256HashValue::default();
        match ensure_verity(&tf, &h) {
            Err(CompareVerityError::VerityMissing) => {}
            o => panic!("Unexpected {o:?}"),
        }
        Ok(())
    }
}
