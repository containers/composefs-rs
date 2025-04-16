use sha2::{digest::FixedOutputReset, digest::Output, Digest, Sha256, Sha512};

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
