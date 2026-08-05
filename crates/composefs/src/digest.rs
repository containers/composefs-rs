//! Cryptographic hash digest wrappers backed by OpenSSL.
//!
//! Provides [`Digest`] and [`FixedOutputReset`] traits with concrete
//! implementations for SHA-256, SHA-384, and SHA-512 using the system
//! OpenSSL library.

use openssl::hash::{Hasher, MessageDigest};
use std::fmt;

/// The output type of a [`Digest`] algorithm.
pub type Output<D> = <D as Digest>::Output;

/// Trait for cryptographic hash digest algorithms.
pub trait Digest: fmt::Debug {
    /// Fixed-size byte array produced by this algorithm.
    type Output: AsRef<[u8]> + AsMut<[u8]> + Clone + fmt::Debug + PartialEq + Eq;

    /// Create a new hasher in its initial state.
    fn new() -> Self;

    /// Feed data into the hasher.
    fn update(&mut self, data: impl AsRef<[u8]>);

    /// Consume the hasher and return the computed digest.
    fn finalize(self) -> Self::Output;

    /// One-shot convenience: hash `data` and return the digest.
    fn digest(data: impl AsRef<[u8]>) -> Self::Output
    where
        Self: Sized,
    {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

/// A [`Digest`] that can be finalized and reused without re-allocating.
pub trait FixedOutputReset: Digest {
    /// Return the computed digest and reset the hasher for reuse.
    fn finalize_reset(&mut self) -> Self::Output;
}

macro_rules! impl_digest {
    ($name:ident, $md:expr, $size:literal) => {
        /// OpenSSL-backed hasher.
        pub struct $name(Hasher);

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl Digest for $name {
            type Output = [u8; $size];

            fn new() -> Self {
                Self(Hasher::new($md).expect(concat!(stringify!($name), " hasher creation failed")))
            }

            fn update(&mut self, data: impl AsRef<[u8]>) {
                self.0
                    .update(data.as_ref())
                    .expect(concat!(stringify!($name), " update failed"));
            }

            fn finalize(mut self) -> [u8; $size] {
                let result = self
                    .0
                    .finish()
                    .expect(concat!(stringify!($name), " finalize failed"));
                let mut out = [0u8; $size];
                out.copy_from_slice(&result);
                out
            }
        }

        impl FixedOutputReset for $name {
            fn finalize_reset(&mut self) -> [u8; $size] {
                let result = self
                    .0
                    .finish()
                    .expect(concat!(stringify!($name), " finalize failed"));
                let mut out = [0u8; $size];
                out.copy_from_slice(&result);
                out
            }
        }
    };
}

impl_digest!(Sha256, MessageDigest::sha256(), 32);
impl_digest!(Sha384, MessageDigest::sha384(), 48);
impl_digest!(Sha512, MessageDigest::sha512(), 64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty() {
        let hash = Sha256::digest(b"");
        assert_eq!(
            hex::encode(hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hello() {
        let hash = Sha256::digest(b"hello world");
        assert_eq!(
            hex::encode(hash),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn sha256_incremental() {
        let mut h = Sha256::new();
        h.update(b"hello ");
        h.update(b"world");
        let hash = h.finalize();
        assert_eq!(
            hex::encode(hash),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn sha256_finalize_reset() {
        let mut h = Sha256::new();
        h.update(b"hello world");
        let hash1 = h.finalize_reset();

        h.update(b"hello world");
        let hash2 = h.finalize_reset();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn sha384_empty() {
        let hash = Sha384::digest(b"");
        assert_eq!(
            hex::encode(hash),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[test]
    fn sha512_empty() {
        let hash = Sha512::digest(b"");
        assert_eq!(
            hex::encode(hash),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }
}
