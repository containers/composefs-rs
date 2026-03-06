//! Hash value types and trait definitions for fs-verity.
//!
//! This module defines the FsVerityHashValue trait and concrete implementations
//! for SHA-256 and SHA-512 hash values, including parsing from hex strings
//! and object pathnames.

use core::{fmt, hash::Hash};

use hex::FromHexError;
use sha2::{digest::FixedOutputReset, digest::Output, Digest, Sha256, Sha512};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Trait for fs-verity hash value types supporting SHA-256 and SHA-512.
///
/// This trait defines the interface for hash values used in fs-verity operations,
/// including serialization to/from hex strings and object store pathnames.
pub trait FsVerityHashValue
where
    Self: Clone,
    Self: From<Output<Self::Digest>>,
    Self: FromBytes + Immutable + IntoBytes + KnownLayout + Unaligned,
    Self: Hash + Eq,
    Self: fmt::Debug,
    Self: Send + Sync + Unpin + 'static,
{
    /// The underlying hash digest algorithm type.
    type Digest: Digest + FixedOutputReset + fmt::Debug;
    /// The fs-verity algorithm identifier (1 for SHA-256, 2 for SHA-512).
    const ALGORITHM: u8;
    /// An empty hash value with all bytes set to zero.
    const EMPTY: Self;
    /// The algorithm identifier string ("sha256" or "sha512").
    const ID: &str;

    /// Parse a hash value from a hexadecimal string.
    ///
    /// # Arguments
    /// * `hex` - A hexadecimal string representation of the hash
    ///
    /// # Returns
    /// The parsed hash value, or an error if the input is invalid.
    fn from_hex(hex: impl AsRef<[u8]>) -> Result<Self, FromHexError> {
        let mut value = Self::EMPTY;
        hex::decode_to_slice(hex.as_ref(), value.as_mut_bytes())?;
        Ok(value)
    }

    /// Parse a hash value from an object store directory number and basename.
    ///
    /// Object stores typically use a two-level hierarchy where the first byte
    /// of the hash determines the directory name and the remaining bytes form
    /// the basename.
    ///
    /// # Arguments
    /// * `dirnum` - The directory number (first byte of the hash)
    /// * `basename` - The hexadecimal basename (remaining bytes)
    ///
    /// # Returns
    /// The parsed hash value, or an error if the input is invalid.
    fn from_object_dir_and_basename(
        dirnum: u8,
        basename: impl AsRef<[u8]>,
    ) -> Result<Self, FromHexError> {
        let expected_size = 2 * (size_of::<Self>() - 1);
        let bytes = basename.as_ref();
        if bytes.len() != expected_size {
            return Err(FromHexError::InvalidStringLength);
        }
        let mut result = Self::EMPTY;
        result.as_mut_bytes()[0] = dirnum;
        hex::decode_to_slice(bytes, &mut result.as_mut_bytes()[1..])?;
        Ok(result)
    }

    /// Parse a hash value from a full object pathname.
    ///
    /// Parses a pathname in the format "xx/yyyyyy" where "xxyyyyyy" is the
    /// full hexadecimal hash. The prefix before the two-level hierarchy is ignored.
    ///
    /// # Arguments
    /// * `pathname` - The object pathname (e.g., "ab/cdef1234...")
    ///
    /// # Returns
    /// The parsed hash value, or an error if the input is invalid.
    fn from_object_pathname(pathname: impl AsRef<[u8]>) -> Result<Self, FromHexError> {
        // We want to the trailing part of "....../xx/yyyyyy" where xxyyyyyy is our hex length
        let min_size = 2 * size_of::<Self>() + 1;
        let bytes = pathname.as_ref();
        if bytes.len() < min_size {
            return Err(FromHexError::InvalidStringLength);
        }

        let trailing = &bytes[bytes.len() - min_size..];
        let mut result = Self::EMPTY;
        hex::decode_to_slice(&trailing[0..2], &mut result.as_mut_bytes()[0..1])?;
        if trailing[2] != b'/' {
            return Err(FromHexError::InvalidHexCharacter {
                c: trailing[2] as char,
                index: 2,
            });
        }
        hex::decode_to_slice(&trailing[3..], &mut result.as_mut_bytes()[1..])?;
        Ok(result)
    }

    /// Convert the hash value to an object pathname.
    ///
    /// Formats the hash as "xx/yyyyyy" where xx is the first byte in hex
    /// and yyyyyy is the remaining bytes in hex.
    ///
    /// # Returns
    /// A string in object pathname format.
    fn to_object_pathname(&self) -> String {
        format!(
            "{:02x}/{}",
            self.as_bytes()[0],
            hex::encode(&self.as_bytes()[1..])
        )
    }

    /// Convert the hash value to an object directory name.
    ///
    /// Returns just the first byte of the hash as a two-character hex string.
    ///
    /// # Returns
    /// A string representing the directory name.
    fn to_object_dir(&self) -> String {
        format!("{:02x}", self.as_bytes()[0])
    }

    /// Convert the hash value to a hexadecimal string.
    ///
    /// # Returns
    /// The full hash as a hex string.
    fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }

    /// Convert the hash value to an identifier string with algorithm prefix.
    ///
    /// # Returns
    /// A string in the format "algorithm:hexhash" (e.g., "sha256:abc123...").
    fn to_id(&self) -> String {
        format!("{}:{}", Self::ID, self.to_hex())
    }
}

impl fmt::Debug for Sha256HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.to_hex())
    }
}

impl fmt::Debug for Sha512HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha512:{}", self.to_hex())
    }
}

/// A SHA-256 hash value for fs-verity operations.
///
/// This is a 32-byte hash value using the SHA-256 algorithm.
#[derive(Clone, Eq, FromBytes, Hash, Immutable, IntoBytes, KnownLayout, PartialEq, Unaligned)]
#[repr(C)]
pub struct Sha256HashValue([u8; 32]);

impl From<Output<Sha256>> for Sha256HashValue {
    fn from(value: Output<Sha256>) -> Self {
        Self(value.into())
    }
}

impl FsVerityHashValue for Sha256HashValue {
    type Digest = Sha256;
    const ALGORITHM: u8 = 1;
    const EMPTY: Self = Self([0; 32]);
    const ID: &str = "sha256";
}

/// A SHA-512 hash value for fs-verity operations.
///
/// This is a 64-byte hash value using the SHA-512 algorithm.
#[derive(Clone, Eq, FromBytes, Hash, Immutable, IntoBytes, KnownLayout, PartialEq, Unaligned)]
#[repr(C)]
pub struct Sha512HashValue([u8; 64]);

impl From<Output<Sha512>> for Sha512HashValue {
    fn from(value: Output<Sha512>) -> Self {
        Self(value.into())
    }
}

impl FsVerityHashValue for Sha512HashValue {
    type Digest = Sha512;
    const ALGORITHM: u8 = 2;
    const EMPTY: Self = Self([0; 64]);
    const ID: &str = "sha512";
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_fsverity_hash<H: FsVerityHashValue>() {
        let len = size_of::<H>();
        let hexlen = len * 2;

        let hex = H::EMPTY.to_hex();
        assert_eq!(hex.as_bytes(), [b'0'].repeat(hexlen));

        assert_eq!(H::EMPTY.to_id(), format!("{}:{}", H::ID, hex));
        assert_eq!(format!("{:?}", H::EMPTY), format!("{}:{}", H::ID, hex));

        assert_eq!(H::from_hex(&hex), Ok(H::EMPTY));

        assert_eq!(H::from_hex("lol"), Err(FromHexError::OddLength));
        assert_eq!(H::from_hex("lolo"), Err(FromHexError::InvalidStringLength));
        assert_eq!(
            H::from_hex([b'l'].repeat(hexlen)),
            Err(FromHexError::InvalidHexCharacter { c: 'l', index: 0 })
        );

        assert_eq!(H::from_object_dir_and_basename(0, &hex[2..]), Ok(H::EMPTY));

        assert_eq!(H::from_object_dir_and_basename(0, &hex[2..]), Ok(H::EMPTY));

        assert_eq!(
            H::from_object_dir_and_basename(0, "lol"),
            Err(FromHexError::InvalidStringLength)
        );

        assert_eq!(
            H::from_object_dir_and_basename(0, [b'l'].repeat(hexlen - 2)),
            Err(FromHexError::InvalidHexCharacter { c: 'l', index: 0 })
        );

        assert_eq!(
            H::from_object_pathname(format!("{}/{}", &hex[0..2], &hex[2..])),
            Ok(H::EMPTY)
        );

        assert_eq!(
            H::from_object_pathname(format!("../this/is/ignored/{}/{}", &hex[0..2], &hex[2..])),
            Ok(H::EMPTY)
        );

        assert_eq!(
            H::from_object_pathname(&hex),
            Err(FromHexError::InvalidStringLength)
        );

        assert_eq!(
            H::from_object_pathname("lol"),
            Err(FromHexError::InvalidStringLength)
        );

        assert_eq!(
            H::from_object_pathname([b'l'].repeat(hexlen + 1)),
            Err(FromHexError::InvalidHexCharacter { c: 'l', index: 0 })
        );

        assert_eq!(
            H::from_object_pathname(format!("{}0{}", &hex[0..2], &hex[2..])),
            Err(FromHexError::InvalidHexCharacter { c: '0', index: 2 })
        );
    }

    #[test]
    fn test_sha256hashvalue() {
        test_fsverity_hash::<Sha256HashValue>();
    }

    #[test]
    fn test_sha512hashvalue() {
        test_fsverity_hash::<Sha512HashValue>();
    }
}
