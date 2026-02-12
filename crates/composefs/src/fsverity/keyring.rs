//! Kernel keyring integration for fs-verity certificates.
//!
//! This module provides functions for injecting CA certificates into the
//! kernel's `.fs-verity` keyring, enabling kernel-level signature verification
//! for fsverity-protected files.

#![allow(unsafe_code)]

use std::num::NonZeroI32;
use thiserror::Error;

/// The kernel keyring serial for the `.fs-verity` keyring.
///
/// This is `KEY_SPEC_FS_FSVERITY_KEYRING` from the Linux kernel, defined as -4.
/// See `fs/verity/signature.c` in the kernel source.
const KEY_SPEC_FS_FSVERITY_KEYRING: i32 = -4;

/// Errors that can occur when injecting a certificate into the kernel keyring.
#[derive(Error, Debug)]
pub enum KeyringError {
    /// Failed to parse the PEM certificate.
    #[error("failed to parse PEM certificate: {0}")]
    PemParseFailed(String),
    /// Failed to add key to the keyring.
    #[error("failed to add key to keyring: {0}")]
    KeyAddFailed(#[from] keyutils::Error),
    /// Permission denied (requires CAP_SYS_ADMIN).
    #[error("permission denied: adding keys to .fs-verity keyring requires root/CAP_SYS_ADMIN")]
    PermissionDenied,
    /// The keyring does not exist (kernel may not have fs-verity signature support).
    #[error("the .fs-verity keyring does not exist; kernel may not support fs-verity signatures")]
    KeyringNotFound,
}

/// Inject a CA certificate into the kernel's `.fs-verity` keyring.
///
/// This allows the kernel to require valid PKCS#7 signatures when `FS_IOC_ENABLE_VERITY`
/// is called. The certificate must be PEM-encoded and will be converted to DER format
/// before being added to the keyring.
///
/// # Trust Model
///
/// When a certificate is loaded into the `.fs-verity` keyring, the kernel will verify
/// PKCS#7 signatures passed to `FS_IOC_ENABLE_VERITY` against this keyring. If the
/// signature is invalid or the signing certificate is not trusted by a key in the
/// keyring, the ioctl will fail.
///
/// This provides kernel-level enforcement of file integrity signatures, complementing
/// the application-level verification provided by OCI signature artifacts.
///
/// # Requirements
///
/// - Requires `CAP_SYS_ADMIN` capability (typically root).
/// - The kernel must be built with `CONFIG_FS_VERITY_BUILTIN_SIGNATURES=y`.
/// - The `.fs-verity` keyring must exist.
///
/// # Arguments
///
/// * `cert_pem` - The PEM-encoded X.509 certificate to add to the keyring.
///
/// # Example
///
/// ```ignore
/// use composefs::fsverity::inject_fsverity_cert;
///
/// let cert_pem = std::fs::read("my-ca-cert.pem")?;
/// inject_fsverity_cert(&cert_pem)?;
/// println!("Certificate added to .fs-verity keyring");
/// ```
pub fn inject_fsverity_cert(cert_pem: &[u8]) -> Result<(), KeyringError> {
    // Parse PEM to extract DER-encoded certificate
    let cert_der = pem_to_der(cert_pem)?;

    // Get the .fs-verity keyring
    // SAFETY: The kernel defines KEY_SPEC_FS_FSVERITY_KEYRING as a valid special keyring ID.
    // NonZeroI32::new(-4) is guaranteed to succeed since -4 != 0.
    let keyring_serial = NonZeroI32::new(KEY_SPEC_FS_FSVERITY_KEYRING)
        .expect("KEY_SPEC_FS_FSVERITY_KEYRING is non-zero");
    let mut keyring = unsafe { keyutils::Keyring::new(keyring_serial) };

    // Add the certificate as an asymmetric key
    // The description can be anything - the kernel will derive the actual description
    // from the certificate's subject and issuer
    let result = keyring.add_key::<keyutils::keytypes::Asymmetric, _, _>("", &cert_der[..]);

    match result {
        Ok(_key) => Ok(()),
        Err(e) => {
            // Check for specific error conditions using errno values
            // keyutils::Error is an alias for errno::Errno
            let errno_val = e.0;
            if errno_val == rustix::io::Errno::ACCESS.raw_os_error()
                || errno_val == rustix::io::Errno::PERM.raw_os_error()
            {
                Err(KeyringError::PermissionDenied)
            } else if errno_val == 126 || errno_val == 128 {
                // ENOKEY = 126, EKEYREVOKED = 128 on Linux
                Err(KeyringError::KeyringNotFound)
            } else {
                Err(KeyringError::KeyAddFailed(e))
            }
        }
    }
}

/// Parse a PEM-encoded certificate and extract the DER-encoded body.
///
/// This is a simple parser that handles standard PEM format:
/// ```text
/// -----BEGIN CERTIFICATE-----
/// <base64 encoded DER>
/// -----END CERTIFICATE-----
/// ```
fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, KeyringError> {
    let pem_str = std::str::from_utf8(pem)
        .map_err(|e| KeyringError::PemParseFailed(format!("invalid UTF-8: {e}")))?;

    // Find the BEGIN and END markers
    let begin_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";

    let begin_pos = pem_str.find(begin_marker).ok_or_else(|| {
        KeyringError::PemParseFailed("missing BEGIN CERTIFICATE marker".to_string())
    })?;

    let end_pos = pem_str.find(end_marker).ok_or_else(|| {
        KeyringError::PemParseFailed("missing END CERTIFICATE marker".to_string())
    })?;

    if end_pos <= begin_pos {
        return Err(KeyringError::PemParseFailed(
            "END marker before BEGIN marker".to_string(),
        ));
    }

    // Extract the base64-encoded body
    let body_start = begin_pos + begin_marker.len();
    let base64_body = &pem_str[body_start..end_pos];

    // Remove whitespace and decode base64
    let base64_clean: String = base64_body.chars().filter(|c| !c.is_whitespace()).collect();

    // Decode base64 using a simple implementation
    base64_decode(&base64_clean)
        .map_err(|e| KeyringError::PemParseFailed(format!("base64 decode failed: {e}")))
}

/// Simple base64 decoder for PEM parsing.
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn decode_char(c: u8) -> Result<u8, String> {
        if c == b'=' {
            return Ok(0);
        }
        ALPHABET
            .iter()
            .position(|&x| x == c)
            .map(|p| p as u8)
            .ok_or_else(|| format!("invalid base64 character: {}", c as char))
    }

    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("base64 input length must be a multiple of 4".to_string());
    }

    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);

    for chunk in bytes.chunks(4) {
        let a = decode_char(chunk[0])?;
        let b = decode_char(chunk[1])?;
        let c = decode_char(chunk[2])?;
        let d = decode_char(chunk[3])?;

        result.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            result.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            result.push((c << 6) | d);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pem_to_der_valid() {
        // A minimal valid PEM structure (content is not a real certificate)
        let pem = b"-----BEGIN CERTIFICATE-----
SGVsbG8gV29ybGQh
-----END CERTIFICATE-----";
        let result = pem_to_der(pem).unwrap();
        assert_eq!(result, b"Hello World!");
    }

    #[test]
    fn test_pem_to_der_with_whitespace() {
        let pem = b"-----BEGIN CERTIFICATE-----
SGVs
bG8g
V29y
bGQh
-----END CERTIFICATE-----";
        let result = pem_to_der(pem).unwrap();
        assert_eq!(result, b"Hello World!");
    }

    #[test]
    fn test_pem_to_der_missing_begin() {
        let pem = b"SGVsbG8gV29ybGQh
-----END CERTIFICATE-----";
        let result = pem_to_der(pem);
        assert!(matches!(result, Err(KeyringError::PemParseFailed(_))));
    }

    #[test]
    fn test_pem_to_der_missing_end() {
        let pem = b"-----BEGIN CERTIFICATE-----
SGVsbG8gV29ybGQh";
        let result = pem_to_der(pem);
        assert!(matches!(result, Err(KeyringError::PemParseFailed(_))));
    }

    #[test]
    fn test_base64_decode_valid() {
        assert_eq!(base64_decode("SGVsbG8=").unwrap(), b"Hello");
        assert_eq!(base64_decode("SGVsbG8h").unwrap(), b"Hello!");
        assert_eq!(base64_decode("YQ==").unwrap(), b"a");
        assert_eq!(base64_decode("YWI=").unwrap(), b"ab");
        assert_eq!(base64_decode("YWJj").unwrap(), b"abc");
    }

    #[test]
    fn test_base64_decode_invalid_length() {
        assert!(base64_decode("SGVsbG8").is_err());
    }

    #[test]
    fn test_base64_decode_invalid_char() {
        assert!(base64_decode("SGVs!G8=").is_err());
    }
}
