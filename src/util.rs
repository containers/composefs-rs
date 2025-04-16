use std::{
    io::{Error, ErrorKind, Read, Result},
    os::fd::{AsFd, AsRawFd},
};

use tokio::io::{AsyncRead, AsyncReadExt};

/// Formats a string like "/proc/self/fd/3" for the given fd.  This can be used to work with kernel
/// APIs that don't directly accept file descriptors.
///
/// This call never fails.
pub(crate) fn proc_self_fd(fd: impl AsFd) -> String {
    format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd())
}

/// This function reads the exact amount of bytes required to fill the buffer, possibly performing
/// multiple reads to do so (and also retrying if required to deal with EINTR).
///
/// The "-ish" is that, unlike the standard Read::read_exact() method, it's possible to determine
/// the difference between an incomplete read (where some amount of bytes were read, but the buffer
/// wasn't filled) and a "clean" EOF where an EOF occurred immediately with no data read at all,
/// which is still considered to be a success.
///
/// # Return value
///
/// There are four possible return values:
///
///  - in case the requested number of bytes were successfully read into the buffer, returns
///    Ok(true)
///  - in case of a "clean" EOF where the stream ends immediately, the function returns
///    Ok(false)
///  - in case of an unexpected EOF after some bytes were read, the function returns an Error with
///    ErrorKind::UnexpectedEof
///  - in case of underlying errors from the Read implementation, the error is returned directly
pub(crate) fn read_exactish(reader: &mut impl Read, buf: &mut [u8]) -> Result<bool> {
    let buflen = buf.len();
    let mut todo: &mut [u8] = buf;

    while !todo.is_empty() {
        match reader.read(todo) {
            Ok(0) => {
                return match todo.len() {
                    s if s == buflen => Ok(false), // clean EOF
                    _ => Err(Error::from(ErrorKind::UnexpectedEof)),
                };
            }
            Ok(n) => todo = &mut todo[n..],
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    Ok(true)
}

/// This function reads the exact amount of bytes required to fill the buffer, possibly performing
/// multiple reads to do so (and also retrying if required to deal with EINTR).
///
/// This is the async version of read_exactish().
pub(crate) async fn read_exactish_async(
    reader: &mut (impl AsyncRead + Unpin),
    buf: &mut [u8],
) -> Result<bool> {
    let buflen = buf.len();
    let mut todo: &mut [u8] = buf;

    while !todo.is_empty() {
        match reader.read(todo).await {
            Ok(0) => {
                return match todo.len() {
                    s if s == buflen => Ok(false), // clean EOF
                    _ => Err(ErrorKind::UnexpectedEof.into()),
                };
            }
            Ok(n) => todo = &mut todo[n..],
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    Ok(true)
}

/// A utility type representing a SHA-256 digest in binary.
pub type Sha256Digest = [u8; 32];

/// Parse a string containing a SHA256 digest in hexidecimal form into a Sha256Digest.
///
/// The string must contain exactly 64 characters and consist entirely of [0-9a-f], case
/// insensitive.
///
/// In case of a failure to parse the string, this function returns ErrorKind::InvalidInput.
pub fn parse_sha256(string: impl AsRef<str>) -> Result<Sha256Digest> {
    let mut value = [0u8; 32];
    hex::decode_to_slice(string.as_ref(), &mut value)
        .map_err(|source| Error::new(ErrorKind::InvalidInput, source))?;
    Ok(value)
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    fn read_exactish_common(read9: fn(&mut &[u8]) -> Result<bool>) {
        // empty returns false immediately
        let mut r = b"" as &[u8];
        assert_eq!(read9(&mut r).unwrap(), false);
        assert_eq!(read9(&mut r).unwrap(), false); // repeatable

        // read one full buffer and then immediate EOF
        r = b"ninebytes";
        assert_eq!(read9(&mut r).unwrap(), true);
        assert_eq!(read9(&mut r).unwrap(), false);

        // read a full buffer and then fail on a partial one
        r = b"twelve bytes";
        assert_eq!(read9(&mut r).unwrap(), true);
        assert_eq!(read9(&mut r).unwrap_err().kind(), ErrorKind::UnexpectedEof);

        // read two full buffers and then immediate EOF
        r = b"eighteen(18) bytes";
        assert_eq!(read9(&mut r).unwrap(), true);
        assert_eq!(read9(&mut r).unwrap(), true);
        assert_eq!(read9(&mut r).unwrap(), false);
    }

    #[test]
    fn test_read_exactish() {
        read_exactish_common(|r| read_exactish(r, &mut [0; 9]));
    }

    #[test]
    fn test_read_exactish_broken_reader() {
        struct BrokenReader;
        impl Read for BrokenReader {
            fn read(&mut self, _buffer: &mut [u8]) -> Result<usize> {
                Err(ErrorKind::NetworkDown.into())
            }
        }

        // read from a broken reader
        assert_eq!(
            read_exactish(&mut BrokenReader, &mut [0; 9])
                .unwrap_err()
                .kind(),
            ErrorKind::NetworkDown
        );
    }

    #[test]
    fn test_read_exactish_async() {
        read_exactish_common(|r| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(read_exactish_async(r, &mut [0; 9]))
        });
    }

    #[tokio::test]
    async fn test_read_exactish_broken_reader_async() {
        // read from a broken reader
        let mut reader = tokio_test::io::Builder::new()
            .read_error(Error::from(ErrorKind::NetworkDown))
            .build();

        assert_eq!(
            read_exactish_async(&mut reader, &mut [0; 9])
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::NetworkDown
        );
    }

    #[test]
    fn test_parse_sha256() {
        let valid = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let valid_caps = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFf";
        let valid_weird = "00112233445566778899aABbcCDdeEFf00112233445566778899AaBbCcDdEeFf";
        assert_eq!(hex::encode(parse_sha256(valid).unwrap()), valid);
        assert_eq!(hex::encode(parse_sha256(valid_caps).unwrap()), valid);
        assert_eq!(hex::encode(parse_sha256(valid_weird).unwrap()), valid);

        fn assert_invalid(x: &str) {
            assert_eq!(parse_sha256(x).unwrap_err().kind(), ErrorKind::InvalidInput);
        }

        // empty
        assert_invalid("");
        // something randomly wrong
        assert_invalid("/etc/shadow");
        // too short
        assert_invalid("00112233445566778899aabbccddeeff00112233445566778899aabbccddeef");
        // too long
        assert_invalid("00112233445566778899aabbccddeeff00112233445566778899aabbccddeefff");
        // non-hex character
        assert_invalid("00112233445566778899aabbccddeeff00112233445566778899aabbccddeefg");
    }
}
