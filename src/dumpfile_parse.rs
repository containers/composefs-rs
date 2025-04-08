//! # Parsing and generating composefs dump file entry
//!
//! The composefs project defines a "dump file" which is a textual
//! serializion of the metadata file.  This module supports parsing
//! and generating dump file entries.
use std::borrow::Cow;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fmt::Display;
use std::fmt::Write as WriteFmt;
use std::fs::File;
use std::io::BufRead;
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;

use anyhow::Context;
use anyhow::{anyhow, Result};
use rustix::fs::FileType;

/// https://github.com/torvalds/linux/blob/47ac09b91befbb6a235ab620c32af719f8208399/include/uapi/linux/limits.h#L13
const PATH_MAX: u32 = 4096;
/// Maximum size accepted for inline content.
const MAX_INLINE_CONTENT: u16 = 5000;
/// https://github.com/torvalds/linux/blob/47ac09b91befbb6a235ab620c32af719f8208399/include/uapi/linux/limits.h#L15
/// This isn't exposed in libc/rustix, and in any case we should be conservative...if this ever
/// gets bumped it'd be a hazard.
const XATTR_NAME_MAX: usize = 255;
// See above
const XATTR_LIST_MAX: usize = u16::MAX as usize;
// See above
const XATTR_SIZE_MAX: usize = u16::MAX as usize;

#[derive(Debug, PartialEq, Eq)]
/// An extended attribute entry
pub struct Xattr<'k> {
    /// key
    pub key: Cow<'k, OsStr>,
    /// value
    pub value: Cow<'k, [u8]>,
}
/// A full set of extended attributes
pub type Xattrs<'k> = Vec<Xattr<'k>>;

/// Modification time
#[derive(Debug, PartialEq, Eq)]
pub struct Mtime {
    /// Seconds
    pub sec: u64,
    /// Nanoseconds
    pub nsec: u64,
}

/// A composefs dumpfile entry
#[derive(Debug, PartialEq, Eq)]
pub struct Entry<'p> {
    /// The filename
    pub path: Cow<'p, Path>,
    /// uid
    pub uid: u32,
    /// gid
    pub gid: u32,
    /// mode (includes file type)
    pub mode: u32,
    /// Modification time
    pub mtime: Mtime,
    /// The specific file/directory data
    pub item: Item<'p>,
    /// Extended attributes
    pub xattrs: Xattrs<'p>,
}

#[derive(Debug, PartialEq, Eq)]
/// A serializable composefs entry.
///
/// The `Display` implementation for this type is defined to serialize
/// into a format consumable by `mkcomposefs --from-file`.
pub enum Item<'p> {
    /// A regular, inlined file
    RegularInline {
        /// Number of links
        nlink: u32,
        /// Inline content
        content: Cow<'p, [u8]>,
    },
    /// A regular external file
    Regular {
        /// Size of the file
        size: u64,
        /// Number of links
        nlink: u32,
        /// The backing store path
        path: Cow<'p, Path>,
        /// The fsverity digest
        fsverity_digest: Option<String>,
    },
    /// A character or block device node
    Device {
        /// Number of links
        nlink: u32,
        /// The device number
        rdev: u64,
    },
    /// A symbolic link
    Symlink {
        /// Number of links
        nlink: u32,
        /// Symlink target
        target: Cow<'p, Path>,
    },
    /// A hardlink entry
    Hardlink {
        /// The hardlink target
        target: Cow<'p, Path>,
    },
    /// FIFO
    Fifo {
        /// Number of links
        nlink: u32,
    },
    /// A directory
    Directory {
        /// Size of a directory is not necessarily meaningful
        size: u64,
        /// Number of links
        nlink: u32,
    },
}

/// Unescape a byte array according to the composefs dump file escaping format,
/// limiting the maximum possible size.
fn unescape_limited(s: &str, max: usize) -> Result<Cow<[u8]>> {
    // If there are no escapes, just return the input unchanged. However,
    // it must also be ASCII to maintain a 1-1 correspondence between byte
    // and character.
    if !s.contains('\\') && s.is_ascii() {
        let len = s.len();
        if len > max {
            anyhow::bail!("Input {len} exceeded maximum length {max}");
        }
        return Ok(Cow::Borrowed(s.as_bytes()));
    }
    let mut it = s.chars();
    let mut r = Vec::new();
    while let Some(c) = it.next() {
        if r.len() == max {
            anyhow::bail!("Input exceeded maximum length {max}");
        }
        if c != '\\' {
            write!(r, "{c}").unwrap();
            continue;
        }
        let c = it.next().ok_or_else(|| anyhow!("Unterminated escape"))?;
        let c = match c {
            '\\' => b'\\',
            'n' => b'\n',
            'r' => b'\r',
            't' => b'\t',
            'x' => {
                let mut s = String::new();
                s.push(
                    it.next()
                        .ok_or_else(|| anyhow!("Unterminated hex escape"))?,
                );
                s.push(
                    it.next()
                        .ok_or_else(|| anyhow!("Unterminated hex escape"))?,
                );

                u8::from_str_radix(&s, 16).with_context(|| anyhow!("Invalid hex escape {s}"))?
            }
            o => anyhow::bail!("Invalid escape {o}"),
        };
        r.push(c);
    }
    Ok(r.into())
}

/// Unescape a byte array according to the composefs dump file escaping format.
fn unescape(s: &str) -> Result<Cow<[u8]>> {
    unescape_limited(s, usize::MAX)
}

/// Unescape a string into a Rust `OsStr` which is really just an alias for a byte array,
/// but we also impose a constraint that it can not have an embedded NUL byte.
fn unescape_to_osstr(s: &str) -> Result<Cow<OsStr>> {
    let v = unescape(s)?;
    if v.contains(&0u8) {
        anyhow::bail!("Invalid embedded NUL");
    }
    let r = match v {
        Cow::Borrowed(v) => Cow::Borrowed(OsStr::from_bytes(v)),
        Cow::Owned(v) => Cow::Owned(OsString::from_vec(v)),
    };
    Ok(r)
}

/// Unescape a string into a Rust `Path`, which is like a byte array but
/// with a few constraints:
/// - Cannot contain an embedded NUL
/// - Cannot be empty, or longer than PATH_MAX
fn unescape_to_path(s: &str) -> Result<Cow<Path>> {
    let v = unescape_to_osstr(s).and_then(|v| {
        if v.is_empty() {
            anyhow::bail!("Invalid empty path");
        }
        let l = v.len();
        if l > PATH_MAX as usize {
            anyhow::bail!("Path is too long: {l} bytes");
        }
        Ok(v)
    })?;
    let r = match v {
        Cow::Borrowed(v) => Cow::Borrowed(Path::new(v)),
        Cow::Owned(v) => Cow::Owned(PathBuf::from(v)),
    };
    Ok(r)
}

/// Like [`unescape_to_path`], but also ensures the path is in "canonical"
/// form; this has the same semantics as Rust https://doc.rust-lang.org/std/path/struct.Path.html#method.components
/// which in particular removes `.` and extra `//`.
///
/// We also deny uplinks `..` and empty paths.
fn unescape_to_path_canonical(s: &str) -> Result<Cow<Path>> {
    let p = unescape_to_path(s)?;
    let mut components = p.components();
    let mut r = std::path::PathBuf::new();
    let Some(first) = components.next() else {
        anyhow::bail!("Invalid empty path");
    };
    if first != std::path::Component::RootDir {
        anyhow::bail!("Invalid non-absolute path");
    }
    r.push(first);
    for component in components {
        match component {
            // Prefix is a windows thing; I don't think RootDir or CurDir are reachable
            // after the first component has been RootDir.
            std::path::Component::Prefix(_)
            | std::path::Component::RootDir
            | std::path::Component::CurDir => {
                anyhow::bail!("Internal error in unescape_to_path_canonical");
            }
            std::path::Component::ParentDir => {
                anyhow::bail!("Invalid \"..\" in path");
            }
            std::path::Component::Normal(_) => {
                r.push(component);
            }
        }
    }
    // If the input was already in normal form,
    // then we can just return the original version, which
    // may itself be a Cow::Borrowed, and hence we free our malloc buffer.
    if r.as_os_str().as_bytes() == p.as_os_str().as_bytes() {
        Ok(p)
    } else {
        // Otherwise return our copy.
        Ok(r.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscapeMode {
    Standard,
    XattrKey,
}

/// Escape a byte array according to the composefs dump file text format.
fn escape<W: std::fmt::Write>(out: &mut W, s: &[u8], mode: EscapeMode) -> std::fmt::Result {
    // Empty content must be represented by `-`
    if s.is_empty() {
        return out.write_char('-');
    }
    // But a single `-` must be "quoted".
    if s == b"-" {
        return out.write_str(r"\x2d");
    }
    for c in s.iter().copied() {
        // Escape `=` as hex in xattr keys.
        let is_special = c == b'\\' || (matches!((mode, c), (EscapeMode::XattrKey, b'=')));
        let is_printable = c.is_ascii_alphanumeric() || c.is_ascii_punctuation();
        if is_printable && !is_special {
            out.write_char(c as char)?;
        } else {
            match c {
                b'\\' => out.write_str(r"\\")?,
                b'\n' => out.write_str(r"\n")?,
                b'\t' => out.write_str(r"\t")?,
                b'\r' => out.write_str(r"\r")?,
                o => write!(out, "\\x{:02x}", o)?,
            }
        }
    }
    std::fmt::Result::Ok(())
}

/// If the provided string is empty, map it to `-`.
fn optional_str(s: &str) -> Option<&str> {
    match s {
        "-" => None,
        o => Some(o),
    }
}

impl FromStr for Mtime {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let (sec, nsec) = s
            .split_once('.')
            .ok_or_else(|| anyhow!("Missing . in mtime"))?;
        Ok(Self {
            sec: u64::from_str(sec)?,
            nsec: u64::from_str(nsec)?,
        })
    }
}

impl<'k> Xattr<'k> {
    fn parse(s: &'k str) -> Result<Self> {
        let (key, value) = s
            .split_once('=')
            .ok_or_else(|| anyhow!("Missing = in xattrs"))?;
        let key = unescape_to_osstr(key)?;
        let keylen = key.as_bytes().len();
        if keylen > XATTR_NAME_MAX {
            anyhow::bail!(
                "xattr name too long; max={} found={}",
                XATTR_NAME_MAX,
                keylen
            );
        }
        let value = unescape(value)?;
        let valuelen = value.len();
        if valuelen > XATTR_SIZE_MAX {
            anyhow::bail!(
                "xattr value too long; max={} found={}",
                XATTR_SIZE_MAX,
                keylen
            );
        }
        Ok(Self { key, value })
    }
}

impl<'p> Entry<'p> {
    fn check_nonregfile(content: Option<&str>, fsverity_digest: Option<&str>) -> Result<()> {
        if content.is_some() {
            anyhow::bail!("entry cannot have content");
        }
        if fsverity_digest.is_some() {
            anyhow::bail!("entry cannot have fsverity digest");
        }
        Ok(())
    }

    fn check_rdev(rdev: u64) -> Result<()> {
        if rdev != 0 {
            anyhow::bail!("entry cannot have device (rdev) {rdev}");
        }
        Ok(())
    }

    /// Parse an entry from a composefs dump file line.
    pub fn parse(s: &'p str) -> Result<Entry<'p>> {
        let mut components = s.split(' ');
        let mut next = |name: &str| components.next().ok_or_else(|| anyhow!("Missing {name}"));
        let path = unescape_to_path_canonical(next("path")?)?;
        let size = u64::from_str(next("size")?)?;
        let modeval = next("mode")?;
        let (is_hardlink, mode) = if let Some((_, rest)) = modeval.split_once('@') {
            (true, u32::from_str_radix(rest, 8)?)
        } else {
            (false, u32::from_str_radix(modeval, 8)?)
        };
        let nlink = u32::from_str(next("nlink")?)?;
        let uid = u32::from_str(next("uid")?)?;
        let gid = u32::from_str(next("gid")?)?;
        let rdev = u64::from_str(next("rdev")?)?;
        let mtime = Mtime::from_str(next("mtime")?)?;
        let payload = optional_str(next("payload")?);
        let content = optional_str(next("content")?);
        let fsverity_digest = optional_str(next("digest")?);
        let xattrs = components
            .try_fold((Vec::new(), 0usize), |(mut acc, total_namelen), line| {
                let xattr = Xattr::parse(line)?;
                // Limit the total length of keys.
                let total_namelen = total_namelen.saturating_add(xattr.key.len());
                if total_namelen > XATTR_LIST_MAX {
                    anyhow::bail!("Too many xattrs");
                }
                acc.push(xattr);
                Ok((acc, total_namelen))
            })?
            .0;

        let ty = FileType::from_raw_mode(mode);
        let item = if is_hardlink {
            if ty == FileType::Directory {
                anyhow::bail!("Invalid hardlinked directory");
            }
            let target =
                unescape_to_path_canonical(payload.ok_or_else(|| anyhow!("Missing payload"))?)?;
            // TODO: the dumpfile format suggests to retain all the metadata on hardlink lines
            Item::Hardlink { target }
        } else {
            match ty {
                FileType::RegularFile => {
                    Self::check_rdev(rdev)?;
                    if let Some(path) = payload.as_ref() {
                        let path = unescape_to_path(path)?;
                        Item::Regular {
                            size,
                            nlink,
                            path,
                            fsverity_digest: fsverity_digest.map(ToOwned::to_owned),
                        }
                    } else {
                        // A dumpfile entry with no backing path or payload is treated as an empty file
                        let content = content.unwrap_or_default();
                        let content = unescape_limited(content, MAX_INLINE_CONTENT.into())?;
                        if fsverity_digest.is_some() {
                            anyhow::bail!("Inline file cannot have fsverity digest");
                        }
                        Item::RegularInline { nlink, content }
                    }
                }
                FileType::Symlink => {
                    Self::check_nonregfile(content, fsverity_digest)?;
                    Self::check_rdev(rdev)?;

                    // Note that the target of *symlinks* is not required to be in canonical form,
                    // as we don't actually traverse those links on our own, and we need to support
                    // symlinks that e.g. contain `//` or other things.
                    let target =
                        unescape_to_path(payload.ok_or_else(|| anyhow!("Missing payload"))?)?;
                    let targetlen = target.as_os_str().as_bytes().len();
                    if targetlen > PATH_MAX as usize {
                        anyhow::bail!("Target length too large {}", targetlen);
                    }
                    Item::Symlink { nlink, target }
                }
                FileType::Fifo => {
                    Self::check_nonregfile(content, fsverity_digest)?;
                    Self::check_rdev(rdev)?;

                    Item::Fifo { nlink }
                }
                FileType::CharacterDevice | FileType::BlockDevice => {
                    Self::check_nonregfile(content, fsverity_digest)?;
                    Item::Device { nlink, rdev }
                }
                FileType::Directory => {
                    Self::check_nonregfile(content, fsverity_digest)?;
                    Self::check_rdev(rdev)?;

                    Item::Directory { size, nlink }
                }
                FileType::Socket => {
                    anyhow::bail!("sockets are not supported");
                }
                FileType::Unknown => {
                    anyhow::bail!("Unhandled file type from raw mode: {mode}")
                }
            }
        };
        Ok(Entry {
            path,
            uid,
            gid,
            mode,
            mtime,
            item,
            xattrs,
        })
    }

    /// Remove internal entries
    /// FIXME: This is arguably a composefs-info dump bug?
    pub fn filter_special(mut self) -> Self {
        self.xattrs.retain(|v| {
            !matches!(
                (v.key.as_bytes(), &*v.value),
                (b"trusted.overlay.opaque" | b"user.overlay.opaque", b"x")
            )
        });
        self
    }
}

impl Item<'_> {
    pub(crate) fn size(&self) -> u64 {
        match self {
            Item::Regular { size, .. } | Item::Directory { size, .. } => *size,
            Item::RegularInline { content, .. } => content.len() as u64,
            _ => 0,
        }
    }

    pub(crate) fn nlink(&self) -> u32 {
        match self {
            Item::RegularInline { nlink, .. } => *nlink,
            Item::Regular { nlink, .. } => *nlink,
            Item::Device { nlink, .. } => *nlink,
            Item::Symlink { nlink, .. } => *nlink,
            Item::Directory { nlink, .. } => *nlink,
            Item::Fifo { nlink, .. } => *nlink,
            _ => 0,
        }
    }

    pub(crate) fn rdev(&self) -> u64 {
        match self {
            Item::Device { rdev, .. } => *rdev,
            _ => 0,
        }
    }

    pub(crate) fn payload(&self) -> Option<&Path> {
        match self {
            Item::Regular { path, .. } => Some(path),
            Item::Symlink { target, .. } => Some(target),
            Item::Hardlink { target } => Some(target),
            _ => None,
        }
    }
}

impl Display for Mtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.sec, self.nsec)
    }
}

impl Display for Entry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        escape(f, self.path.as_os_str().as_bytes(), EscapeMode::Standard)?;
        write!(
            f,
            " {} {:o} {} {} {} {} {} ",
            self.item.size(),
            self.mode,
            self.item.nlink(),
            self.uid,
            self.gid,
            self.item.rdev(),
            self.mtime,
        )?;
        // Payload is written for non-inline files, hardlinks and symlinks
        if let Some(payload) = self.item.payload() {
            escape(f, payload.as_os_str().as_bytes(), EscapeMode::Standard)?;
            f.write_char(' ')?;
        } else {
            write!(f, "- ")?;
        }
        match &self.item {
            Item::RegularInline { content, .. } => {
                escape(f, content, EscapeMode::Standard)?;
                write!(f, " -")?;
            }
            Item::Regular {
                fsverity_digest, ..
            } => {
                let fsverity_digest = fsverity_digest.as_deref().unwrap_or("-");
                write!(f, "- {fsverity_digest}")?;
            }
            _ => {
                write!(f, "- -")?;
            }
        }
        for xattr in self.xattrs.iter() {
            f.write_char(' ')?;
            escape(f, xattr.key.as_bytes(), EscapeMode::XattrKey)?;
            f.write_char('=')?;
            escape(f, &xattr.value, EscapeMode::Standard)?;
        }
        std::fmt::Result::Ok(())
    }
}

/// Configuration for parsing a dumpfile
#[derive(Debug, Default)]
pub struct DumpConfig<'a> {
    /// Only dump these toplevel filenames
    pub filters: Option<&'a [&'a str]>,
}

/// Parse the provided composefs into dumpfile entries.
pub fn dump<F>(input: File, config: DumpConfig, mut handler: F) -> Result<()>
where
    F: FnMut(Entry<'_>) -> Result<()> + Send,
{
    let mut proc = Command::new("composefs-info");
    proc.arg("dump");
    if let Some(filter) = config.filters {
        proc.args(filter.iter().flat_map(|f| ["--filter", f]));
    }
    proc.args(["/dev/stdin"])
        .stdin(std::process::Stdio::from(input))
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut proc = proc.spawn().context("Spawning composefs-info")?;

    // SAFETY: we set up these streams
    let child_stdout = proc.stdout.take().unwrap();
    let child_stderr = proc.stderr.take().unwrap();

    std::thread::scope(|s| {
        let stderr_copier = s.spawn(move || {
            let mut child_stderr = std::io::BufReader::new(child_stderr);
            let mut buf = Vec::new();
            std::io::copy(&mut child_stderr, &mut buf)?;
            anyhow::Ok(buf)
        });

        let child_stdout = std::io::BufReader::new(child_stdout);
        for line in child_stdout.lines() {
            let line = line.context("Reading dump stdout")?;
            let entry = Entry::parse(&line)?.filter_special();
            handler(entry)?;
        }

        let r = proc.wait()?;
        let stderr = stderr_copier.join().unwrap()?;
        if !r.success() {
            let stderr = String::from_utf8_lossy(&stderr);
            let stderr = stderr.trim();
            anyhow::bail!("composefs-info dump failed: {r}: {stderr}")
        }

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{BufWriter, Seek},
        process::Stdio,
    };

    use super::*;

    const SPECIAL_DUMP: &str = include_str!("tests/assets/special.dump");
    const SPECIALS: &[&str] = &["foo=bar=baz", r"\x01\x02", "-"];
    const UNQUOTED: &[&str] = &["foo!bar", "hello-world", "--"];

    fn mkcomposefs(dumpfile: &str, out: &mut File) -> Result<()> {
        let mut tf = tempfile::tempfile().map(BufWriter::new)?;
        tf.write_all(dumpfile.as_bytes())?;
        let mut tf = tf.into_inner()?;
        tf.seek(std::io::SeekFrom::Start(0))?;
        let mut mkcomposefs = Command::new("mkcomposefs")
            .args(["--from-file", "-", "-"])
            .stdin(Stdio::from(tf))
            .stdout(Stdio::from(out.try_clone()?))
            .stderr(Stdio::inherit())
            .spawn()?;

        let st = mkcomposefs.wait()?;
        if !st.success() {
            anyhow::bail!("mkcomposefs failed: {st}");
        };

        Ok(())
    }

    #[test]
    fn test_escape_specials() {
        let cases = [("", "-"), ("-", r"\x2d")];
        for (source, expected) in cases {
            let mut buf = String::new();
            escape(&mut buf, source.as_bytes(), EscapeMode::Standard).unwrap();
            assert_eq!(&buf, expected);
        }
    }

    #[test]
    fn test_escape_roundtrip() {
        let cases = SPECIALS.iter().chain(UNQUOTED);
        for case in cases {
            let mut buf = String::new();
            escape(&mut buf, case.as_bytes(), EscapeMode::Standard).unwrap();
            let case2 = unescape(&buf).unwrap();
            assert_eq!(case, &String::from_utf8(case2.into()).unwrap());
        }
    }

    #[test]
    fn test_escape_unquoted() {
        let cases = UNQUOTED;
        for case in cases {
            let mut buf = String::new();
            escape(&mut buf, case.as_bytes(), EscapeMode::Standard).unwrap();
            assert_eq!(case, &buf);
        }
    }

    #[test]
    fn test_escape_quoted() {
        // We don't escape `=` in standard mode
        {
            let mut buf = String::new();
            escape(&mut buf, b"=", EscapeMode::Standard).unwrap();
            assert_eq!(buf, "=");
        }
        // Verify other special cases
        let cases = &[("=", r"\x3d"), ("-", r"\x2d")];
        for (src, expected) in cases {
            let mut buf = String::new();
            escape(&mut buf, src.as_bytes(), EscapeMode::XattrKey).unwrap();
            assert_eq!(expected, &buf);
        }
    }

    #[test]
    fn test_unescape() {
        assert_eq!(unescape("").unwrap().len(), 0);
        assert_eq!(unescape_limited("", 0).unwrap().len(), 0);
        assert!(unescape_limited("foobar", 3).is_err());
        // This is borrowed input
        assert!(matches!(
            unescape_limited("foobar", 6).unwrap(),
            Cow::Borrowed(_)
        ));
        // But non-ASCII is currently owned out of conservatism
        assert!(matches!(unescape_limited("→", 6).unwrap(), Cow::Owned(_)));
        assert!(unescape_limited("foo→bar", 3).is_err());
    }

    #[test]
    fn test_unescape_path() {
        // Empty
        assert!(unescape_to_path("").is_err());
        // Embedded NUL
        assert!(unescape_to_path("\0").is_err());
        assert!(unescape_to_path("foo\0bar").is_err());
        assert!(unescape_to_path("\0foobar").is_err());
        assert!(unescape_to_path("foobar\0").is_err());
        assert!(unescape_to_path("foo\\x00bar").is_err());
        let mut p = "a".repeat(PATH_MAX.try_into().unwrap());
        assert!(unescape_to_path(&p).is_ok());
        p.push('a');
        assert!(unescape_to_path(&p).is_err());
    }

    #[test]
    fn test_unescape_path_canonical() {
        // Invalid cases
        assert!(unescape_to_path_canonical("").is_err());
        assert!(unescape_to_path_canonical("foo").is_err());
        assert!(unescape_to_path_canonical("../blah").is_err());
        assert!(unescape_to_path_canonical("/foo/..").is_err());
        assert!(unescape_to_path_canonical("/foo/../blah").is_err());
        // Verify that we return borrowed input where possible
        assert!(matches!(
            unescape_to_path_canonical("/foo").unwrap(),
            Cow::Borrowed(v) if v.to_str() == Some("/foo")
        ));
        // But an escaped version must be owned
        assert!(matches!(
            unescape_to_path_canonical(r#"/\x66oo"#).unwrap(),
            Cow::Owned(v) if v.to_str() == Some("/foo")
        ));
        // Test successful normalization
        assert_eq!(
            unescape_to_path_canonical("///foo/bar//baz")
                .unwrap()
                .to_str()
                .unwrap(),
            "/foo/bar/baz"
        );
        assert_eq!(
            unescape_to_path_canonical("/.").unwrap().to_str().unwrap(),
            "/"
        );
    }

    #[test]
    fn test_xattr() {
        let v = Xattr::parse("foo=bar").unwrap();
        similar_asserts::assert_eq!(v.key.as_bytes(), b"foo");
        similar_asserts::assert_eq!(&*v.value, b"bar");
        // Invalid embedded NUL in keys
        assert!(Xattr::parse("foo\0bar=baz").is_err());
        assert!(Xattr::parse("foo\x00bar=baz").is_err());
        // But embedded NUL in values is OK
        let v = Xattr::parse("security.selinux=bar\x00").unwrap();
        similar_asserts::assert_eq!(v.key.as_bytes(), b"security.selinux");
        similar_asserts::assert_eq!(&*v.value, b"bar\0");
    }

    #[test]
    fn long_xattrs() {
        let mut s = String::from("/file 0 100755 1 0 0 0 0.0 00/26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae - -");
        Entry::parse(&s).unwrap();
        let xattrs_to_fill = XATTR_LIST_MAX / XATTR_NAME_MAX;
        let xattr_name_remainder = XATTR_LIST_MAX % XATTR_NAME_MAX;
        assert_eq!(xattr_name_remainder, 0);
        let uniqueidlen = 8u8;
        let xattr_prefix_len = XATTR_NAME_MAX.checked_sub(uniqueidlen.into()).unwrap();
        let push_long_xattr = |s: &mut String, n| {
            s.push(' ');
            for _ in 0..xattr_prefix_len {
                s.push('a');
            }
            write!(s, "{n:08x}=x").unwrap();
        };
        for i in 0..xattrs_to_fill {
            push_long_xattr(&mut s, i);
        }
        Entry::parse(&s).unwrap();
        push_long_xattr(&mut s, xattrs_to_fill);
        assert!(Entry::parse(&s).is_err());
    }

    #[test]
    fn test_parse() {
        const CONTENT: &str = include_str!("tests/assets/special.dump");
        for line in CONTENT.lines() {
            // Test a full round trip by parsing, serialize, parsing again
            let e = Entry::parse(line).unwrap();
            let serialized = e.to_string();
            if line != serialized {
                dbg!(&line, &e, &serialized);
            }
            similar_asserts::assert_eq!(line, serialized);
            let e2 = Entry::parse(&serialized).unwrap();
            similar_asserts::assert_eq!(e, e2);
        }
    }

    fn parse_all(name: &str, s: &str) -> Result<()> {
        for line in s.lines() {
            if line.is_empty() {
                continue;
            }
            let _: Entry =
                Entry::parse(line).with_context(|| format!("Test case={name:?} line={line:?}"))?;
        }
        Ok(())
    }

    #[test]
    fn test_should_fail() {
        const CASES: &[(&str, &str)] = &[
            (
                "content in fifo",
                "/ 4096 40755 2 0 0 0 0.0 - - -\n/fifo 0 10777 1 0 0 0 0.0 - foobar -",
            ),
            ("root with rdev", "/ 4096 40755 2 0 0 42 0.0 - - -"),
            ("root with fsverity", "/ 4096 40755 2 0 0 0 0.0 - - 35d02f81325122d77ec1d11baba655bc9bf8a891ab26119a41c50fa03ddfb408"),
        ];
        for (name, case) in CASES.iter().copied() {
            assert!(
                parse_all(name, case).is_err(),
                "Expected case {name} to fail"
            );
        }
    }

    #[test_with::executable(mkcomposefs)]
    #[test]
    fn test_load_cfs() -> Result<()> {
        let mut tmpf = tempfile::tempfile()?;
        mkcomposefs(SPECIAL_DUMP, &mut tmpf).unwrap();
        let mut entries = String::new();
        tmpf.seek(std::io::SeekFrom::Start(0))?;
        dump(tmpf, DumpConfig::default(), |e| {
            writeln!(entries, "{e}")?;
            Ok(())
        })
        .unwrap();
        similar_asserts::assert_eq!(SPECIAL_DUMP, &entries);
        Ok(())
    }

    #[test_with::executable(mkcomposefs)]
    #[test]
    fn test_load_cfs_filtered() -> Result<()> {
        const FILTERED: &str =
            "/ 4096 40555 2 0 0 0 1633950376.0 - - - trusted.foo1=bar-1 user.foo2=bar-2\n\
/blockdev 0 60777 1 0 0 107690 1633950376.0 - - - trusted.bar=bar-2\n\
/inline 15 100777 1 0 0 0 1633950376.0 - FOOBAR\\nINAFILE\\n - user.foo=bar-2\n";
        let mut tmpf = tempfile::tempfile()?;
        mkcomposefs(SPECIAL_DUMP, &mut tmpf).unwrap();
        let mut entries = String::new();
        tmpf.seek(std::io::SeekFrom::Start(0))?;
        let filter = DumpConfig {
            filters: Some(&["blockdev", "inline"]),
        };
        dump(tmpf, filter, |e| {
            writeln!(entries, "{e}")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(FILTERED, &entries);
        Ok(())
    }
}
