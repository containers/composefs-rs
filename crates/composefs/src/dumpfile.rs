//! Reading and writing composefs dumpfile format.
//!
//! This module provides functionality to serialize filesystem trees into
//! the composefs dumpfile text format (writing), and to convert parsed
//! dumpfile entries back into tree structures (reading).
//!
//! The module handles file metadata, extended attributes, and hardlink tracking.

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    ffi::{OsStr, OsString},
    fmt,
    io::{BufWriter, Write},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    rc::Rc,
};

use anyhow::{ensure, Context, Result};
use rustix::fs::FileType;

use crate::{
    dumpfile_parse::{Entry, Item},
    fsverity::FsVerityHashValue,
    tree::{Directory, FileSystem, Inode, Leaf, LeafContent, RegularFile, Stat},
};

fn write_empty(writer: &mut impl fmt::Write) -> fmt::Result {
    writer.write_str("-")
}

fn write_escaped(writer: &mut impl fmt::Write, bytes: &[u8]) -> fmt::Result {
    if bytes.is_empty() {
        return write_empty(writer);
    }

    for c in bytes {
        let c = *c;

        if c < b'!' || c == b'=' || c == b'\\' || c > b'~' {
            write!(writer, "\\x{c:02x}")?;
        } else {
            writer.write_char(c as char)?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_entry(
    writer: &mut impl fmt::Write,
    path: &Path,
    stat: &Stat,
    ifmt: FileType,
    size: u64,
    nlink: usize,
    rdev: u64,
    payload: impl AsRef<OsStr>,
    content: &[u8],
    digest: Option<&str>,
) -> fmt::Result {
    let mode = stat.st_mode | ifmt.as_raw_mode();
    let uid = stat.st_uid;
    let gid = stat.st_gid;
    let mtim_sec = stat.st_mtim_sec;

    write_escaped(writer, path.as_os_str().as_bytes())?;
    write!(
        writer,
        " {size} {mode:o} {nlink} {uid} {gid} {rdev} {mtim_sec}.0 "
    )?;
    write_escaped(writer, payload.as_ref().as_bytes())?;
    write!(writer, " ")?;
    write_escaped(writer, content)?;
    write!(writer, " ")?;
    if let Some(id) = digest {
        write!(writer, "{id}")?;
    } else {
        write_empty(writer)?;
    }

    for (key, value) in &*stat.xattrs.borrow() {
        write!(writer, " ")?;
        write_escaped(writer, key.as_bytes())?;
        write!(writer, "=")?;
        write_escaped(writer, value)?;
    }

    Ok(())
}

/// Writes a directory entry to the dumpfile format.
///
/// Writes the metadata for a directory including path, permissions, ownership,
/// timestamps, and extended attributes.
pub fn write_directory(
    writer: &mut impl fmt::Write,
    path: &Path,
    stat: &Stat,
    nlink: usize,
) -> fmt::Result {
    write_entry(
        writer,
        path,
        stat,
        FileType::Directory,
        0,
        nlink,
        0,
        "",
        &[],
        None,
    )
}

/// Writes a leaf node (non-directory) entry to the dumpfile format.
///
/// Handles all types of leaf nodes including regular files (inline and external),
/// device files, symlinks, sockets, and FIFOs.
pub fn write_leaf(
    writer: &mut impl fmt::Write,
    path: &Path,
    stat: &Stat,
    content: &LeafContent<impl FsVerityHashValue>,
    nlink: usize,
) -> fmt::Result {
    match content {
        LeafContent::Regular(RegularFile::Inline(ref data)) => write_entry(
            writer,
            path,
            stat,
            FileType::RegularFile,
            data.len() as u64,
            nlink,
            0,
            "",
            data,
            None,
        ),
        LeafContent::Regular(RegularFile::External(id, size)) => write_entry(
            writer,
            path,
            stat,
            FileType::RegularFile,
            *size,
            nlink,
            0,
            id.to_object_pathname(),
            &[],
            Some(&id.to_hex()),
        ),
        LeafContent::BlockDevice(rdev) => write_entry(
            writer,
            path,
            stat,
            FileType::BlockDevice,
            0,
            nlink,
            *rdev,
            "",
            &[],
            None,
        ),
        LeafContent::CharacterDevice(rdev) => write_entry(
            writer,
            path,
            stat,
            FileType::CharacterDevice,
            0,
            nlink,
            *rdev,
            "",
            &[],
            None,
        ),
        LeafContent::Fifo => write_entry(
            writer,
            path,
            stat,
            FileType::Fifo,
            0,
            nlink,
            0,
            "",
            &[],
            None,
        ),
        LeafContent::Socket => write_entry(
            writer,
            path,
            stat,
            FileType::Socket,
            0,
            nlink,
            0,
            "",
            &[],
            None,
        ),
        LeafContent::Symlink(ref target) => write_entry(
            writer,
            path,
            stat,
            FileType::Symlink,
            target.as_bytes().len() as u64,
            nlink,
            0,
            target,
            &[],
            None,
        ),
    }
}

/// Writes a hardlink entry to the dumpfile format.
///
/// Creates a special entry that links the given path to an existing target path
/// that was already written to the dumpfile.
pub fn write_hardlink(writer: &mut impl fmt::Write, path: &Path, target: &OsStr) -> fmt::Result {
    write_escaped(writer, path.as_os_str().as_bytes())?;
    write!(writer, " 0 @120000 - - - - 0.0 ")?;
    write_escaped(writer, target.as_bytes())?;
    write!(writer, " - -")?;
    Ok(())
}

struct DumpfileWriter<'a, W: Write, ObjectID: FsVerityHashValue> {
    hardlinks: HashMap<*const Leaf<ObjectID>, OsString>,
    writer: &'a mut W,
}

fn writeln_fmt(writer: &mut impl Write, f: impl Fn(&mut String) -> fmt::Result) -> Result<()> {
    let mut tmp = String::with_capacity(256);
    f(&mut tmp)?;
    Ok(writeln!(writer, "{tmp}")?)
}

impl<'a, W: Write, ObjectID: FsVerityHashValue> DumpfileWriter<'a, W, ObjectID> {
    fn new(writer: &'a mut W) -> Self {
        Self {
            hardlinks: HashMap::new(),
            writer,
        }
    }

    fn write_dir(&mut self, path: &mut PathBuf, dir: &Directory<ObjectID>) -> Result<()> {
        // nlink is 2 + number of subdirectories
        // this is also true for the root dir since '..' is another self-ref
        let nlink = dir.inodes().fold(2, |count, inode| {
            count + {
                match inode {
                    Inode::Directory(..) => 1,
                    _ => 0,
                }
            }
        });

        writeln_fmt(self.writer, |fmt| {
            write_directory(fmt, path, &dir.stat, nlink)
        })?;

        for (name, inode) in dir.sorted_entries() {
            path.push(name);

            match inode {
                Inode::Directory(ref dir) => {
                    self.write_dir(path, dir)?;
                }
                Inode::Leaf(ref leaf) => {
                    self.write_leaf(path, leaf)?;
                }
            }

            path.pop();
        }
        Ok(())
    }

    fn write_leaf(&mut self, path: &Path, leaf: &Rc<Leaf<ObjectID>>) -> Result<()> {
        let nlink = Rc::strong_count(leaf);

        if nlink > 1 {
            // This is a hardlink.  We need to handle that specially.
            let ptr = Rc::as_ptr(leaf);
            if let Some(target) = self.hardlinks.get(&ptr) {
                return writeln_fmt(self.writer, |fmt| write_hardlink(fmt, path, target));
            }

            // @path gets modified all the time, so take a copy
            self.hardlinks.insert(ptr, OsString::from(&path));
        }

        writeln_fmt(self.writer, |fmt| {
            write_leaf(fmt, path, &leaf.stat, &leaf.content, nlink)
        })
    }
}

/// Writes a complete filesystem tree to the composefs dumpfile format.
///
/// Serializes the entire filesystem structure including all directories, files,
/// metadata, and handles hardlink tracking automatically.
pub fn write_dumpfile(
    writer: &mut impl Write,
    fs: &FileSystem<impl FsVerityHashValue>,
) -> Result<()> {
    // default pipe capacity on Linux is 16 pages (65536 bytes), but
    // sometimes the BufWriter will write more than its capacity...
    let mut buffer = BufWriter::with_capacity(32768, writer);
    let mut dfw = DumpfileWriter::new(&mut buffer);
    let mut path = PathBuf::from("/");

    dfw.write_dir(&mut path, &fs.root)?;
    buffer.flush()?;

    Ok(())
}

// Reading: Converting dumpfile entries to tree structures

/// Convert a dumpfile Entry into tree structures and insert into a FileSystem.
pub fn add_entry_to_filesystem<ObjectID: FsVerityHashValue>(
    fs: &mut FileSystem<ObjectID>,
    entry: Entry<'_>,
    hardlinks: &mut HashMap<PathBuf, Rc<Leaf<ObjectID>>>,
) -> Result<()> {
    let path = entry.path.as_ref();

    // Handle root directory specially
    if path == Path::new("/") {
        let stat = entry_to_stat(&entry);
        fs.set_root_stat(stat);
        return Ok(());
    }

    // Split the path into directory and filename
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    let filename = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Path has no filename: {path:?}"))?;

    // Get or create parent directory
    let parent_dir = if parent == Path::new("/") {
        &mut fs.root
    } else {
        fs.root
            .get_directory_mut(parent.as_os_str())
            .with_context(|| format!("Parent directory not found: {parent:?}"))?
    };

    // Convert the entry to an inode
    let inode = match entry.item {
        Item::Directory { .. } => {
            let stat = entry_to_stat(&entry);
            Inode::Directory(Box::new(Directory::new(stat)))
        }
        Item::Hardlink { ref target } => {
            // Look up the target in our hardlinks map and clone the Rc
            let target_leaf = hardlinks
                .get(target.as_ref())
                .ok_or_else(|| anyhow::anyhow!("Hardlink target not found: {target:?}"))?
                .clone();
            Inode::Leaf(target_leaf)
        }
        Item::RegularInline { ref content, .. } => {
            let stat = entry_to_stat(&entry);
            let data: Box<[u8]> = match content {
                std::borrow::Cow::Borrowed(d) => Box::from(*d),
                std::borrow::Cow::Owned(d) => d.clone().into_boxed_slice(),
            };
            let content = LeafContent::Regular(RegularFile::Inline(data));
            Inode::Leaf(Rc::new(Leaf { stat, content }))
        }
        Item::Regular {
            size,
            ref fsverity_digest,
            ..
        } => {
            let stat = entry_to_stat(&entry);
            let digest = fsverity_digest
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("External file missing fsverity digest"))?;
            let object_id = ObjectID::from_hex(digest)?;
            let content = LeafContent::Regular(RegularFile::External(object_id, size));
            Inode::Leaf(Rc::new(Leaf { stat, content }))
        }
        Item::Device { rdev, .. } => {
            let stat = entry_to_stat(&entry);
            // S_IFMT = 0o170000, S_IFBLK = 0o60000, S_IFCHR = 0o20000
            let content = if entry.mode & 0o170000 == 0o60000 {
                LeafContent::BlockDevice(rdev)
            } else {
                LeafContent::CharacterDevice(rdev)
            };
            Inode::Leaf(Rc::new(Leaf { stat, content }))
        }
        Item::Symlink { ref target, .. } => {
            let stat = entry_to_stat(&entry);
            let target_os: Box<OsStr> = match target {
                std::borrow::Cow::Borrowed(t) => Box::from(t.as_os_str()),
                std::borrow::Cow::Owned(t) => Box::from(t.as_os_str()),
            };
            let content = LeafContent::Symlink(target_os);
            Inode::Leaf(Rc::new(Leaf { stat, content }))
        }
        Item::Fifo { .. } => {
            let stat = entry_to_stat(&entry);
            let content = LeafContent::Fifo;
            Inode::Leaf(Rc::new(Leaf { stat, content }))
        }
    };

    // Store Leafs in the hardlinks map for future hardlink lookups
    if let Inode::Leaf(ref leaf) = inode {
        hardlinks.insert(path.to_path_buf(), leaf.clone());
    }

    parent_dir.insert(filename, inode);
    Ok(())
}

/// Convert a dumpfile Entry's metadata into a tree Stat structure.
fn entry_to_stat(entry: &Entry<'_>) -> Stat {
    let mut xattrs = BTreeMap::new();
    for xattr in &entry.xattrs {
        let key: Box<OsStr> = match &xattr.key {
            std::borrow::Cow::Borrowed(k) => Box::from(*k),
            std::borrow::Cow::Owned(k) => Box::from(k.as_os_str()),
        };
        let value: Box<[u8]> = match &xattr.value {
            std::borrow::Cow::Borrowed(v) => Box::from(*v),
            std::borrow::Cow::Owned(v) => v.clone().into_boxed_slice(),
        };
        xattrs.insert(key, value);
    }

    Stat {
        st_mode: entry.mode & 0o7777, // Keep only permission bits
        st_uid: entry.uid,
        st_gid: entry.gid,
        st_mtim_sec: entry.mtime.sec as i64,
        xattrs: RefCell::new(xattrs),
    }
}

/// Parse a dumpfile string and build a complete FileSystem.
///
/// The dumpfile must start with a root directory entry (`/`) which provides
/// the root metadata. Returns an error if no root entry is found.
pub fn dumpfile_to_filesystem<ObjectID: FsVerityHashValue>(
    dumpfile: &str,
) -> Result<FileSystem<ObjectID>> {
    let mut lines = dumpfile.lines().peekable();
    let mut hardlinks = HashMap::new();

    // Find the first non-empty line which must be the root entry
    let root_stat = loop {
        match lines.next() {
            Some(line) if line.trim().is_empty() => continue,
            Some(line) => {
                let entry = Entry::parse(line)
                    .with_context(|| format!("Failed to parse dumpfile line: {line}"))?;
                ensure!(
                    entry.path.as_ref() == Path::new("/"),
                    "Dumpfile must start with root directory entry, found: {:?}",
                    entry.path
                );
                break entry_to_stat(&entry);
            }
            None => anyhow::bail!("Dumpfile is empty, expected root directory entry"),
        }
    };

    let mut fs = FileSystem::new(root_stat);

    // Process remaining entries
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let entry =
            Entry::parse(line).with_context(|| format!("Failed to parse dumpfile line: {line}"))?;
        add_entry_to_filesystem(&mut fs, entry, &mut hardlinks)?;
    }

    Ok(fs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsverity::Sha256HashValue;

    const SIMPLE_DUMP: &str = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/empty_file 0 100644 1 0 0 0 1000.0 - - -
/small_file 5 100644 1 0 0 0 1000.0 - hello -
/symlink 7 120777 1 0 0 0 1000.0 /target - -
"#;

    #[test]
    fn test_simple_dumpfile_conversion() -> Result<()> {
        let fs = dumpfile_to_filesystem::<Sha256HashValue>(SIMPLE_DUMP)?;

        // Check files exist
        assert!(fs.root.lookup(OsStr::new("empty_file")).is_some());
        assert!(fs.root.lookup(OsStr::new("small_file")).is_some());
        assert!(fs.root.lookup(OsStr::new("symlink")).is_some());

        // Check inline file content
        let small_file = fs.root.get_file(OsStr::new("small_file"))?;
        if let RegularFile::Inline(data) = small_file {
            assert_eq!(&**data, b"hello");
        } else {
            panic!("Expected inline file");
        }

        Ok(())
    }

    #[test]
    fn test_hardlinks() -> Result<()> {
        let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/original 11 100644 2 0 0 0 1000.0 - hello_world -
/hardlink1 0 @120000 2 0 0 0 0.0 /original - -
/dir1 4096 40755 2 0 0 0 1000.0 - - -
/dir1/hardlink2 0 @120000 2 0 0 0 0.0 /original - -
"#;

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile)?;

        // Get the original file
        let original = fs.root.lookup(OsStr::new("original")).unwrap();
        let hardlink1 = fs.root.lookup(OsStr::new("hardlink1")).unwrap();

        // Get hardlink2 from dir1
        let dir1 = fs.root.get_directory(OsStr::new("dir1"))?;
        let hardlink2 = dir1.lookup(OsStr::new("hardlink2")).unwrap();

        // All three should be Leaf inodes
        let original_leaf = match original {
            Inode::Leaf(ref l) => l,
            _ => panic!("Expected Leaf inode"),
        };
        let hardlink1_leaf = match hardlink1 {
            Inode::Leaf(ref l) => l,
            _ => panic!("Expected Leaf inode"),
        };
        let hardlink2_leaf = match hardlink2 {
            Inode::Leaf(ref l) => l,
            _ => panic!("Expected Leaf inode"),
        };

        // They should all point to the same Rc (same pointer)
        assert!(Rc::ptr_eq(original_leaf, hardlink1_leaf));
        assert!(Rc::ptr_eq(original_leaf, hardlink2_leaf));

        // Verify the strong count is 3 (original + 2 hardlinks)
        assert_eq!(Rc::strong_count(original_leaf), 3);

        // Verify content
        if let LeafContent::Regular(RegularFile::Inline(data)) = &original_leaf.content {
            assert_eq!(&**data, b"hello_world");
        } else {
            panic!("Expected inline regular file");
        }

        Ok(())
    }
}
