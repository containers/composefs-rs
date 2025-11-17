//! TAR archive processing and split stream conversion.
//!
//! This module handles the conversion of tar archives (container image layers) into composefs split streams.
//! It provides both synchronous and asynchronous tar processing, intelligently deciding whether to store
//! file content inline in the split stream or externally in the object store based on file size.
//!
//! Key components include the `split()` and `split_async()` functions for converting tar streams,
//! `get_entry()` for reading back tar entries from split streams, and comprehensive support for
//! tar format features including GNU long names, PAX extensions, and various file types.
//! The `TarEntry` and `TarItem` types represent processed tar entries in composefs format.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fmt,
    io::Read,
    os::unix::prelude::{OsStrExt, OsStringExt},
    path::PathBuf,
};

use anyhow::{bail, ensure, Result};
use rustix::fs::makedev;
use tar::{EntryType, Header, PaxExtensions};
use tokio::io::{AsyncRead, AsyncReadExt};

use composefs::{
    dumpfile,
    fsverity::FsVerityHashValue,
    splitstream::{SplitStreamData, SplitStreamReader, SplitStreamWriter},
    tree::{LeafContent, RegularFile, Stat},
    util::{read_exactish, read_exactish_async},
    INLINE_CONTENT_MAX,
};

fn read_header<R: Read>(reader: &mut R) -> Result<Option<Header>> {
    let mut header = Header::new_gnu();
    if read_exactish(reader, header.as_mut_bytes())? {
        Ok(Some(header))
    } else {
        Ok(None)
    }
}

async fn read_header_async(reader: &mut (impl AsyncRead + Unpin)) -> Result<Option<Header>> {
    let mut header = Header::new_gnu();
    if read_exactish_async(reader, header.as_mut_bytes()).await? {
        Ok(Some(header))
    } else {
        Ok(None)
    }
}

/// Splits the tar file from tar_stream into a Split Stream.  The store_data function is
/// responsible for ensuring that "external data" is in the composefs repository and returns the
/// fsverity hash value of that data.
pub fn split(
    tar_stream: &mut impl Read,
    writer: &mut SplitStreamWriter<impl FsVerityHashValue>,
) -> Result<()> {
    while let Some(header) = read_header(tar_stream)? {
        // the header always gets stored as inline data
        writer.write_inline(header.as_bytes());

        if header.as_bytes() == &[0u8; 512] {
            continue;
        }

        // read the corresponding data, if there is any
        let actual_size = header.entry_size()? as usize;
        let storage_size = actual_size.next_multiple_of(512);
        let mut buffer = vec![0u8; storage_size];
        tar_stream.read_exact(&mut buffer)?;

        if header.entry_type() == EntryType::Regular && actual_size > INLINE_CONTENT_MAX {
            // non-empty regular file: store the data external and the trailing padding inline
            writer.write_external(&buffer[..actual_size])?;
            writer.write_inline(&buffer[actual_size..]);
        } else {
            // else: store the data inline in the split stream
            writer.write_inline(&buffer);
        }
    }
    Ok(())
}

/// Asynchronously splits a tar archive into a composefs split stream.
///
/// Similar to `split()` but processes the tar stream asynchronously. Files larger than
/// `INLINE_CONTENT_MAX` are stored externally in the object store, while smaller files
/// and metadata are stored inline in the split stream.
///
/// Returns an error if the tar stream is malformed or if writing to the split stream fails.
pub async fn split_async(
    mut tar_stream: impl AsyncRead + Unpin,
    writer: &mut SplitStreamWriter<impl FsVerityHashValue>,
) -> Result<()> {
    while let Some(header) = read_header_async(&mut tar_stream).await? {
        // the header always gets stored as inline data
        writer.write_inline(header.as_bytes());

        if header.as_bytes() == &[0u8; 512] {
            continue;
        }

        // read the corresponding data, if there is any
        let actual_size = header.entry_size()? as usize;
        let storage_size = actual_size.next_multiple_of(512);
        let mut buffer = vec![0u8; storage_size];
        tar_stream.read_exact(&mut buffer).await?;

        if header.entry_type() == EntryType::Regular && actual_size > INLINE_CONTENT_MAX {
            // non-empty regular file: store the data in the object store
            let padding = buffer.split_off(actual_size);
            writer.write_external_async(buffer).await?;
            writer.write_inline(&padding);
        } else {
            // else: store the data inline in the split stream
            writer.write_inline(&buffer);
        }
    }
    Ok(())
}

/// Represents the content type of a tar entry.
///
/// Tar entries can be directories, regular files/symlinks/devices (leaf nodes), or hardlinks
/// to existing files. This enum captures the different types of content that can appear in a tar archive.
#[derive(Debug)]
pub enum TarItem<ObjectID: FsVerityHashValue> {
    /// A directory entry.
    Directory,
    /// A leaf node (regular file, symlink, device, or fifo).
    Leaf(LeafContent<ObjectID>),
    /// A hardlink pointing to another path.
    Hardlink(OsString),
}

/// Represents a complete tar entry extracted from a split stream.
///
/// Contains the full metadata and content for a single file or directory from a tar archive,
/// including its path, stat information (permissions, ownership, timestamps), and the actual content.
#[derive(Debug)]
pub struct TarEntry<ObjectID: FsVerityHashValue> {
    /// The absolute path of the entry in the filesystem.
    pub path: PathBuf,
    /// File metadata (mode, uid, gid, mtime, xattrs).
    pub stat: Stat,
    /// The content or type of this entry.
    pub item: TarItem<ObjectID>,
}

impl<ObjectID: FsVerityHashValue> fmt::Display for TarEntry<ObjectID> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self.item {
            TarItem::Hardlink(ref target) => dumpfile::write_hardlink(fmt, &self.path, target),
            TarItem::Directory => dumpfile::write_directory(fmt, &self.path, &self.stat, 1),
            TarItem::Leaf(ref content) => {
                dumpfile::write_leaf(fmt, &self.path, &self.stat, content, 1)
            }
        }
    }
}

fn path_from_tar(pax: Option<Box<[u8]>>, gnu: Vec<u8>, short: &[u8]) -> PathBuf {
    // Prepend leading /
    let mut path = vec![b'/'];
    if let Some(name) = pax {
        path.extend(name);
    } else if !gnu.is_empty() {
        path.extend(gnu);
    } else {
        path.extend(short);
    }

    // Drop trailing '/' characters in case of directories.
    path.pop_if(|x| x == &b'/');

    PathBuf::from(OsString::from_vec(path))
}

fn symlink_target_from_tar(pax: Option<Box<[u8]>>, gnu: Vec<u8>, short: &[u8]) -> Box<OsStr> {
    if let Some(name) = pax {
        OsStr::from_bytes(name.as_ref()).into()
    } else if !gnu.is_empty() {
        OsStr::from_bytes(&gnu).into()
    } else {
        OsStr::from_bytes(short).into()
    }
}

/// Reads and parses the next tar entry from a split stream.
///
/// Decodes tar headers and data from a composefs split stream, handling both inline and
/// external content storage. Supports GNU long name/link extensions, PAX headers, and
/// extended attributes. Returns `None` when the end of the archive is reached.
///
/// Returns the parsed tar entry, or `None` if the end of the stream is reached.
pub fn get_entry<ObjectID: FsVerityHashValue>(
    reader: &mut SplitStreamReader<ObjectID>,
) -> Result<Option<TarEntry<ObjectID>>> {
    // We don't have a way to drive the standard tar crate that lets us feed it random bits of
    // header data while continuing to handle the external references as references.  That means we
    // have to do the header interpretation ourselves, including handling of PAX/GNU extensions for
    // xattrs and long filenames.
    //
    // We try to use as much of the tar crate as possible to help us with this.
    let mut gnu_longlink: Vec<u8> = vec![];
    let mut gnu_longname: Vec<u8> = vec![];
    let mut pax_longlink: Option<Box<[u8]>> = None;
    let mut pax_longname: Option<Box<[u8]>> = None;
    let mut xattrs = BTreeMap::new();

    let mut buf = [0u8; 512];
    loop {
        if !reader.read_inline_exact(&mut buf)? || buf == [0u8; 512] {
            return Ok(None);
        }

        let header = tar::Header::from_byte_slice(&buf);

        let size = header.entry_size()?;
        let stored_size = size.next_multiple_of(512);

        let item = match reader.read_exact(size as usize, stored_size as usize)? {
            SplitStreamData::External(id) => match header.entry_type() {
                EntryType::Regular | EntryType::Continuous => {
                    ensure!(
                        size as usize > INLINE_CONTENT_MAX,
                        "Splitstream incorrectly stored a small ({size} byte) file external"
                    );
                    TarItem::Leaf(LeafContent::Regular(RegularFile::External(id, size)))
                }
                _ => bail!("Unsupported external-chunked entry {header:?} {id:?}"),
            },
            SplitStreamData::Inline(content) => match header.entry_type() {
                EntryType::GNULongLink => {
                    gnu_longlink.extend(content);
                    gnu_longlink.pop_if(|x| *x == b'\0');

                    continue;
                }
                EntryType::GNULongName => {
                    gnu_longname.extend(content);
                    gnu_longname.pop_if(|x| *x == b'\0');
                    continue;
                }
                EntryType::XGlobalHeader => {
                    todo!();
                }
                EntryType::XHeader => {
                    for item in PaxExtensions::new(&content) {
                        let extension = item?;
                        let key = extension.key()?;
                        let value = Box::from(extension.value_bytes());

                        if key == "path" {
                            pax_longname = Some(value);
                        } else if key == "linkpath" {
                            pax_longlink = Some(value);
                        } else if let Some(xattr) = key.strip_prefix("SCHILY.xattr.") {
                            xattrs.insert(Box::from(OsStr::new(xattr)), value);
                        }
                    }
                    continue;
                }
                EntryType::Directory => TarItem::Directory,
                EntryType::Regular | EntryType::Continuous => {
                    ensure!(
                        content.len() <= INLINE_CONTENT_MAX,
                        "Splitstream incorrectly stored a large ({} byte) file inline",
                        content.len()
                    );
                    TarItem::Leaf(LeafContent::Regular(RegularFile::Inline(content)))
                }
                EntryType::Link => TarItem::Hardlink({
                    let Some(link_name) = header.link_name_bytes() else {
                        bail!("link without a name?")
                    };
                    OsString::from(path_from_tar(pax_longlink, gnu_longlink, &link_name))
                }),
                EntryType::Symlink => TarItem::Leaf(LeafContent::Symlink({
                    let Some(link_name) = header.link_name_bytes() else {
                        bail!("symlink without a name?")
                    };
                    symlink_target_from_tar(pax_longlink, gnu_longlink, &link_name)
                })),
                EntryType::Block => TarItem::Leaf(LeafContent::BlockDevice(
                    match (header.device_major()?, header.device_minor()?) {
                        (Some(major), Some(minor)) => makedev(major, minor),
                        _ => bail!("Device entry without device numbers?"),
                    },
                )),
                EntryType::Char => TarItem::Leaf(LeafContent::CharacterDevice(
                    match (header.device_major()?, header.device_minor()?) {
                        (Some(major), Some(minor)) => makedev(major, minor),
                        _ => bail!("Device entry without device numbers?"),
                    },
                )),
                EntryType::Fifo => TarItem::Leaf(LeafContent::Fifo),
                _ => {
                    todo!("Unsupported entry {:?}", header);
                }
            },
        };

        return Ok(Some(TarEntry {
            path: path_from_tar(pax_longname, gnu_longname, &header.path_bytes()),
            stat: Stat {
                st_uid: header.uid()? as u32,
                st_gid: header.gid()? as u32,
                st_mode: header.mode()?,
                st_mtim_sec: header.mtime()? as i64,
                xattrs: RefCell::new(xattrs),
            },
            item,
        }));
    }
}

#[cfg(test)]
mod tests {
    use crate::TAR_LAYER_CONTENT_TYPE;

    use super::*;
    use composefs::{
        fsverity::Sha256HashValue, generic_tree::LeafContent, repository::Repository,
        splitstream::SplitStreamReader,
    };
    use std::{io::Cursor, path::Path, sync::Arc};
    use tar::Builder;

    use once_cell::sync::Lazy;
    use std::sync::Mutex;

    static TEST_TEMPDIRS: Lazy<Mutex<Vec<tempfile::TempDir>>> =
        Lazy::new(|| Mutex::new(Vec::new()));

    pub(crate) fn create_test_repository() -> Result<Arc<Repository<Sha256HashValue>>> {
        // Create a temporary repository for testing and store it in static
        let tempdir = tempfile::TempDir::new().unwrap();
        let fd = rustix::fs::open(
            tempdir.path(),
            rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::PATH,
            0.into(),
        )?;

        // Store tempdir in static to keep it alive
        {
            let mut guard = TEST_TEMPDIRS.lock().unwrap();
            guard.push(tempdir);
        }

        let mut repo = Repository::open_path(&fd, ".").unwrap();
        repo.set_insecure(true);

        Ok(Arc::new(repo))
    }

    /// Helper method to append a file to a tar builder with sensible defaults
    fn append_file(
        builder: &mut Builder<&mut Vec<u8>>,
        path: &str,
        content: &[u8],
    ) -> Result<tar::Header> {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_uid(1000);
        header.set_gid(1000);
        header.set_mtime(1234567890);
        header.set_size(content.len() as u64);
        header.set_entry_type(tar::EntryType::Regular);
        builder.append_data(&mut header, path, content)?;
        Ok(header)
    }

    /// Helper method to process tar data through split/get_entry pipeline
    fn read_all_via_splitstream(tar_data: Vec<u8>) -> Result<Vec<TarEntry<Sha256HashValue>>> {
        let mut tar_cursor = Cursor::new(tar_data);
        let repo = create_test_repository()?;
        let mut writer = repo.create_stream(TAR_LAYER_CONTENT_TYPE);

        split(&mut tar_cursor, &mut writer)?;
        let object_id = writer.done()?;

        let mut reader: SplitStreamReader<Sha256HashValue> = SplitStreamReader::new(
            repo.open_object(&object_id)?.into(),
            Some(TAR_LAYER_CONTENT_TYPE),
        )?;

        let mut entries = Vec::new();
        while let Some(entry) = get_entry(&mut reader)? {
            entries.push(entry);
        }
        Ok(entries)
    }

    #[test]
    fn test_empty_tar() {
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);
            builder.finish().unwrap();
        }

        let mut tar_cursor = Cursor::new(tar_data);
        let repo = create_test_repository().unwrap();
        let mut writer = repo.create_stream(TAR_LAYER_CONTENT_TYPE);

        split(&mut tar_cursor, &mut writer).unwrap();
        let object_id = writer.done().unwrap();

        let mut reader: SplitStreamReader<Sha256HashValue> = SplitStreamReader::new(
            repo.open_object(&object_id).unwrap().into(),
            Some(TAR_LAYER_CONTENT_TYPE),
        )
        .unwrap();
        assert!(get_entry(&mut reader).unwrap().is_none());
    }

    #[test]
    fn test_single_small_file() {
        let mut tar_data = Vec::new();
        let original_header = {
            let mut builder = Builder::new(&mut tar_data);

            // Add one small regular file
            let content = b"Hello, World!";
            let header = append_file(&mut builder, "hello.txt", content).unwrap();

            builder.finish().unwrap();
            header
        };

        let mut tar_cursor = Cursor::new(tar_data);
        let repo = create_test_repository().unwrap();
        let mut writer = repo.create_stream(TAR_LAYER_CONTENT_TYPE);

        split(&mut tar_cursor, &mut writer).unwrap();
        let object_id = writer.done().unwrap();

        let mut reader: SplitStreamReader<Sha256HashValue> = SplitStreamReader::new(
            repo.open_object(&object_id).unwrap().into(),
            Some(TAR_LAYER_CONTENT_TYPE),
        )
        .unwrap();

        // Should have exactly one entry
        let entry = get_entry(&mut reader)
            .unwrap()
            .expect("Should have one entry");
        assert_eq!(entry.path, PathBuf::from("/hello.txt"));
        assert!(matches!(
            entry.item,
            TarItem::Leaf(LeafContent::Regular(RegularFile::Inline(_)))
        ));

        // Use the helper to compare header and stat
        assert_header_stat_equal(&original_header, &entry.stat, "hello.txt");

        if let TarItem::Leaf(LeafContent::Regular(RegularFile::Inline(ref content))) = entry.item {
            assert_eq!(content.as_ref(), b"Hello, World!");
        }

        // Should be no more entries
        assert!(get_entry(&mut reader).unwrap().is_none());
    }

    #[test]
    fn test_inline_threshold() {
        let mut tar_data = Vec::new();
        let (threshold_header, over_threshold_header) = {
            let mut builder = Builder::new(&mut tar_data);

            // File exactly at the threshold should be inline
            let threshold_content = vec![b'X'; INLINE_CONTENT_MAX];
            let header1 =
                append_file(&mut builder, "threshold_file.txt", &threshold_content).unwrap();

            // File just over threshold should be external
            let over_threshold_content = vec![b'Y'; INLINE_CONTENT_MAX + 1];
            let header2 = append_file(
                &mut builder,
                "over_threshold_file.txt",
                &over_threshold_content,
            )
            .unwrap();

            builder.finish().unwrap();
            (header1, header2)
        };

        let mut tar_cursor = Cursor::new(tar_data);
        let repo = create_test_repository().unwrap();
        let mut writer = repo.create_stream(TAR_LAYER_CONTENT_TYPE);

        split(&mut tar_cursor, &mut writer).unwrap();
        let object_id = writer.done().unwrap();

        let mut reader: SplitStreamReader<Sha256HashValue> = SplitStreamReader::new(
            repo.open_object(&object_id).unwrap().into(),
            Some(TAR_LAYER_CONTENT_TYPE),
        )
        .unwrap();
        let mut entries = Vec::new();

        while let Some(entry) = get_entry(&mut reader).unwrap() {
            entries.push(entry);
        }

        assert_eq!(entries.len(), 2);

        // First file should be inline
        assert_eq!(entries[0].path, PathBuf::from("/threshold_file.txt"));
        assert_header_stat_equal(&threshold_header, &entries[0].stat, "threshold_file.txt");
        if let TarItem::Leaf(LeafContent::Regular(RegularFile::Inline(ref content))) =
            entries[0].item
        {
            assert_eq!(content.len(), INLINE_CONTENT_MAX);
            assert_eq!(content[0], b'X');
        } else {
            panic!("Expected inline regular file for threshold file");
        }

        // Second file should be external
        assert_eq!(entries[1].path, PathBuf::from("/over_threshold_file.txt"));
        assert_header_stat_equal(
            &over_threshold_header,
            &entries[1].stat,
            "over_threshold_file.txt",
        );
        if let TarItem::Leaf(LeafContent::Regular(RegularFile::External(_, size))) = entries[1].item
        {
            assert_eq!(size, (INLINE_CONTENT_MAX + 1) as u64);
        } else {
            panic!("Expected external regular file for over-threshold file");
        }
    }

    #[test]
    fn test_round_trip_simple() {
        // Create a simple tar with various file types
        let mut original_tar = Vec::new();
        let (small_header, large_header) = {
            let mut builder = Builder::new(&mut original_tar);

            // Add a small file
            let small_content = b"Small file content";
            let header1 = append_file(&mut builder, "small.txt", small_content).unwrap();

            // Add a large file
            let large_content = vec![b'L'; INLINE_CONTENT_MAX + 100];
            let header2 = append_file(&mut builder, "large.txt", &large_content).unwrap();

            builder.finish().unwrap();
            (header1, header2)
        };

        // Split the tar
        let mut tar_cursor = Cursor::new(original_tar.clone());
        let repo = create_test_repository().unwrap();
        let mut writer = repo.create_stream(TAR_LAYER_CONTENT_TYPE);
        split(&mut tar_cursor, &mut writer).unwrap();
        let object_id = writer.done().unwrap();

        // Read back entries and compare with original headers
        let mut reader: SplitStreamReader<Sha256HashValue> = SplitStreamReader::new(
            repo.open_object(&object_id).unwrap().into(),
            Some(TAR_LAYER_CONTENT_TYPE),
        )
        .unwrap();
        let mut entries = Vec::new();

        while let Some(entry) = get_entry(&mut reader).unwrap() {
            entries.push(entry);
        }

        assert_eq!(entries.len(), 2, "Should have exactly 2 entries");

        // Compare small file
        assert_eq!(entries[0].path, PathBuf::from("/small.txt"));
        assert_header_stat_equal(&small_header, &entries[0].stat, "small.txt");

        if let TarItem::Leaf(LeafContent::Regular(RegularFile::Inline(ref content))) =
            entries[0].item
        {
            assert_eq!(content.as_ref(), b"Small file content");
        } else {
            panic!("Expected inline regular file for small.txt");
        }

        // Compare large file
        assert_eq!(entries[1].path, PathBuf::from("/large.txt"));
        assert_header_stat_equal(&large_header, &entries[1].stat, "large.txt");

        if let TarItem::Leaf(LeafContent::Regular(RegularFile::External(ref id, size))) =
            entries[1].item
        {
            assert_eq!(size, (INLINE_CONTENT_MAX + 100) as u64);
            // Verify the external content matches
            use std::io::Read;
            let mut external_data = Vec::new();
            std::fs::File::from(repo.open_object(id).unwrap())
                .read_to_end(&mut external_data)
                .unwrap();
            let expected_content = vec![b'L'; INLINE_CONTENT_MAX + 100];
            assert_eq!(
                external_data, expected_content,
                "External file content should match"
            );
        } else {
            panic!("Expected external regular file for large.txt");
        }
    }

    #[test]
    fn test_special_filename_cases() {
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);

            // Test file with special characters
            let content1 = b"Special chars content";
            append_file(&mut builder, "file-with_special.chars@123", content1).unwrap();

            // Test file with long filename
            let long_name = "a".repeat(100);
            let content2 = b"Long filename content";
            append_file(&mut builder, &long_name, content2).unwrap();

            builder.finish().unwrap();
        };

        let entries = read_all_via_splitstream(tar_data).unwrap();
        assert_eq!(entries.len(), 2);

        // Verify special characters filename
        assert_eq!(
            entries[0].path,
            PathBuf::from("/file-with_special.chars@123")
        );
        assert_eq!(
            entries[0].path.file_name().unwrap(),
            "file-with_special.chars@123"
        );

        // Verify long filename
        let expected_long_path = format!("/{}", "a".repeat(100));
        assert_eq!(entries[1].path, PathBuf::from(expected_long_path));
        assert_eq!(entries[1].path.file_name().unwrap(), &*"a".repeat(100));
    }

    #[test]
    fn test_gnu_long_filename_reproduction() {
        // Create a very long path that will definitely trigger GNU long name extensions
        let very_long_path = format!(
            "very/long/path/that/exceeds/the/normal/tar/header/limit/{}",
            "x".repeat(120)
        );
        let content = b"Content for very long path";

        // Use append_data to create a tar with a very long filename that triggers GNU extensions
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);
            append_file(&mut builder, &very_long_path, content).unwrap();
            builder.finish().unwrap();
        };

        let entries = read_all_via_splitstream(tar_data).unwrap();
        assert_eq!(entries.len(), 1);
        let abspath = format!("/{very_long_path}");
        assert_eq!(entries[0].path, Path::new(&abspath));
    }

    #[test]
    fn test_gnu_longlink() {
        let very_long_path = format!(
            "very/long/path/that/exceeds/the/normal/tar/header/limit/{}",
            "x".repeat(120)
        );

        // Use append_data to create a tar with a very long filename that triggers GNU extensions
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o777);
            header.set_entry_type(EntryType::Symlink);
            header.set_size(0);
            header.set_uid(0);
            header.set_gid(0);
            builder
                .append_link(&mut header, "long-symlink", &very_long_path)
                .unwrap();
            builder.finish().unwrap();
        };

        let entries = read_all_via_splitstream(tar_data).unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0].item {
            TarItem::Leaf(LeafContent::Symlink(ref target)) => {
                assert_eq!(&**target, OsStr::new(&very_long_path));
            }
            _ => unreachable!(),
        };
    }

    /// Compare a tar::Header with a composefs Stat structure for equality
    fn assert_header_stat_equal(header: &tar::Header, stat: &Stat, msg_prefix: &str) {
        assert_eq!(
            header.mode().unwrap(),
            stat.st_mode,
            "{msg_prefix}: mode mismatch"
        );
        assert_eq!(
            header.uid().unwrap() as u32,
            stat.st_uid,
            "{msg_prefix}: uid mismatch"
        );
        assert_eq!(
            header.gid().unwrap() as u32,
            stat.st_gid,
            "{msg_prefix}: gid mismatch"
        );
        assert_eq!(
            header.mtime().unwrap() as i64,
            stat.st_mtim_sec,
            "{msg_prefix}: mtime mismatch"
        );
    }
}
