use std::{
    cell::RefCell,
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fmt,
    io::Read,
    path::PathBuf,
};

use anyhow::{bail, Result};
use rustix::fs::makedev;
use tar::{Entry, EntryType, Header};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{
    dumpfile,
    fsverity::{FsVerityHashValue, Sha256HashValue},
    image::{LeafContent, Stat, StatXattrs},
    splitstream::{SplitStreamReader, SplitStreamWriter},
    util::{read_exactish, read_exactish_async},
    INLINE_CONTENT_MAX,
};

// Constants related to tar archives
const TAR_BLOCK_SIZE: usize = 512;
const PAX_SCHILYXATTR: &str = "SCHILY.xattr.";

fn stat_from_tar_header(header: &tar::Header) -> Result<Stat> {
    Ok(Stat {
        st_uid: header.uid()? as u32,
        st_gid: header.gid()? as u32,
        st_mode: header.mode()?,
        st_mtim_sec: header.mtime()? as i64,
        xattrs: RefCell::new(BTreeMap::new()),
    })
}

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
pub fn split<R: Read>(tar_stream: &mut R, writer: &mut SplitStreamWriter) -> Result<()> {
    while let Some(header) = read_header(tar_stream)? {
        // the header always gets stored as inline data
        writer.write_inline(header.as_bytes());

        if header.as_bytes() == &[0u8; 512] {
            continue;
        }

        // read the corresponding data, if there is any
        let actual_size = header.entry_size()? as usize;
        let storage_size = (actual_size + 511) & !511;
        let mut buffer = vec![0u8; storage_size];
        tar_stream.read_exact(&mut buffer)?;

        if header.entry_type() == EntryType::Regular && actual_size > INLINE_CONTENT_MAX {
            // non-empty regular file: store the data in the object store
            let padding = buffer.split_off(actual_size);
            writer.write_external(&buffer, padding)?;
        } else {
            // else: store the data inline in the split stream
            writer.write_inline(&buffer);
        }
    }
    Ok(())
}

pub async fn split_async(
    mut tar_stream: impl AsyncRead + Unpin,
    writer: &mut SplitStreamWriter<'_>,
) -> Result<()> {
    while let Some(header) = read_header_async(&mut tar_stream).await? {
        // the header always gets stored as inline data
        writer.write_inline(header.as_bytes());

        if header.as_bytes() == &[0u8; 512] {
            continue;
        }

        // read the corresponding data, if there is any
        let actual_size = header.entry_size()? as usize;
        let storage_size = (actual_size + 511) & !511;
        let mut buffer = vec![0u8; storage_size];
        tar_stream.read_exact(&mut buffer).await?;

        if header.entry_type() == EntryType::Regular && actual_size > INLINE_CONTENT_MAX {
            // non-empty regular file: store the data in the object store
            let padding = buffer.split_off(actual_size);
            writer.write_external(&buffer, padding)?;
        } else {
            // else: store the data inline in the split stream
            writer.write_inline(&buffer);
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
pub enum TarItem {
    #[default]
    Directory,
    Leaf(LeafContent),
    /// Contains the target of the link
    /// The actual link path should be in TarEntry.path
    Hardlink(OsString),
}

#[derive(Debug)]
pub struct TarEntry {
    pub path: PathBuf,
    pub stat: Stat,
    pub item: TarItem,
}

impl fmt::Display for TarEntry {
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

fn update_xattrs<R: Read>(
    entry: &mut Entry<'_, &mut SplitStreamReader<R>>,
    xattrs: &mut StatXattrs,
) -> Result<(), anyhow::Error> {
    if let Ok(Some(ext)) = entry.pax_extensions() {
        for e in ext {
            let e = e?;
            let key = e.key()?;

            if let Some(xattr) = key.strip_prefix(PAX_SCHILYXATTR) {
                let value = Box::from(e.value_bytes());
                xattrs.insert(Box::from(OsStr::new(xattr)), value);
            }
        }
    };

    Ok(())
}

fn parse_external_entry<R: Read>(
    entry: &mut Entry<'_, &mut SplitStreamReader<R>>,
) -> Result<(TarEntry, usize), anyhow::Error> {
    let header = entry.header();
    let entry_size = header.entry_size()? as usize;

    let stat = stat_from_tar_header(header)?;

    let stored_size = (entry_size + 511) & !511;

    let padding = stored_size.saturating_sub(entry_size);

    let mut id = Sha256HashValue::EMPTY;
    entry.read_exact(&mut id)?;

    let (path, item) = match entry.header().entry_type() {
        EntryType::Regular | EntryType::Continuous => (
            PathBuf::from("/").join(entry.path()?),
            TarItem::Leaf(LeafContent::ExternalFile(id, entry_size as u64)),
        ),

        _ => bail!(
            "Unsupported external-chunked entry {:?} {}",
            entry.header(),
            hex::encode(id)
        ),
    };

    return Ok((TarEntry { path, item, stat }, padding));
}

fn parse_internal_entry<R: Read>(
    entry: &mut Entry<'_, &mut SplitStreamReader<R>>,
) -> Result<(TarEntry, usize), anyhow::Error> {
    let mut bytes_read = 0;

    let header = entry.header();
    let entry_size = header.entry_size()? as usize;

    let stat = stat_from_tar_header(header)?;

    let (path, item) = match header.entry_type() {
        EntryType::Regular | EntryType::Continuous => {
            // tar will always only read however long the content length is
            // in the header. It doesn't take into account the length of buffer
            // so there's no point in trying to read more
            let mut content = vec![0; entry_size];

            bytes_read = entry.read(&mut content)?;

            // entry.path() contains untruncated path, while entry.header.path contains
            // path truncated to 100 bytes
            (
                PathBuf::from("/").join(entry.path()?),
                TarItem::Leaf(LeafContent::InlineFile(content)),
            )
        }

        EntryType::Link | EntryType::Symlink => {
            let is_hard_link = header.entry_type() == EntryType::Link;

            // only get absolute path for hard links, for symlinks we want relative paths
            let link_name = match entry.link_name()? {
                Some(l) => {
                    if is_hard_link {
                        PathBuf::from("/").join(l)
                    } else {
                        PathBuf::from(l)
                    }
                }

                None => bail!("Hard link without a path?"),
            };

            let tar_item = if is_hard_link {
                TarItem::Hardlink(link_name.into())
            } else {
                TarItem::Leaf(LeafContent::Symlink(link_name.into()))
            };

            (PathBuf::from("/").join(entry.path()?), tar_item)
        }

        EntryType::Fifo => (
            PathBuf::from("/").join(entry.path()?),
            TarItem::Leaf(LeafContent::Fifo),
        ),

        EntryType::Char | EntryType::Block => {
            let (maj, min) = match (header.device_major()?, header.device_minor()?) {
                (Some(major), Some(minor)) => (major, minor),

                _ => bail!("Device entry without device numbers?"),
            };

            let tar_item = if header.entry_type() == EntryType::Char {
                TarItem::Leaf(LeafContent::CharacterDevice(makedev(maj, min)))
            } else {
                TarItem::Leaf(LeafContent::BlockDevice(makedev(maj, min)))
            };

            (PathBuf::from("/").join(entry.path()?), tar_item)
        }

        EntryType::Directory => (PathBuf::from("/").join(entry.path()?), TarItem::Directory),

        // The iterator never returns these types
        EntryType::GNULongName
        | EntryType::GNULongLink
        | EntryType::XHeader
        | EntryType::XGlobalHeader => {
            unreachable!(
                "tar iterator shouldn't have returned entry type: {:#?}",
                header.entry_type()
            )
        }

        EntryType::GNUSparse => {
            unreachable!("OCI tar entries should not contain GNUSparse entries")
        }

        _ => todo!(),
    };

    return Ok((TarEntry { path, item, stat }, bytes_read));
}

pub fn get_entry<R: Read>(
    splitstream_reader: &mut SplitStreamReader<R>,
) -> Result<Option<TarEntry>> {
    // We need to keep creating a new archive so that it reads a header for us
    // The tar crate internally keeps track of the previous header and tries to
    // skip the content length found in the previous header.
    // This is a problem for external entries, as if an external entry has 10240 bytes
    // but we only store 32 bytes + some padding; on next iteration of an entry, the tar
    // crate will try to skip the next (10240 + 511) & !511 bytes
    let mut archive = splitstream_reader.get_tar_archive();

    let mut entries = match archive.entries() {
        Ok(e) => e,
        Err(err) => {
            bail!("Failed to get archive entries. Err: {err:?}")
        }
    };

    if let Some(entry) = entries.next() {
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => {
                bail!("Error while reading entry: {e:?}");
            }
        };

        let entry_size = entry.size() as usize;

        // An external ref, i.e. a SHA256 hash
        let tar_entry = if entry_size > INLINE_CONTENT_MAX {
            let (tar_entry, padding) = parse_external_entry(&mut entry)?;

            update_xattrs(&mut entry, &mut tar_entry.stat.xattrs.borrow_mut())?;

            // TODO: This is really ugly way to handle things. Need to find a better alt
            // In the next inline chunk read, we'll need to skip this padding
            // which is actually the padding for the external chunk
            splitstream_reader.set_padding_to_skip(padding);

            tar_entry
        } else {
            let (tar_entry, bytes_read) = parse_internal_entry(&mut entry)?;

            update_xattrs(&mut entry, &mut tar_entry.stat.xattrs.borrow_mut())?;

            if bytes_read & 511 != 0 {
                splitstream_reader.discard_padding(TAR_BLOCK_SIZE - bytes_read)?;
            }

            tar_entry
        };

        return Ok(Some(tar_entry));
    }

    Ok(None)
}
