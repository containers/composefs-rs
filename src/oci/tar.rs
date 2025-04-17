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

use crate::{
    dumpfile,
    image::{LeafContent, RegularFile, Stat},
    splitstream::{SplitStreamData, SplitStreamReader, SplitStreamWriter},
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

#[derive(Debug)]
pub enum TarItem {
    Directory,
    Leaf(LeafContent),
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
    // https://github.com/rust-lang/rust/issues/122741
    // path.pop_if(|x| x == &b'/');
    if path.last() == Some(&b'/') {
        path.pop(); // this is Vec<u8>, so that's a single char.
    }

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

pub fn get_entry<R: Read>(reader: &mut SplitStreamReader<R>) -> Result<Option<TarEntry>> {
    let mut gnu_longlink: Vec<u8> = vec![];
    let mut gnu_longname: Vec<u8> = vec![];
    let mut pax_longlink: Option<Box<[u8]>> = None;
    let mut pax_longname: Option<Box<[u8]>> = None;
    let mut xattrs = BTreeMap::new();

    loop {
        let mut buf = [0u8; 512];
        if !reader.read_inline_exact(&mut buf)? || buf == [0u8; 512] {
            return Ok(None);
        }

        let header = tar::Header::from_byte_slice(&buf);
        assert!(header.as_ustar().is_some());

        let size = header.entry_size()?;

        let item = match reader.read_exact(size as usize, ((size + 511) & !511) as usize)? {
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
                    continue;
                }
                EntryType::GNULongName => {
                    gnu_longname.extend(content);
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
