use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    fmt,
    io::{BufWriter, Write},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    rc::Rc,
};

use anyhow::Result;
use rustix::fs::FileType;

use crate::{
    fsverity::Sha256HashValue,
    image::{DirEnt, Directory, FileSystem, Inode, Leaf, LeafContent, Stat},
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
            write!(writer, "\\x{:02x}", c)?;
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
    digest: Option<&Sha256HashValue>,
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
        write!(writer, "{}", hex::encode(id))?;
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

pub fn write_leaf(
    writer: &mut impl fmt::Write,
    path: &Path,
    stat: &Stat,
    content: &LeafContent,
    nlink: usize,
) -> fmt::Result {
    match content {
        LeafContent::InlineFile(ref data) => write_entry(
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
        LeafContent::ExternalFile(id, size) => write_entry(
            writer,
            path,
            stat,
            FileType::RegularFile,
            *size,
            nlink,
            0,
            format!("{:02x}/{}", id[0], hex::encode(&id[1..])),
            &[],
            Some(id),
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

pub fn write_hardlink(writer: &mut impl fmt::Write, path: &Path, target: &OsStr) -> fmt::Result {
    write_escaped(writer, path.as_os_str().as_bytes())?;
    write!(writer, " 0 @120000 - - - - 0.0 ")?;
    write_escaped(writer, target.as_bytes())?;
    write!(writer, " - -")?;
    Ok(())
}

struct DumpfileWriter<'a, W: Write> {
    hardlinks: HashMap<*const Leaf, OsString>,
    writer: &'a mut W,
}

fn writeln_fmt(writer: &mut impl Write, f: impl Fn(&mut String) -> fmt::Result) -> Result<()> {
    let mut tmp = String::with_capacity(256);
    f(&mut tmp)?;
    Ok(writeln!(writer, "{}", tmp)?)
}

impl<'a, W: Write> DumpfileWriter<'a, W> {
    fn new(writer: &'a mut W) -> Self {
        Self {
            hardlinks: HashMap::new(),
            writer,
        }
    }

    fn write_dir(&mut self, path: &mut PathBuf, dir: &Directory) -> Result<()> {
        // nlink is 2 + number of subdirectories
        // this is also true for the root dir since '..' is another self-ref
        let nlink = dir.entries.iter().fold(2, |count, ent| {
            count + {
                match ent.inode {
                    Inode::Directory(..) => 1,
                    _ => 0,
                }
            }
        });

        writeln_fmt(self.writer, |fmt| {
            write_directory(fmt, path, &dir.stat, nlink)
        })?;

        for DirEnt { name, inode } in dir.entries.iter() {
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

    fn write_leaf(&mut self, path: &Path, leaf: &Rc<Leaf>) -> Result<()> {
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

pub fn write_dumpfile<W: Write>(writer: &mut W, fs: &FileSystem) -> Result<()> {
    // default pipe capacity on Linux is 16 pages (65536 bytes), but
    // sometimes the BufWriter will write more than its capacity...
    let mut buffer = BufWriter::with_capacity(32768, writer);
    let mut dfw = DumpfileWriter::new(&mut buffer);
    let mut path = PathBuf::from("/");

    dfw.write_dir(&mut path, &fs.root)?;
    buffer.flush()?;

    Ok(())
}
