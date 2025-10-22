//! Reading and writing filesystem trees to/from disk.
//!
//! This module provides functionality to read filesystem structures from
//! disk into composefs tree representations and write them back, including
//! handling of hardlinks, extended attributes, and repository integration.

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    ffi::{CStr, OsStr},
    fs::File,
    io::{Read, Write},
    mem::MaybeUninit,
    os::unix::ffi::OsStrExt,
    path::Path,
    rc::Rc,
};

use anyhow::{ensure, Result};
use rustix::{
    buffer::spare_capacity,
    fd::{AsFd, OwnedFd},
    fs::{
        fstat, getxattr, linkat, listxattr, mkdirat, mknodat, openat, readlinkat, symlinkat,
        AtFlags, Dir, FileType, Mode, OFlags, CWD,
    },
    io::{read, Errno},
};
use zerocopy::IntoBytes;

use crate::{
    fsverity::{compute_verity, FsVerityHashValue},
    repository::Repository,
    tree::{Directory, FileSystem, Inode, Leaf, LeafContent, RegularFile, Stat},
    util::proc_self_fd,
    INLINE_CONTENT_MAX,
};

/// Attempt to use O_TMPFILE + rename to atomically set file contents.
/// Will fall back to a non-atomic write if the target doesn't support O_TMPFILE.
fn set_file_contents(dirfd: &OwnedFd, name: &OsStr, stat: &Stat, data: &[u8]) -> Result<()> {
    match openat(
        dirfd,
        ".",
        OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
        stat.st_mode.into(),
    ) {
        Ok(tmp) => {
            let mut tmp = File::from(tmp);
            tmp.write_all(data)?;
            tmp.sync_data()?;
            linkat(
                CWD,
                proc_self_fd(&tmp),
                dirfd,
                name,
                AtFlags::SYMLINK_FOLLOW,
            )?;
        }
        Err(Errno::OPNOTSUPP) => {
            // vfat? yolo...
            let fd = openat(
                dirfd,
                name,
                OFlags::CREATE | OFlags::WRONLY | OFlags::CLOEXEC,
                stat.st_mode.into(),
            )?;
            let mut f = File::from(fd);
            f.write_all(data)?;
            f.sync_data()?;
        }
        Err(e) => Err(e)?,
    }
    Ok(())
}

fn write_directory<ObjectID: FsVerityHashValue>(
    dir: &Directory<ObjectID>,
    dirfd: &OwnedFd,
    name: &OsStr,
    repo: &Repository<ObjectID>,
) -> Result<()> {
    match mkdirat(dirfd, name, dir.stat.st_mode.into()) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(e) => Err(e)?,
    }

    let fd = openat(dirfd, name, OFlags::PATH | OFlags::DIRECTORY, 0.into())?;
    write_directory_contents(dir, &fd, repo)
}

fn write_leaf<ObjectID: FsVerityHashValue>(
    leaf: &Leaf<ObjectID>,
    dirfd: &OwnedFd,
    name: &OsStr,
    repo: &Repository<ObjectID>,
) -> Result<()> {
    let mode = leaf.stat.st_mode.into();

    match &leaf.content {
        LeafContent::Regular(RegularFile::Inline(ref data)) => {
            set_file_contents(dirfd, name, &leaf.stat, data)?
        }
        LeafContent::Regular(RegularFile::External(ref id, size)) => {
            let object = repo.open_object(id)?;
            // TODO: make this better.  At least needs to be EINTR-safe.  Could even do reflink in some cases...
            let mut buffer = vec![MaybeUninit::uninit(); *size as usize];
            let (data, _) = read(object, &mut buffer)?;
            set_file_contents(dirfd, name, &leaf.stat, data)?;
        }
        LeafContent::BlockDevice(rdev) => mknodat(dirfd, name, FileType::BlockDevice, mode, *rdev)?,
        LeafContent::CharacterDevice(rdev) => {
            mknodat(dirfd, name, FileType::CharacterDevice, mode, *rdev)?
        }
        LeafContent::Socket => mknodat(dirfd, name, FileType::Socket, mode, 0)?,
        LeafContent::Fifo => mknodat(dirfd, name, FileType::Fifo, mode, 0)?,
        LeafContent::Symlink(target) => symlinkat(target.as_ref(), dirfd, name)?,
    }

    Ok(())
}

fn write_directory_contents<ObjectID: FsVerityHashValue>(
    dir: &Directory<ObjectID>,
    fd: &OwnedFd,
    repo: &Repository<ObjectID>,
) -> Result<()> {
    for (name, inode) in dir.entries() {
        match inode {
            Inode::Directory(ref dir) => write_directory(dir, fd, name, repo),
            Inode::Leaf(ref leaf) => write_leaf(leaf, fd, name, repo),
        }?;
    }

    Ok(())
}

/// Writes a directory tree from composefs representation to a filesystem path.
///
/// Reconstructs the filesystem structure at the specified output directory,
/// creating directories, files, symlinks, and device nodes as needed. External
/// file content is read from the repository. Note that hardlinks are not supported.
pub fn write_to_path<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    dir: &Directory<ObjectID>,
    output_dir: &Path,
) -> Result<()> {
    let fd = openat(CWD, output_dir, OFlags::PATH | OFlags::DIRECTORY, 0.into())?;
    write_directory_contents(dir, &fd, repo)
}

/// Helper for reading filesystem trees from disk into composefs representation.
///
/// Tracks hardlinks via inode numbers and handles integration with repositories
/// for storing large file content.
#[derive(Debug)]
pub struct FilesystemReader<'repo, ObjectID: FsVerityHashValue> {
    repo: Option<&'repo Repository<ObjectID>>,
    inodes: HashMap<(u64, u64), Rc<Leaf<ObjectID>>>,
}

impl<ObjectID: FsVerityHashValue> FilesystemReader<'_, ObjectID> {
    fn read_xattrs(fd: &OwnedFd) -> Result<BTreeMap<Box<OsStr>, Box<[u8]>>> {
        // flistxattr() and fgetxattr() don't work with with O_PATH fds, so go via /proc/self/fd.
        // Note: we want the symlink-following version of this call, which produces the correct
        // behaviour even when trying to read xattrs from symlinks themselves.  See
        // https://gist.github.com/allisonkarlitskaya/7a80f2ebb3314d80f45c653a1ba0e398
        let filename = proc_self_fd(fd);

        let mut xattrs = BTreeMap::new();

        let mut names = [MaybeUninit::new(0); 65536];
        let (names, _) = listxattr(&filename, &mut names)?;

        for name in names.split_inclusive(|c| *c == 0) {
            let mut buffer = [MaybeUninit::new(0); 65536];
            let name: &[u8] = name.as_bytes();
            let name = CStr::from_bytes_with_nul(name)?;
            let (value, _) = getxattr(&filename, name, &mut buffer)?;
            let key = Box::from(OsStr::from_bytes(name.to_bytes()));
            xattrs.insert(key, Box::from(value));
        }

        Ok(xattrs)
    }

    fn stat(fd: &OwnedFd, ifmt: FileType) -> Result<(rustix::fs::Stat, Stat)> {
        let buf = fstat(fd)?;

        ensure!(
            FileType::from_raw_mode(buf.st_mode) == ifmt,
            "File type changed
            between readdir() and fstat()"
        );

        Ok((
            buf,
            Stat {
                st_mode: buf.st_mode & 0o7777,
                st_uid: buf.st_uid,
                st_gid: buf.st_gid,
                st_mtim_sec: buf.st_mtime as i64,
                xattrs: RefCell::new(Self::read_xattrs(fd)?),
            },
        ))
    }

    fn read_leaf_content(
        &mut self,
        fd: OwnedFd,
        buf: rustix::fs::Stat,
    ) -> Result<LeafContent<ObjectID>> {
        let content = match FileType::from_raw_mode(buf.st_mode) {
            FileType::Directory | FileType::Unknown => unreachable!(),
            FileType::RegularFile => {
                let mut buffer = Vec::with_capacity(buf.st_size as usize);
                if buf.st_size > 0 {
                    read(fd, spare_capacity(&mut buffer))?;
                }
                let buffer = Box::from(buffer);

                if buf.st_size > INLINE_CONTENT_MAX as i64 {
                    let id = if let Some(repo) = self.repo {
                        repo.ensure_object(&buffer)?
                    } else {
                        compute_verity(&buffer)
                    };
                    LeafContent::Regular(RegularFile::External(id, buf.st_size as u64))
                } else {
                    LeafContent::Regular(RegularFile::Inline(buffer))
                }
            }
            FileType::Symlink => {
                let target = readlinkat(fd, "", [])?;
                LeafContent::Symlink(OsStr::from_bytes(target.as_bytes()).into())
            }
            FileType::CharacterDevice => LeafContent::CharacterDevice(buf.st_rdev),
            FileType::BlockDevice => LeafContent::BlockDevice(buf.st_rdev),
            FileType::Fifo => LeafContent::Fifo,
            FileType::Socket => LeafContent::Socket,
        };
        Ok(content)
    }

    fn read_leaf(
        &mut self,
        dirfd: &OwnedFd,
        name: &OsStr,
        ifmt: FileType,
    ) -> Result<Rc<Leaf<ObjectID>>> {
        let oflags = match ifmt {
            FileType::RegularFile => OFlags::RDONLY,
            _ => OFlags::PATH,
        };

        let fd = openat(
            dirfd,
            name,
            oflags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;

        let (buf, stat) = Self::stat(&fd, ifmt)?;

        // NB: We could check `st_nlink > 1` to find out if we should track a file as a potential
        // hardlink or not, but some filesystems (like fuse-overlayfs) can report this incorrectly.
        // Track all files.  https://github.com/containers/fuse-overlayfs/issues/435
        let key = (buf.st_dev, buf.st_ino);
        if let Some(leafref) = self.inodes.get(&key) {
            Ok(Rc::clone(leafref))
        } else {
            let content = self.read_leaf_content(fd, buf)?;
            let leaf = Rc::new(Leaf { stat, content });
            self.inodes.insert(key, Rc::clone(&leaf));
            Ok(leaf)
        }
    }

    /// Reads a directory from disk into composefs representation.
    ///
    /// Recursively reads directory contents, tracking hardlinks and optionally
    /// reading the directory's own metadata. Large files are stored in the repository
    /// if one was provided.
    pub fn read_directory(
        &mut self,
        dirfd: impl AsFd,
        name: &OsStr,
        stat_self: bool,
    ) -> Result<Directory<ObjectID>> {
        let fd = openat(
            dirfd,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;

        let mut directory = if stat_self {
            let (_, stat) = Self::stat(&fd, FileType::Directory)?;
            Directory::new(stat)
        } else {
            Directory::default()
        };

        for item in Dir::read_from(&fd)? {
            let entry = item?;
            let name = OsStr::from_bytes(entry.file_name().to_bytes());

            if name == "." || name == ".." {
                continue;
            }

            let inode = self.read_inode(&fd, name, entry.file_type())?;
            directory.insert(name, inode);
        }

        Ok(directory)
    }

    fn read_inode(
        &mut self,
        dirfd: &OwnedFd,
        name: &OsStr,
        ifmt: FileType,
    ) -> Result<Inode<ObjectID>> {
        if ifmt == FileType::Directory {
            let dir = self.read_directory(dirfd, name, true)?;
            Ok(Inode::Directory(Box::new(dir)))
        } else {
            let leaf = self.read_leaf(dirfd, name, ifmt)?;
            Ok(Inode::Leaf(leaf))
        }
    }
}

/// Load a filesystem tree from the given path. A repository may
/// be provided; if it is, then all files found in the filesystem
/// are copied in.
pub fn read_filesystem<ObjectID: FsVerityHashValue>(
    dirfd: impl AsFd,
    path: &Path,
    repo: Option<&Repository<ObjectID>>,
    stat_root: bool,
) -> Result<FileSystem<ObjectID>> {
    let mut reader = FilesystemReader {
        repo,
        inodes: HashMap::new(),
    };

    let root = reader.read_directory(dirfd, path.as_os_str(), stat_root)?;

    Ok(FileSystem {
        root,
        have_root_stat: stat_root,
    })
}

/// Read the contents of a file.
pub fn read_file<ObjectID: FsVerityHashValue>(
    file: &RegularFile<ObjectID>,
    repo: &Repository<ObjectID>,
) -> Result<Box<[u8]>> {
    match file {
        RegularFile::Inline(data) => Ok(data.clone()),
        RegularFile::External(id, size) => {
            let mut data = Vec::with_capacity(*size as usize);
            std::fs::File::from(repo.open_object(id)?).read_to_end(&mut data)?;
            ensure!(
                *size == data.len() as u64,
                "File content doesn't have the expected length"
            );
            Ok(data.into_boxed_slice())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::{openat, CWD};

    #[test]
    fn test_write_contents() -> Result<()> {
        let td = tempfile::tempdir()?;
        let testpath = &td.path().join("testfile");
        let td = openat(
            CWD,
            td.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::from_raw_mode(0),
        )?;
        let st = Stat {
            st_mode: 0o755,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: Default::default(),
            xattrs: Default::default(),
        };
        set_file_contents(&td, OsStr::new("testfile"), &st, b"new contents").unwrap();
        drop(td);
        assert_eq!(std::fs::read(testpath)?, b"new contents");
        Ok(())
    }
}
