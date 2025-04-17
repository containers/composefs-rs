use std::{
    cell::RefCell,
    cmp::max,
    collections::{BTreeMap, HashMap},
    ffi::{CStr, OsStr},
    fs::File,
    io::Write,
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
    fsverity::{compute_verity, Sha256HashValue},
    image::{Directory, FileSystem, Inode, Leaf, LeafContent, RegularFile, Stat},
    repository::Repository,
    selabel::selabel,
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

fn write_directory(
    dir: &Directory,
    dirfd: &OwnedFd,
    name: &OsStr,
    repo: &Repository,
) -> Result<()> {
    match mkdirat(dirfd, name, dir.stat.st_mode.into()) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(e) => Err(e)?,
    }

    let fd = openat(dirfd, name, OFlags::PATH | OFlags::DIRECTORY, 0.into())?;
    write_directory_contents(dir, &fd, repo)
}

fn write_leaf(leaf: &Leaf, dirfd: &OwnedFd, name: &OsStr, repo: &Repository) -> Result<()> {
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

fn write_directory_contents(dir: &Directory, fd: &OwnedFd, repo: &Repository) -> Result<()> {
    for (name, inode) in dir.entries() {
        match inode {
            Inode::Directory(ref dir) => write_directory(dir, fd, name, repo),
            Inode::Leaf(ref leaf) => write_leaf(leaf, fd, name, repo),
        }?;
    }

    Ok(())
}

// NB: hardlinks not supported
pub fn write_to_path(repo: &Repository, dir: &Directory, output_dir: &Path) -> Result<()> {
    let fd = openat(CWD, output_dir, OFlags::PATH | OFlags::DIRECTORY, 0.into())?;
    write_directory_contents(dir, &fd, repo)
}

#[derive(Debug)]
pub struct FilesystemReader<'repo> {
    repo: Option<&'repo Repository>,
    inodes: HashMap<(u64, u64), Rc<Leaf>>,
    root_mtime: Option<i64>,
}

impl FilesystemReader<'_> {
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

    fn read_leaf_content(&mut self, fd: OwnedFd, buf: rustix::fs::Stat) -> Result<LeafContent> {
        let content = match FileType::from_raw_mode(buf.st_mode) {
            FileType::Directory | FileType::Unknown => unreachable!(),
            FileType::RegularFile => {
                let mut buffer = Vec::with_capacity(buf.st_size as usize);
                read(fd, spare_capacity(&mut buffer))?;
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

    fn read_leaf(&mut self, dirfd: &OwnedFd, name: &OsStr, ifmt: FileType) -> Result<Rc<Leaf>> {
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

    pub fn read_directory(&mut self, dirfd: impl AsFd, name: &OsStr) -> Result<Directory> {
        let fd = openat(
            dirfd,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;

        let (_, stat) = Self::stat(&fd, FileType::Directory)?;
        let mut directory = Directory::new(stat);

        for item in Dir::read_from(&fd)? {
            let entry = item?;
            let name = OsStr::from_bytes(entry.file_name().to_bytes());

            if name == "." || name == ".." {
                continue;
            }

            let inode = self.read_inode(&fd, name, entry.file_type())?;
            self.root_mtime = max(self.root_mtime, Some(inode.stat().st_mtim_sec));
            directory.insert(name, inode);
        }

        Ok(directory)
    }

    fn read_inode(&mut self, dirfd: &OwnedFd, name: &OsStr, ifmt: FileType) -> Result<Inode> {
        if ifmt == FileType::Directory {
            let dir = self.read_directory(dirfd, name)?;
            Ok(Inode::Directory(Box::new(dir)))
        } else {
            let leaf = self.read_leaf(dirfd, name, ifmt)?;
            Ok(Inode::Leaf(leaf))
        }
    }
}

pub fn read_from_path(path: &Path, repo: Option<&Repository>) -> Result<FileSystem> {
    let mut reader = FilesystemReader {
        repo,
        inodes: HashMap::new(),
        root_mtime: None,
    };
    let mut fs = FileSystem {
        root: reader.read_directory(CWD, path.as_os_str())?,
    };

    // A filesystem with no files ends up in the 1970s...
    fs.root.stat.st_mtim_sec = reader.root_mtime.unwrap_or(0);

    // We can only relabel if we have the repo because we need to read the config and policy files
    if let Some(repo) = repo {
        selabel(&mut fs, repo)?;
    }

    Ok(fs)
}

pub fn create_image(path: &Path, repo: Option<&Repository>) -> Result<Sha256HashValue> {
    let fs = read_from_path(path, repo)?;
    let image = crate::erofs::writer::mkfs_erofs(&fs);
    if let Some(repo) = repo {
        Ok(repo.write_image(None, &image)?)
    } else {
        Ok(compute_verity(&image))
    }
}

pub fn create_dumpfile(path: &Path) -> Result<()> {
    let fs = read_from_path(path, None)?;
    super::dumpfile::write_dumpfile(&mut std::io::stdout(), &fs)
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
