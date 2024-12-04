use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    ffi::OsString,
    ffi::{CStr, OsStr},
    mem::MaybeUninit,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::Path,
    rc::Rc,
};

use anyhow::{bail, ensure, Result};
use rustix::{
    fd::{AsFd, OwnedFd},
    fs::{
        fdatasync, fstat, getxattr, linkat, listxattr, mkdirat, mknodat, openat, readlinkat,
        symlinkat, AtFlags, Dir, FileType, Mode, OFlags, CWD,
    },
    io::{read_uninit, write, Errno},
};

use crate::{
    fsverity::{digest::FsVerityHasher, Sha256HashValue},
    image::{DirEnt, Directory, FileSystem, Inode, Leaf, LeafContent, Stat},
    repository::Repository,
    selabel::selabel,
    util::proc_self_fd,
    INLINE_CONTENT_MAX,
};

fn set_file_contents(dirfd: &OwnedFd, name: &OsStr, stat: &Stat, data: &[u8]) -> Result<()> {
    match openat(
        dirfd,
        ".",
        OFlags::WRONLY | OFlags::TMPFILE,
        stat.st_mode.into(),
    ) {
        Ok(tmp) => {
            write(&tmp, data)?; // TODO: make this better
            fdatasync(&tmp)?;
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
                OFlags::CREATE | OFlags::WRONLY,
                stat.st_mode.into(),
            )?;
            write(&fd, data)?;
            fdatasync(&fd)?;
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

    match leaf.content {
        LeafContent::InlineFile(ref data) => set_file_contents(dirfd, name, &leaf.stat, data)?,
        LeafContent::ExternalFile(ref id, size) => {
            let object = repo.open_object(id)?;
            // TODO: make this better.  At least needs to be EINTR-safe.  Could even do reflink in some cases...
            let mut buffer = vec![MaybeUninit::uninit(); size as usize];
            let (data, _) = read_uninit(object, &mut buffer)?;
            set_file_contents(dirfd, name, &leaf.stat, data)?;
        }
        LeafContent::BlockDevice(rdev) => mknodat(dirfd, name, FileType::BlockDevice, mode, rdev)?,
        LeafContent::CharacterDevice(rdev) => {
            mknodat(dirfd, name, FileType::CharacterDevice, mode, rdev)?
        }
        LeafContent::Socket => mknodat(dirfd, name, FileType::Socket, mode, 0)?,
        LeafContent::Fifo => mknodat(dirfd, name, FileType::Fifo, mode, 0)?,
        LeafContent::Symlink(ref target) => symlinkat(target, dirfd, name)?,
    }

    Ok(())
}

fn write_directory_contents(dir: &Directory, fd: &OwnedFd, repo: &Repository) -> Result<()> {
    for DirEnt { name, inode } in &dir.entries {
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

pub struct FilesystemReader<'repo> {
    st_dev: u64,
    repo: Option<&'repo Repository>,
    inodes: HashMap<u64, Rc<Leaf>>,
    root_mtime: i64,
}

impl FilesystemReader<'_> {
    fn read_xattrs(&mut self, fd: &OwnedFd) -> Result<BTreeMap<Box<OsStr>, Box<[u8]>>> {
        // flistxattr() and fgetxattr() don't with with O_PATH fds, so go via /proc/self/fd. Note:
        // we want the symlink-following version of this call, which produces the correct behaviour
        // even when trying to read xattrs from symlinks themselves.  See
        // https://gist.github.com/allisonkarlitskaya/7a80f2ebb3314d80f45c653a1ba0e398
        let filename = proc_self_fd(fd);

        let mut xattrs = BTreeMap::new();

        let names_size = listxattr(&filename, &mut [])?;
        let mut names = vec![0; names_size];
        let actual_names_size = listxattr(&filename, &mut names)?;

        // Can be less than the expected size on overlayfs because of
        // https://github.com/containers/composefs-rs/issues/41
        ensure!(
            actual_names_size <= names.len(),
            "xattrs changed during read"
        );
        names.truncate(actual_names_size);

        let mut buffer = [0; 65536];
        for name in names.split_inclusive(|c| *c == 0) {
            let name = CStr::from_bytes_with_nul(name)?;
            let value_size = getxattr(&filename, name, &mut buffer)?;
            let key = Box::from(OsStr::from_bytes(name.to_bytes()));
            let value = Box::from(&buffer[..value_size]);
            xattrs.insert(key, value);
        }

        Ok(xattrs)
    }

    fn stat(&mut self, fd: &OwnedFd, ifmt: FileType) -> Result<(rustix::fs::Stat, Stat)> {
        let buf = fstat(fd)?;

        ensure!(
            FileType::from_raw_mode(buf.st_mode) == ifmt,
            "File type changed
            between readdir() and fstat()"
        );

        let mtime = buf.st_mtime as i64;

        if buf.st_dev != self.st_dev {
            if self.st_dev == u64::MAX {
                self.st_dev = buf.st_dev;
            } else {
                bail!("Attempting to cross devices while importing filesystem");
            }
        } else {
            // The root mtime is equal to the most recent mtime of any inode *except* the root
            // directory.  Because self.st_dev is unset at first, we know we're in this branch only
            // if this is the second (or later) inode we process (ie: not the root directory).
            if mtime > self.root_mtime {
                self.root_mtime = mtime;
            }
        }

        Ok((
            buf,
            Stat {
                st_mode: buf.st_mode & 0o7777,
                st_uid: buf.st_uid,
                st_gid: buf.st_gid,
                st_mtim_sec: mtime,
                xattrs: RefCell::new(self.read_xattrs(fd)?),
            },
        ))
    }

    fn read_leaf_content(&mut self, fd: OwnedFd, buf: rustix::fs::Stat) -> Result<LeafContent> {
        let content = match FileType::from_raw_mode(buf.st_mode) {
            FileType::Directory | FileType::Unknown => unreachable!(),
            FileType::RegularFile => {
                let mut buffer = vec![MaybeUninit::uninit(); buf.st_size as usize];
                let (data, _) = read_uninit(fd, &mut buffer)?;

                if buf.st_size > INLINE_CONTENT_MAX as i64 {
                    let id = if let Some(repo) = self.repo {
                        repo.ensure_object(data)?
                    } else {
                        FsVerityHasher::hash(data)
                    };
                    LeafContent::ExternalFile(id, buf.st_size as u64)
                } else {
                    LeafContent::InlineFile(Vec::from(data))
                }
            }
            FileType::Symlink => {
                let target = readlinkat(fd, "", [])?;
                LeafContent::Symlink(OsString::from_vec(target.into_bytes()))
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

        let (buf, stat) = self.stat(&fd, ifmt)?;

        if let Some(leafref) = self.inodes.get(&buf.st_ino) {
            Ok(Rc::clone(leafref))
        } else {
            let content = self.read_leaf_content(fd, buf)?;
            let leaf = Rc::new(Leaf { stat, content });
            if buf.st_nlink > 1 {
                self.inodes.insert(buf.st_ino, Rc::clone(&leaf));
            }
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

        let (_, stat) = self.stat(&fd, FileType::Directory)?;
        let mut directory = Directory {
            stat,
            entries: vec![],
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

    fn read_inode(&mut self, dirfd: &OwnedFd, name: &OsStr, ifmt: FileType) -> Result<Inode> {
        if ifmt == FileType::Directory {
            Ok(Inode::Directory(Box::new(
                self.read_directory(dirfd, name)?,
            )))
        } else {
            Ok(Inode::Leaf(self.read_leaf(dirfd, name, ifmt)?))
        }
    }
}

pub fn read_from_path(path: &Path, repo: Option<&Repository>) -> Result<FileSystem> {
    let mut reader = FilesystemReader {
        repo,
        inodes: HashMap::new(),
        st_dev: u64::MAX,
        root_mtime: 0,
    };
    let mut fs = FileSystem {
        root: reader.read_directory(CWD, path.as_os_str())?,
    };
    fs.root.stat.st_mtim_sec = reader.root_mtime;

    // We can only relabel if we have the repo because we need to read the config and policy files
    if let Some(repo) = repo {
        selabel(&mut fs, repo)?;
    }

    Ok(fs)
}

pub fn create_image(path: &Path, repo: Option<&Repository>) -> Result<Sha256HashValue> {
    let fs = read_from_path(path, repo)?;
    let image = super::image::mkcomposefs(fs)?;
    if let Some(repo) = repo {
        Ok(repo.write_image(None, &image)?)
    } else {
        Ok(FsVerityHasher::hash(&image))
    }
}

pub fn create_dumpfile(path: &Path) -> Result<()> {
    let fs = read_from_path(path, None)?;
    super::dumpfile::write_dumpfile(&mut std::io::stdout(), &fs)
}
