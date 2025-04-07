use std::{cell::RefCell, collections::BTreeMap, ffi::OsStr, path::Path, rc::Rc};

use thiserror::Error;

use crate::fsverity::Sha256HashValue;

#[derive(Debug)]
pub struct Stat {
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_mtim_sec: i64,
    pub xattrs: RefCell<BTreeMap<Box<OsStr>, Box<[u8]>>>,
}

#[derive(Debug)]
pub enum RegularFile {
    Inline(Box<[u8]>),
    External(Sha256HashValue, u64),
}

#[derive(Debug)]
pub enum LeafContent {
    Regular(RegularFile),
    BlockDevice(u64),
    CharacterDevice(u64),
    Fifo,
    Socket,
    Symlink(Box<OsStr>),
}

#[derive(Debug)]
pub struct Leaf {
    pub stat: Stat,
    pub content: LeafContent,
}

#[derive(Debug)]
pub struct Directory {
    pub stat: Stat,
    pub entries: BTreeMap<Box<OsStr>, Inode>,
}

#[derive(Debug)]
pub enum Inode {
    Directory(Box<Directory>),
    Leaf(Rc<Leaf>),
}

#[derive(Error, Debug)]
pub enum ImageError {
    #[error("Directory entry {0:?} does not exist")]
    NotFound(Box<OsStr>),
    #[error("Directory entry {0:?} is not a subdirectory")]
    NotADirectory(Box<OsStr>),
    #[error("Directory entry {0:?} is a directory")]
    IsADirectory(Box<OsStr>),
    #[error("Directory entry {0:?} is not a regular file")]
    IsNotRegular(Box<OsStr>),
}

impl Inode {
    pub fn stat(&self) -> &Stat {
        match self {
            Inode::Directory(dir) => &dir.stat,
            Inode::Leaf(leaf) => &leaf.stat,
        }
    }
}

impl Directory {
    pub fn new(stat: Stat) -> Self {
        Self {
            stat,
            entries: BTreeMap::new(),
        }
    }

    pub fn recurse(&mut self, name: impl AsRef<OsStr>) -> Result<&mut Directory, ImageError> {
        match self.entries.get_mut(name.as_ref()) {
            Some(Inode::Directory(subdir)) => Ok(subdir),
            Some(_) => Err(ImageError::NotADirectory(name.as_ref().into())),
            None => Err(ImageError::NotFound(name.as_ref().into())),
        }
    }

    pub fn mkdir(&mut self, name: &OsStr, stat: Stat) {
        match self.entries.get_mut(name) {
            // Entry already exists, is a dir.  update the stat, but don't drop the entries
            Some(Inode::Directory(dir)) => dir.stat = stat,
            // Entry already exists, is not a dir
            Some(Inode::Leaf(..)) => todo!("Trying to replace non-dir with dir!"),
            // Entry doesn't exist yet
            None => {
                self.entries
                    .insert(name.into(), Inode::Directory(Directory::new(stat).into()));
            }
        }
    }

    pub fn insert(&mut self, name: &OsStr, inode: Inode) {
        self.entries.insert(name.into(), inode);
    }

    pub fn get_for_link(&self, name: &OsStr) -> Result<Rc<Leaf>, ImageError> {
        match self.entries.get(name) {
            Some(Inode::Leaf(leaf)) => Ok(Rc::clone(leaf)),
            Some(Inode::Directory(..)) => Err(ImageError::IsADirectory(name.into())),
            None => Err(ImageError::NotFound(name.into())),
        }
    }

    pub fn remove(&mut self, name: &OsStr) {
        self.entries.remove(name);
    }

    pub fn remove_all(&mut self) {
        self.entries.clear();
    }

    pub fn newest_file(&self) -> i64 {
        let mut newest = self.stat.st_mtim_sec;
        for inode in self.entries.values() {
            let mtime = match inode {
                Inode::Leaf(ref leaf) => leaf.stat.st_mtim_sec,
                Inode::Directory(ref dir) => dir.newest_file(),
            };
            if mtime > newest {
                newest = mtime;
            }
        }
        newest
    }
}

#[derive(Debug)]
pub struct FileSystem {
    pub root: Directory,
}

impl Default for FileSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl FileSystem {
    pub fn new() -> Self {
        Self {
            root: Directory::new(Stat {
                st_mode: u32::MAX, // assigned later
                st_uid: u32::MAX,  // assigned later
                st_gid: u32::MAX,  // assigned later
                st_mtim_sec: -1,   // assigned later
                xattrs: RefCell::new(BTreeMap::new()),
            }),
        }
    }

    fn get_parent_dir<'a>(&'a mut self, name: &Path) -> Result<&'a mut Directory, ImageError> {
        let mut dir = &mut self.root;

        if let Some(parent) = name.parent() {
            for segment in parent {
                if segment.is_empty() || segment == "/" {
                    // Path.parent() is really weird...
                    continue;
                }
                dir = dir.recurse(segment)?;
            }
        }

        Ok(dir)
    }

    pub fn mkdir(&mut self, name: &Path, stat: Stat) -> Result<(), ImageError> {
        if let Some(filename) = name.file_name() {
            let dir = self.get_parent_dir(name)?;
            dir.mkdir(filename, stat);
        }
        Ok(())
    }

    pub fn insert_rc(&mut self, name: &Path, leaf: Rc<Leaf>) -> Result<(), ImageError> {
        if let Some(filename) = name.file_name() {
            let dir = self.get_parent_dir(name)?;
            dir.insert(filename, Inode::Leaf(leaf));
            Ok(())
        } else {
            todo!()
        }
    }

    pub fn insert(&mut self, name: &Path, leaf: Leaf) -> Result<(), ImageError> {
        self.insert_rc(name, Rc::new(leaf))
    }

    fn get_for_link(&mut self, name: &Path) -> Result<Rc<Leaf>, ImageError> {
        if let Some(filename) = name.file_name() {
            let dir = self.get_parent_dir(name)?;
            dir.get_for_link(filename)
        } else {
            todo!()
        }
    }

    pub fn hardlink(&mut self, name: &Path, target: &OsStr) -> Result<(), ImageError> {
        let rc = self.get_for_link(Path::new(target))?;
        self.insert_rc(name, rc)
    }

    pub fn remove(&mut self, name: &Path) -> Result<(), ImageError> {
        if let Some(filename) = name.file_name() {
            let dir = self.get_parent_dir(name)?;
            dir.remove(filename);
            Ok(())
        } else {
            todo!();
        }
    }

    pub fn done(&mut self) {
        // We need to look at the root entry and deal with the "assign later" fields
        let stat = &mut self.root.stat;

        if stat.st_mode == u32::MAX {
            stat.st_mode = 0o555;
        }
        if stat.st_uid == u32::MAX {
            stat.st_uid = 0;
        }
        if stat.st_gid == u32::MAX {
            stat.st_gid = 0;
        }
        if stat.st_mtim_sec == -1 {
            // write this in full to avoid annoying the borrow checker
            self.root.stat.st_mtim_sec = self.root.newest_file();
        }
    }
}
