use std::{cell::RefCell, collections::BTreeMap, ffi::OsStr, path::Path, rc::Rc};

use anyhow::{bail, Context, Result};

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

    pub fn recurse(&mut self, name: impl AsRef<OsStr>) -> Result<&mut Directory> {
        match self.entries.get_mut(name.as_ref()) {
            Some(Inode::Directory(subdir)) => Ok(subdir),
            Some(_) => bail!("Parent directory is not a directory"),
            None => bail!("Unable to find parent directory {:?}", name.as_ref()),
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

    pub fn get_for_link(&self, name: &OsStr) -> Result<Rc<Leaf>> {
        match self.entries.get(name) {
            Some(Inode::Leaf(leaf)) => Ok(Rc::clone(leaf)),
            Some(Inode::Directory(..)) => bail!("Cannot hardlink to directory"),
            None => bail!("Attempt to hardlink to non-existent file"),
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

    fn get_parent_dir<'a>(&'a mut self, name: &Path) -> Result<&'a mut Directory> {
        let mut dir = &mut self.root;

        if let Some(parent) = name.parent() {
            for segment in parent {
                if segment.is_empty() || segment == "/" {
                    // Path.parent() is really weird...
                    continue;
                }
                dir = dir
                    .recurse(segment)
                    .with_context(|| format!("Trying to insert item {:?}", name))?;
            }
        }

        Ok(dir)
    }

    pub fn mkdir(&mut self, name: &Path, stat: Stat) -> Result<()> {
        if let Some(filename) = name.file_name() {
            let dir = self.get_parent_dir(name)?;
            dir.mkdir(filename, stat);
        }
        Ok(())
    }

    pub fn insert_rc(&mut self, name: &Path, leaf: Rc<Leaf>) -> Result<()> {
        if let Some(filename) = name.file_name() {
            let dir = self.get_parent_dir(name)?;
            dir.insert(filename, Inode::Leaf(leaf));
            Ok(())
        } else {
            todo!()
        }
    }

    pub fn insert(&mut self, name: &Path, leaf: Leaf) -> Result<()> {
        self.insert_rc(name, Rc::new(leaf))
    }

    fn get_for_link(&mut self, name: &Path) -> Result<Rc<Leaf>> {
        if let Some(filename) = name.file_name() {
            let dir = self.get_parent_dir(name)?;
            dir.get_for_link(filename)
        } else {
            todo!()
        }
    }

    pub fn hardlink(&mut self, name: &Path, target: &OsStr) -> Result<()> {
        let rc = self.get_for_link(Path::new(target))?;
        self.insert_rc(name, rc)
    }

    pub fn remove(&mut self, name: &Path) -> Result<()> {
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
