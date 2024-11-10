use std::{
    cell::RefCell,
    cmp::{Ord, Ordering},
    ffi::{OsStr, OsString},
    io::Read,
    path::Path,
    process::{Command, Stdio},
    rc::Rc,
};

use anyhow::{bail, Context, Result};

use crate::{dumpfile::write_dumpfile, fsverity::Sha256HashValue};

#[derive(Debug)]
pub struct Stat {
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_mtim_sec: i64,
    pub xattrs: RefCell<Vec<(OsString, Vec<u8>)>>,
}

#[derive(Debug)]
pub enum LeafContent {
    InlineFile(Vec<u8>),
    ExternalFile(Sha256HashValue, u64),
    BlockDevice(u64),
    CharacterDevice(u64),
    Fifo,
    Socket,
    Symlink(OsString),
}

#[derive(Debug)]
pub struct Leaf {
    pub stat: Stat,
    pub content: LeafContent,
}

#[derive(Debug)]
pub struct Directory {
    pub stat: Stat,
    pub entries: Vec<DirEnt>,
}

#[derive(Debug)]
pub enum Inode {
    Directory(Box<Directory>),
    Leaf(Rc<Leaf>),
}

#[derive(Debug)]
pub struct DirEnt {
    pub name: OsString,
    pub inode: Inode,
}

impl Directory {
    pub fn find_entry(&self, name: &OsStr) -> Result<usize, usize> {
        // OCI layer tarballs are typically sorted, with the entries for a particular directory
        // written out immediately after that directory was created.  That means that it's very
        // likely that the thing we're looking for is either the last entry or the insertion point
        // immediately following it.  Fast-path those cases by essentially unrolling the first
        // iteration of the binary search.
        if let Some(last_entry) = self.entries.last() {
            match name.cmp(&last_entry.name) {
                Ordering::Equal => Ok(self.entries.len() - 1), // the last item, indeed
                Ordering::Greater => Err(self.entries.len()),  // need to append
                Ordering::Less => self.entries.binary_search_by_key(&name, |e| &e.name),
            }
        } else {
            Err(0)
        }
    }

    pub fn recurse(&mut self, name: impl AsRef<OsStr>) -> Result<&mut Directory> {
        match self.find_entry(name.as_ref()) {
            Ok(idx) => match &mut self.entries[idx].inode {
                Inode::Directory(ref mut subdir) => Ok(subdir),
                _ => bail!("Parent directory is not a directory"),
            },
            _ => bail!("Unable to find parent directory {:?}", name.as_ref()),
        }
    }

    pub fn mkdir(&mut self, name: &OsStr, stat: Stat) {
        match self.find_entry(name) {
            Ok(idx) => match self.entries[idx].inode {
                // Entry already exists, is a dir
                Inode::Directory(ref mut dir) => {
                    // update the stat, but don't drop the entries
                    dir.stat = stat;
                }
                // Entry already exists, is not a dir
                Inode::Leaf(..) => {
                    todo!("Trying to replace non-dir with dir!");
                }
            },
            // Entry doesn't exist yet
            Err(idx) => {
                self.entries.insert(
                    idx,
                    DirEnt {
                        name: OsString::from(name),
                        inode: Inode::Directory(Box::new(Directory {
                            stat,
                            entries: vec![],
                        })),
                    },
                );
            }
        }
    }

    pub fn insert(&mut self, name: &OsStr, leaf: Rc<Leaf>) {
        match self.find_entry(name) {
            Ok(idx) => {
                // found existing item
                self.entries[idx].inode = Inode::Leaf(leaf);
            }
            Err(idx) => {
                // need to add new item
                self.entries.insert(
                    idx,
                    DirEnt {
                        name: OsString::from(name),
                        inode: Inode::Leaf(leaf),
                    },
                );
            }
        }
    }

    pub fn get_for_link(&self, name: &OsStr) -> Result<Rc<Leaf>> {
        match self.find_entry(name) {
            Ok(idx) => match self.entries[idx].inode {
                Inode::Leaf(ref leaf) => Ok(Rc::clone(leaf)),
                Inode::Directory(..) => bail!("Cannot hardlink to directory"),
            },
            _ => bail!("Attempt to hardlink to non-existent file"),
        }
    }

    pub fn remove(&mut self, name: &OsStr) {
        match self.find_entry(name) {
            Ok(idx) => {
                self.entries.remove(idx);
            }
            _ => { /* not an error to remove an already-missing file */ }
        }
    }

    pub fn remove_all(&mut self) {
        self.entries.clear();
    }
}

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
        FileSystem {
            root: Directory {
                stat: Stat {
                    st_mode: 0o755,
                    st_uid: 0,
                    st_gid: 0,
                    st_mtim_sec: 0,
                    xattrs: RefCell::new(vec![]),
                },
                entries: vec![],
            },
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
            dir.insert(filename, leaf);
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
}

pub fn mkcomposefs(filesystem: FileSystem) -> Result<Vec<u8>> {
    let mut mkcomposefs = Command::new("mkcomposefs")
        .args(["--from-file", "-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let mut stdin = mkcomposefs.stdin.take().unwrap();
    write_dumpfile(&mut stdin, &filesystem)?;
    drop(stdin);

    let mut stdout = mkcomposefs.stdout.take().unwrap();
    let mut image = vec![];
    stdout.read_to_end(&mut image)?;
    drop(stdout);

    if !mkcomposefs.wait()?.success() {
        bail!("mkcomposefs failed");
    };

    Ok(image)
}
