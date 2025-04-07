use std::{
    cell::RefCell,
    collections::BTreeMap,
    ffi::OsStr,
    path::{Component, Path},
    rc::Rc,
};

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
    entries: BTreeMap<Box<OsStr>, Inode>,
}

#[derive(Debug)]
pub enum Inode {
    Directory(Box<Directory>),
    Leaf(Rc<Leaf>),
}

#[derive(Error, Debug)]
pub enum ImageError {
    #[error("Invalid filename {0:?}")]
    InvalidFilename(Box<OsStr>),
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

    /// Iterates over all inodes in the current directory, in no particular order.
    pub fn inodes(&self) -> impl Iterator<Item = &Inode> + use<'_> {
        self.entries.values()
    }

    /// Iterates over all entries in the current directory, in no particular order.  The iterator
    /// returns pairs of `(&OsStr, &Inode)` and is probably used like so:
    ///
    /// Currently this is equivalent to `Directory::sorted_entries()` but that might change at some
    /// point.
    ///
    /// ```
    /// let fs = composefs::image::FileSystem::new();
    ///
    /// // populate the fs...
    ///
    /// for (name, inode) in fs.root.entries() {
    ///   // name: &OsStr, inode: &Inode
    /// }
    /// ```
    pub fn entries(&self) -> impl Iterator<Item = (&OsStr, &Inode)> + use<'_> {
        self.entries.iter().map(|(k, v)| (k.as_ref(), v))
    }

    /// Iterates over all entries in the current directory, in asciibetical order of name.  The
    /// iterator returns pairs of `(&OsStr, &Inode)`.
    pub fn sorted_entries(&self) -> impl Iterator<Item = (&OsStr, &Inode)> + use<'_> {
        self.entries.iter().map(|(k, v)| (k.as_ref(), v))
    }

    /// Gets a reference to a subdirectory of this directory.
    ///
    /// The given path may be absolute or relative and it makes no difference.  It may not contain
    /// any Windows-like prefixes, or "." or ".." components.  It may or may not end in "/" and it
    /// makes no difference.
    ///
    /// See `Directory::get_directory_mut()` for the mutable verison of this function.
    ///
    /// # Arguments
    ///
    ///  * `pathname`: the full pathname of the directory to fetch, taken as being relative to the
    ///    current directory even if it starts with '/'
    ///
    /// # Return value
    ///
    /// On success, this returns a reference to the named directory.
    ///
    /// On failure, can return any number of errors from ImageError.
    pub fn get_directory(&self, pathname: &OsStr) -> Result<&Directory, ImageError> {
        let path = Path::new(pathname);
        let mut dir = self;

        for component in path.components() {
            dir = match component {
                Component::RootDir => dir,
                Component::Prefix(..) | Component::CurDir | Component::ParentDir => {
                    return Err(ImageError::InvalidFilename(pathname.into()))
                }
                Component::Normal(filename) => match dir.entries.get(filename) {
                    Some(Inode::Directory(subdir)) => subdir,
                    Some(_) => return Err(ImageError::NotADirectory(filename.into())),
                    None => return Err(ImageError::NotFound(filename.into())),
                },
            }
        }

        Ok(dir)
    }

    /// Gets a mutable reference to a subdirectory of this directory.
    ///
    /// This is the mutable version of `Directory::get_directory()`.
    pub fn get_directory_mut(&mut self, pathname: &OsStr) -> Result<&mut Directory, ImageError> {
        let path = Path::new(pathname);
        let mut dir = self;

        for component in path.components() {
            dir = match component {
                Component::RootDir => dir,
                Component::Prefix(..) | Component::CurDir | Component::ParentDir => {
                    return Err(ImageError::InvalidFilename(pathname.into()))
                }
                Component::Normal(filename) => match dir.entries.get_mut(filename) {
                    Some(Inode::Directory(subdir)) => subdir,
                    Some(_) => return Err(ImageError::NotADirectory(filename.into())),
                    None => return Err(ImageError::NotFound(filename.into())),
                },
            };
        }

        Ok(dir)
    }

    /// Splits a pathname into a directory and the filename within that directory.  The directory
    /// must already exist.  The filename within the directory may or may not exist.
    ///
    /// This is the main entry point for most operations based on pathname.  The expectation is
    /// that the returned filename will be used to perform a more concrete operation on the
    /// returned directory.
    ///
    /// See `Directory::get_directory()` for more information about path traversal.  See
    /// `Directory::split_mut()` for the mutable version of this function.
    ///
    /// # Arguments
    ///
    ///  * `pathname`: the full pathname to the file of interest
    ///
    /// # Return value
    ///
    /// On success (the pathname is not invalid and the directory exists), returns a tuple of the
    /// `Directory` containing the file at the given path, and the basename of that file.
    ///
    /// On failure, can return any number of errors from ImageError.
    pub fn split<'d, 'n>(
        &'d self,
        pathname: &'n OsStr,
    ) -> Result<(&'d Directory, &'n OsStr), ImageError> {
        let path = Path::new(pathname);

        let Some(filename) = path.file_name() else {
            return Err(ImageError::InvalidFilename(Box::from(pathname)));
        };

        let dir = match path.parent() {
            Some(parent) => self.get_directory(parent.as_os_str())?,
            None => self,
        };

        Ok((dir, filename))
    }

    /// Splits a pathname into a directory and the filename within that directory.  The directory
    /// must already exist.  The filename within the directory may or may not exist.
    ///
    /// This is the `_mut` version of `Directory::split()`.
    pub fn split_mut<'d, 'n>(
        &'d mut self,
        pathname: &'n OsStr,
    ) -> Result<(&'d mut Directory, &'n OsStr), ImageError> {
        let path = Path::new(pathname);

        let Some(filename) = path.file_name() else {
            return Err(ImageError::InvalidFilename(Box::from(pathname)));
        };

        let dir = match path.parent() {
            Some(parent) => self.get_directory_mut(parent.as_os_str())?,
            None => self,
        };

        Ok((dir, filename))
    }

    /// Takes a reference to the "leaf" file (not directory) with the given filename directly
    /// contained in this directory.  This is usually done in preparation for creating a hardlink
    /// or in order to avoid issues with the borrow checker when mutating the tree.
    ///
    /// # Arguments
    ///
    ///  * `filename`: the filename in the current directory.  If you need to support full
    ///    pathnames then you should call `Directory::split()` first.
    ///
    /// # Return value
    ///
    /// On success (the entry exists and is not a directory) the Rc is cloned and a new reference
    /// is returned.
    ///
    /// On failure, can return any number of errors from ImageError.
    pub fn ref_leaf(&self, filename: &OsStr) -> Result<Rc<Leaf>, ImageError> {
        match self.entries.get(filename) {
            Some(Inode::Leaf(leaf)) => Ok(Rc::clone(leaf)),
            Some(Inode::Directory(..)) => Err(ImageError::IsADirectory(Box::from(filename))),
            None => Err(ImageError::NotFound(Box::from(filename))),
        }
    }

    /// Obtains information about the regular file with the given filename directly contained in
    /// this directory.
    ///
    /// # Arguments
    ///
    ///  * `filename`: the filename in the current directory.  If you need to support full
    ///    pathnames then you should call `Directory::split()` first.
    ///
    /// # Return value
    ///
    /// On success (the entry exists and is a regular file) then the return value is either:
    ///  * the inline data
    ///  * an external reference, with size information
    ///
    /// On failure, can return any number of errors from ImageError.
    pub fn get_file<'a>(&'a self, filename: &OsStr) -> Result<&'a RegularFile, ImageError> {
        match self.entries.get(filename) {
            Some(Inode::Leaf(leaf)) => match &leaf.content {
                LeafContent::Regular(file) => Ok(file),
                _ => Err(ImageError::IsNotRegular(filename.into())),
            },
            Some(Inode::Directory(..)) => Err(ImageError::IsADirectory(filename.into())),
            None => Err(ImageError::NotFound(filename.into())),
        }
    }

    /// Inserts the given inode into the directory with special handling for directories.  In case
    /// the inode is a directory and there is already a subdirectory with the given filename, the
    /// `stat` field will be updated with the value from the provided `inode` but the old directory
    /// entries will be left in place.
    ///
    /// In all other cases, this function is equivalent to `Directory::insert()`.
    ///
    /// This is something like extracting an archive or an overlay: directories are merged with
    /// existing directories, but otherwise the new content replaces what was there before.
    ///
    /// # Arguments
    ///
    ///  * `filename`: the filename in the current directory.  If you need to support full
    ///    pathnames then you should call `Directory::split()` first.
    ///  * `inode`: the inode to store under the `filename`
    pub fn merge(&mut self, filename: &OsStr, inode: Inode) {
        // If we're putting a directory on top of a directory, then update the stat information but
        // keep the old entries in place.
        if let Inode::Directory(new_dir) = inode {
            if let Some(Inode::Directory(old_dir)) = self.entries.get_mut(filename) {
                old_dir.stat = new_dir.stat;
            } else {
                // Unfortunately we already deconstructed the original inode and we can't get it
                // back again.  This is necessary because we wanted to move the stat field (above)
                // without cloning it which can't be done through a reference (mutable or not).
                self.insert(filename, Inode::Directory(new_dir));
            }
        } else {
            self.insert(filename, inode);
        }
    }

    /// Inserts the given inode into the directory.
    ///
    /// If the `filename` existed previously, the content is completely overwitten, including the
    /// case that it was a directory.
    ///
    /// # Arguments
    ///
    ///  * `filename`: the filename in the current directory.  If you need to support full
    ///    pathnames then you should call `Directory::split()` first.
    ///  * `inode`: the inode to store under the `filename`
    pub fn insert(&mut self, filename: &OsStr, inode: Inode) {
        self.entries.insert(Box::from(filename), inode);
    }

    /// Removes the named file from the directory, if it exists.  If it doesn't exist, this is a
    /// no-op.
    ///
    /// # Arguments
    ///
    ///  * `filename`: the filename in the current directory.  If you need to support full
    ///    pathnames then you should call `Directory::split()` first.
    pub fn remove(&mut self, filename: &OsStr) {
        self.entries.remove(filename);
    }

    /// Removes all content from this directory, making the directory empty.  The `stat` data
    /// remains unmodified.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    fn newest_file(&self) -> i64 {
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
