//! A generic metadata-only filesystem tree where regular files can be stored
//! however the caller wants.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    ffi::OsStr,
    path::{Component, Path},
    rc::Rc,
};

use thiserror::Error;

/// File metadata similar to `struct stat` from POSIX.
#[derive(Debug)]
pub struct Stat {
    /// File mode and permissions bits.
    pub st_mode: u32,
    /// User ID of owner.
    pub st_uid: u32,
    /// Group ID of owner.
    pub st_gid: u32,
    /// Modification time in seconds since Unix epoch.
    pub st_mtim_sec: i64,
    /// Extended attributes as key-value pairs.
    pub xattrs: RefCell<BTreeMap<Box<OsStr>, Box<[u8]>>>,
}

/// Content types for leaf nodes (non-directory files).
#[derive(Debug)]
pub enum LeafContent<T> {
    /// A regular file with content of type `T`.
    Regular(T),
    /// A block device with the given device number.
    BlockDevice(u64),
    /// A character device with the given device number.
    CharacterDevice(u64),
    /// A named pipe (FIFO).
    Fifo,
    /// A Unix domain socket.
    Socket,
    /// A symbolic link pointing to the given target path.
    Symlink(Box<OsStr>),
}

/// A leaf node representing a non-directory file.
#[derive(Debug)]
pub struct Leaf<T> {
    /// Metadata for this leaf node.
    pub stat: Stat,
    /// The content and type of this leaf node.
    pub content: LeafContent<T>,
}

/// A directory node containing named entries.
#[derive(Debug)]
pub struct Directory<T> {
    /// Metadata for this directory.
    pub stat: Stat,
    /// Map of filenames to inodes within this directory.
    pub(crate) entries: BTreeMap<Box<OsStr>, Inode<T>>,
}

/// A filesystem inode representing either a directory or a leaf node.
#[derive(Debug)]
pub enum Inode<T> {
    /// A directory inode.
    Directory(Box<Directory<T>>),
    /// A leaf inode (reference-counted to support hardlinks).
    Leaf(Rc<Leaf<T>>),
}

/// Errors that can occur when working with filesystem images.
#[derive(Error, Debug)]
pub enum ImageError {
    /// The filename contains invalid components (e.g., "..", ".", or Windows prefixes).
    #[error("Invalid filename {0:?}")]
    InvalidFilename(Box<OsStr>),
    /// The specified directory entry does not exist.
    #[error("Directory entry {0:?} does not exist")]
    NotFound(Box<OsStr>),
    /// The entry exists but is not a directory when a directory was expected.
    #[error("Directory entry {0:?} is not a subdirectory")]
    NotADirectory(Box<OsStr>),
    /// The entry is a directory when a non-directory was expected.
    #[error("Directory entry {0:?} is a directory")]
    IsADirectory(Box<OsStr>),
    /// The entry exists but is not a regular file when a regular file was expected.
    #[error("Directory entry {0:?} is not a regular file")]
    IsNotRegular(Box<OsStr>),
}

impl<T> Inode<T> {
    /// Returns a reference to the metadata for this inode.
    pub fn stat(&self) -> &Stat {
        match self {
            Inode::Directory(dir) => &dir.stat,
            Inode::Leaf(leaf) => &leaf.stat,
        }
    }
}

// For some reason #[derive(Default)] doesn't work, so let's DIY
impl<T> Default for Directory<T> {
    fn default() -> Self {
        Self {
            stat: Stat {
                st_uid: 0,
                st_gid: 0,
                st_mode: 0o555,
                st_mtim_sec: 0,
                xattrs: Default::default(),
            },
            entries: BTreeMap::default(),
        }
    }
}

impl<T> Directory<T> {
    /// Creates a new directory with the given metadata.
    pub fn new(stat: Stat) -> Self {
        Self {
            stat,
            entries: BTreeMap::new(),
        }
    }

    /// Iterates over all inodes in the current directory, in no particular order.
    pub fn inodes(&self) -> impl Iterator<Item = &Inode<T>> + use<'_, T> {
        self.entries.values()
    }

    /// Iterates over all entries in the current directory, in no particular order.  The iterator
    /// returns pairs of `(&OsStr, &Inode)` and is probably used like so:
    ///
    /// Currently this is equivalent to `Directory::sorted_entries()` but that might change at some
    /// point.
    ///
    /// ```
    /// use composefs::{tree::FileSystem, fsverity::Sha256HashValue};
    /// let fs = FileSystem::<Sha256HashValue>::default();
    ///
    /// // populate the fs...
    ///
    /// for (name, inode) in fs.root.entries() {
    ///   // name: &OsStr, inode: &Inode
    /// }
    /// ```
    pub fn entries(&self) -> impl Iterator<Item = (&OsStr, &Inode<T>)> + use<'_, T> {
        self.entries.iter().map(|(k, v)| (k.as_ref(), v))
    }

    /// Iterates over all entries in the current directory, in asciibetical order of name.  The
    /// iterator returns pairs of `(&OsStr, &Inode)`.
    pub fn sorted_entries(&self) -> impl Iterator<Item = (&OsStr, &Inode<T>)> + use<'_, T> {
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
    pub fn get_directory(&self, pathname: &OsStr) -> Result<&Directory<T>, ImageError> {
        match self.get_directory_opt(pathname)? {
            Some(r) => Ok(r),
            None => Err(ImageError::NotFound(Box::from(pathname))),
        }
    }

    /// Like [`Self::get_directory()`] but maps [`ImageError::NotFound`] to [`Option`].
    pub fn get_directory_opt(&self, pathname: &OsStr) -> Result<Option<&Directory<T>>, ImageError> {
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
                    None => return Ok(None),
                },
            }
        }

        Ok(Some(dir))
    }

    /// Gets a mutable reference to a subdirectory of this directory.
    ///
    /// This is the mutable version of `Directory::get_directory()`.
    pub fn get_directory_mut(&mut self, pathname: &OsStr) -> Result<&mut Directory<T>, ImageError> {
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
    ) -> Result<(&'d Directory<T>, &'n OsStr), ImageError> {
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
    ) -> Result<(&'d mut Directory<T>, &'n OsStr), ImageError> {
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
    pub fn ref_leaf(&self, filename: &OsStr) -> Result<Rc<Leaf<T>>, ImageError> {
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
    pub fn get_file<'a>(&'a self, filename: &OsStr) -> Result<&'a T, ImageError> {
        self.get_file_opt(filename)?
            .ok_or_else(|| ImageError::NotFound(Box::from(filename)))
    }

    /// Like [`Self::get_file()`] but maps [`ImageError::NotFound`] to [`Option`].
    pub fn get_file_opt<'a>(&'a self, filename: &OsStr) -> Result<Option<&'a T>, ImageError> {
        match self.entries.get(filename) {
            Some(Inode::Leaf(leaf)) => match &leaf.content {
                LeafContent::Regular(file) => Ok(Some(file)),
                _ => Err(ImageError::IsNotRegular(filename.into())),
            },
            Some(Inode::Directory(..)) => Err(ImageError::IsADirectory(filename.into())),
            None => Ok(None),
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
    pub fn merge(&mut self, filename: &OsStr, inode: Inode<T>) {
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
    /// If the `filename` existed previously, the content is completely overwritten, including the
    /// case that it was a directory.
    ///
    /// # Arguments
    ///
    ///  * `filename`: the filename in the current directory.  If you need to support full
    ///    pathnames then you should call `Directory::split()` first.
    ///  * `inode`: the inode to store under the `filename`
    pub fn insert(&mut self, filename: &OsStr, inode: Inode<T>) {
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

    /// Does a directory lookup on the given filename, returning the Inode if it exists.
    ///
    /// # Arguments
    ///
    ///  * `filename`: the filename in the current directory.  If you need to support full
    ///    pathnames then you should call `Directory::split()` first.
    pub fn lookup(&self, filename: &OsStr) -> Option<&Inode<T>> {
        self.entries.get(filename)
    }

    /// Removes an item from the directory, if it exists, returning the Inode value.
    ///
    /// # Arguments
    ///
    ///  * `filename`: the filename in the current directory.  If you need to support full
    ///    pathnames then you should call `Directory::split_mut()` first.
    pub fn pop(&mut self, filename: &OsStr) -> Option<Inode<T>> {
        self.entries.remove(filename)
    }

    /// Removes all content from this directory, making the directory empty.  The `stat` data
    /// remains unmodified.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Recursively finds the newest modification time in this directory tree.
    ///
    /// Returns the maximum modification time among this directory's metadata
    /// and all files and subdirectories it contains.
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

/// A complete filesystem tree with a root directory.
#[derive(Debug)]
pub struct FileSystem<T> {
    /// The root directory of the filesystem.
    pub root: Directory<T>,
    /// Whether the root directory's metadata has been explicitly set.
    pub have_root_stat: bool,
}

impl<T> Default for FileSystem<T> {
    fn default() -> Self {
        Self {
            root: Directory::default(),
            have_root_stat: false,
        }
    }
}

impl<T> FileSystem<T> {
    /// Sets the metadata for the root directory.
    ///
    /// Marks the root directory's stat as explicitly set.
    pub fn set_root_stat(&mut self, stat: Stat) {
        self.have_root_stat = true;
        self.root.stat = stat;
    }

    /// Ensures the root directory has valid metadata.
    ///
    /// If the root stat hasn't been explicitly set, this computes it by finding
    /// the newest modification time in the entire filesystem tree.
    pub fn ensure_root_stat(&mut self) {
        if !self.have_root_stat {
            self.root.stat.st_mtim_sec = self.root.newest_file();
            self.have_root_stat = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};
    use std::rc::Rc;

    // We never store any actual data here
    #[derive(Debug, Default)]
    struct FileContents {}

    // Helper to create a Stat with a specific mtime
    fn stat_with_mtime(mtime: i64) -> Stat {
        Stat {
            st_mode: 0o755,
            st_uid: 1000,
            st_gid: 1000,
            st_mtim_sec: mtime,
            xattrs: RefCell::new(BTreeMap::new()),
        }
    }

    // Helper to create a simple Leaf (e.g., an empty inline file)
    fn new_leaf_file(mtime: i64) -> Rc<Leaf<FileContents>> {
        Rc::new(Leaf {
            stat: stat_with_mtime(mtime),
            content: LeafContent::Regular(FileContents::default()),
        })
    }

    // Helper to create a simple Leaf (symlink)
    fn new_leaf_symlink(target: &str, mtime: i64) -> Rc<Leaf<FileContents>> {
        Rc::new(Leaf {
            stat: stat_with_mtime(mtime),
            content: LeafContent::Symlink(OsString::from(target).into_boxed_os_str()),
        })
    }

    // Helper to create an empty Directory Inode with a specific mtime
    fn new_dir_inode<T>(mtime: i64) -> Inode<T> {
        Inode::Directory(Box::new(Directory {
            stat: stat_with_mtime(mtime),
            entries: BTreeMap::new(),
        }))
    }

    // Helper to create a Directory Inode with specific stat
    fn new_dir_inode_with_stat<T>(stat: Stat) -> Inode<T> {
        Inode::Directory(Box::new(Directory {
            stat,
            entries: BTreeMap::new(),
        }))
    }

    #[test]
    fn test_directory_default() {
        let dir = Directory::<()>::default();
        assert_eq!(dir.stat.st_uid, 0);
        assert_eq!(dir.stat.st_gid, 0);
        assert_eq!(dir.stat.st_mode, 0o555);
        assert_eq!(dir.stat.st_mtim_sec, 0);
        assert!(dir.stat.xattrs.borrow().is_empty());
        assert!(dir.entries.is_empty());
    }

    #[test]
    fn test_directory_new() {
        let stat = stat_with_mtime(123);
        let dir = Directory::<()>::new(stat);
        assert_eq!(dir.stat.st_mtim_sec, 123);
        assert!(dir.entries.is_empty());
    }

    #[test]
    fn test_insert_and_get_leaf() {
        let mut dir = Directory::<FileContents>::default();
        let leaf = new_leaf_file(10);
        dir.insert(OsStr::new("file.txt"), Inode::Leaf(Rc::clone(&leaf)));
        assert_eq!(dir.entries.len(), 1);

        let retrieved_leaf_rc = dir.ref_leaf(OsStr::new("file.txt")).unwrap();
        assert!(Rc::ptr_eq(&retrieved_leaf_rc, &leaf));

        let regular_file_content = dir.get_file(OsStr::new("file.txt")).unwrap();
        assert!(matches!(regular_file_content, FileContents {}));
    }

    #[test]
    fn test_insert_and_get_directory() {
        let mut dir = Directory::<()>::default();
        let sub_dir_inode = new_dir_inode(20);
        dir.insert(OsStr::new("subdir"), sub_dir_inode);
        assert_eq!(dir.entries.len(), 1);

        let retrieved_subdir = dir.get_directory(OsStr::new("subdir")).unwrap();
        assert_eq!(retrieved_subdir.stat.st_mtim_sec, 20);

        let retrieved_subdir_opt = dir
            .get_directory_opt(OsStr::new("subdir"))
            .unwrap()
            .unwrap();
        assert_eq!(retrieved_subdir_opt.stat.st_mtim_sec, 20);
    }

    #[test]
    fn test_get_directory_errors() {
        let mut root = Directory::default();
        root.insert(OsStr::new("dir1"), new_dir_inode(10));
        root.insert(OsStr::new("file1"), Inode::Leaf(new_leaf_file(30)));

        match root.get_directory(OsStr::new("nonexistent")) {
            Err(ImageError::NotFound(name)) => assert_eq!(name.to_str().unwrap(), "nonexistent"),
            _ => panic!("Expected NotFound"),
        }
        assert!(root
            .get_directory_opt(OsStr::new("nonexistent"))
            .unwrap()
            .is_none());

        match root.get_directory(OsStr::new("file1")) {
            Err(ImageError::NotADirectory(name)) => assert_eq!(name.to_str().unwrap(), "file1"),
            _ => panic!("Expected NotADirectory"),
        }
    }

    #[test]
    fn test_get_file_errors() {
        let mut dir = Directory::default();
        dir.insert(OsStr::new("subdir"), new_dir_inode(10));
        dir.insert(
            OsStr::new("link.txt"),
            Inode::Leaf(new_leaf_symlink("target", 20)),
        );

        match dir.get_file(OsStr::new("nonexistent.txt")) {
            Err(ImageError::NotFound(name)) => {
                assert_eq!(name.to_str().unwrap(), "nonexistent.txt")
            }
            _ => panic!("Expected NotFound"),
        }
        assert!(dir
            .get_file_opt(OsStr::new("nonexistent.txt"))
            .unwrap()
            .is_none());

        match dir.get_file(OsStr::new("subdir")) {
            Err(ImageError::IsADirectory(name)) => assert_eq!(name.to_str().unwrap(), "subdir"),
            _ => panic!("Expected IsADirectory"),
        }
        match dir.get_file(OsStr::new("link.txt")) {
            Err(ImageError::IsNotRegular(name)) => assert_eq!(name.to_str().unwrap(), "link.txt"),
            res => panic!("Expected IsNotRegular, got {res:?}"),
        }
    }

    #[test]
    fn test_remove() {
        let mut dir = Directory::default();
        dir.insert(OsStr::new("file1.txt"), Inode::Leaf(new_leaf_file(10)));
        dir.insert(OsStr::new("subdir"), new_dir_inode(20));
        assert_eq!(dir.entries.len(), 2);

        dir.remove(OsStr::new("file1.txt"));
        assert_eq!(dir.entries.len(), 1);
        assert!(!dir.entries.contains_key(OsStr::new("file1.txt")));

        dir.remove(OsStr::new("nonexistent")); // Should be no-op
        assert_eq!(dir.entries.len(), 1);
    }

    #[test]
    fn test_merge() {
        let mut dir = Directory::default();

        // Merge Leaf onto empty
        dir.merge(OsStr::new("item"), Inode::Leaf(new_leaf_file(10)));
        assert_eq!(
            dir.entries
                .get(OsStr::new("item"))
                .unwrap()
                .stat()
                .st_mtim_sec,
            10
        );

        // Merge Directory onto existing Directory
        let mut existing_dir_inode = new_dir_inode_with_stat(stat_with_mtime(80));
        if let Inode::Directory(ref mut ed_box) = existing_dir_inode {
            ed_box.insert(OsStr::new("inner_file"), Inode::Leaf(new_leaf_file(85)));
        }
        dir.insert(OsStr::new("merged_dir"), existing_dir_inode);

        let new_merging_dir_inode = new_dir_inode_with_stat(stat_with_mtime(90));
        dir.merge(OsStr::new("merged_dir"), new_merging_dir_inode);

        match dir.entries.get(OsStr::new("merged_dir")) {
            Some(Inode::Directory(d)) => {
                assert_eq!(d.stat.st_mtim_sec, 90); // Stat updated
                assert_eq!(d.entries.len(), 1); // Inner file preserved
                assert!(d.entries.contains_key(OsStr::new("inner_file")));
            }
            _ => panic!("Expected directory after merge"),
        }

        // Merge Leaf onto Directory (replaces)
        dir.merge(OsStr::new("merged_dir"), Inode::Leaf(new_leaf_file(100)));
        assert!(matches!(
            dir.entries.get(OsStr::new("merged_dir")),
            Some(Inode::Leaf(_))
        ));
        assert_eq!(
            dir.entries
                .get(OsStr::new("merged_dir"))
                .unwrap()
                .stat()
                .st_mtim_sec,
            100
        );
    }

    #[test]
    fn test_clear() {
        let mut dir = Directory::default();
        dir.insert(OsStr::new("file1"), Inode::Leaf(new_leaf_file(10)));
        dir.stat.st_mtim_sec = 100;

        dir.clear();
        assert!(dir.entries.is_empty());
        assert_eq!(dir.stat.st_mtim_sec, 100); // Stat should be unmodified
    }

    #[test]
    fn test_newest_file() {
        let mut root = Directory::new(stat_with_mtime(5));
        assert_eq!(root.newest_file(), 5);

        root.insert(OsStr::new("file1"), Inode::Leaf(new_leaf_file(10)));
        assert_eq!(root.newest_file(), 10);

        let subdir_stat = stat_with_mtime(15);
        let mut subdir = Box::new(Directory::new(subdir_stat));
        subdir.insert(OsStr::new("subfile1"), Inode::Leaf(new_leaf_file(12)));
        root.insert(OsStr::new("subdir"), Inode::Directory(subdir));
        assert_eq!(root.newest_file(), 15);

        if let Some(Inode::Directory(sd)) = root.entries.get_mut(OsStr::new("subdir")) {
            sd.insert(OsStr::new("subfile2"), Inode::Leaf(new_leaf_file(20)));
        }
        assert_eq!(root.newest_file(), 20);

        root.stat.st_mtim_sec = 25;
        assert_eq!(root.newest_file(), 25);
    }

    #[test]
    fn test_iteration_entries_sorted_inodes() {
        let mut dir = Directory::default();
        dir.insert(OsStr::new("b_file"), Inode::Leaf(new_leaf_file(10)));
        dir.insert(OsStr::new("a_dir"), new_dir_inode(20));
        dir.insert(
            OsStr::new("c_link"),
            Inode::Leaf(new_leaf_symlink("target", 30)),
        );

        let names_from_entries: Vec<&OsStr> = dir.entries().map(|(name, _)| name).collect();
        assert_eq!(names_from_entries.len(), 3); // BTreeMap iter is sorted
        assert!(names_from_entries.contains(&OsStr::new("a_dir")));
        assert!(names_from_entries.contains(&OsStr::new("b_file")));
        assert!(names_from_entries.contains(&OsStr::new("c_link")));

        let sorted_names: Vec<&OsStr> = dir.sorted_entries().map(|(name, _)| name).collect();
        assert_eq!(
            sorted_names,
            vec![
                OsStr::new("a_dir"),
                OsStr::new("b_file"),
                OsStr::new("c_link")
            ]
        );

        let mut inode_types = vec![];
        for inode in dir.inodes() {
            match inode {
                Inode::Directory(_) => inode_types.push("dir"),
                Inode::Leaf(_) => inode_types.push("leaf"),
            }
        }
        assert_eq!(inode_types.len(), 3);
        assert_eq!(inode_types.iter().filter(|&&t| t == "dir").count(), 1);
        assert_eq!(inode_types.iter().filter(|&&t| t == "leaf").count(), 2);
    }
}
