//! A filesystem tree which stores regular files using the composefs strategy
//! of inlining small files, and having an external fsverity reference for
//! larger ones.

use crate::fsverity::FsVerityHashValue;

pub use crate::generic_tree::{self, ImageError, Stat};

/// Represents a regular file's content storage strategy in composefs.
///
/// Files can be stored inline for small content or externally referenced
/// for larger files using fsverity hashing.
#[derive(Debug, Clone)]
pub enum RegularFile<ObjectID: FsVerityHashValue> {
    /// File content stored inline as raw bytes.
    Inline(Box<[u8]>),
    /// File stored externally, referenced by fsverity hash and size.
    ///
    /// The tuple contains (fsverity hash, file size in bytes).
    External(ObjectID, u64),
}

// Re-export generic types. Note that we don't need to re-write
// the generic constraint T: FsVerityHashValue here because it will
// be transitively enforced.

/// Content of a leaf node in the filesystem tree, specialized for composefs regular files.
pub type LeafContent<T> = generic_tree::LeafContent<RegularFile<T>>;

/// A leaf node in the filesystem tree (file, symlink, or device), specialized for composefs regular files.
pub type Leaf<T> = generic_tree::Leaf<RegularFile<T>>;

/// A directory in the filesystem tree, specialized for composefs regular files.
pub type Directory<T> = generic_tree::Directory<RegularFile<T>>;

/// An inode representing either a directory or a leaf node, specialized for composefs regular files.
pub type Inode<T> = generic_tree::Inode<RegularFile<T>>;

/// A complete filesystem tree, specialized for composefs regular files.
pub type FileSystem<T> = generic_tree::FileSystem<RegularFile<T>>;

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap, ffi::OsStr, rc::Rc};

    use super::*;
    use crate::fsverity::Sha256HashValue;

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

    // Helper to create an empty Directory Inode with a specific mtime
    fn new_dir_inode(mtime: i64) -> Inode<Sha256HashValue> {
        Inode::Directory(Box::new(Directory {
            stat: stat_with_mtime(mtime),
            entries: BTreeMap::new(),
        }))
    }

    // Helper to create a simple Leaf (e.g., an empty inline file)
    fn new_leaf_file(mtime: i64) -> Rc<Leaf<Sha256HashValue>> {
        Rc::new(Leaf {
            stat: stat_with_mtime(mtime),
            content: LeafContent::Regular(super::RegularFile::Inline(Default::default())),
        })
    }

    // Helper for default stat in tests
    fn default_stat() -> Stat {
        Stat {
            st_mode: 0o755,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 0,
            xattrs: RefCell::new(BTreeMap::new()),
        }
    }

    #[test]
    fn test_insert_and_get_leaf() {
        let mut dir = Directory::<Sha256HashValue>::new(default_stat());
        let leaf = new_leaf_file(10);
        dir.insert(OsStr::new("file.txt"), Inode::Leaf(Rc::clone(&leaf)));
        assert_eq!(dir.entries.len(), 1);

        let retrieved_leaf_rc = dir.ref_leaf(OsStr::new("file.txt")).unwrap();
        assert!(Rc::ptr_eq(&retrieved_leaf_rc, &leaf));

        let regular_file_content = dir.get_file(OsStr::new("file.txt")).unwrap();
        assert!(matches!(
            regular_file_content,
            super::RegularFile::Inline(_)
        ));
    }

    #[test]
    fn test_insert_and_get_directory() {
        let mut dir = Directory::<Sha256HashValue>::new(default_stat());
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
}
