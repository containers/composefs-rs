//! OCI image processing and filesystem construction.
//!
//! This module handles the conversion of OCI container image layers into composefs filesystems.
//! It processes tar entries from container layers, handles overlayfs semantics like whiteouts,
//! and constructs the final filesystem tree that can be mounted or analyzed.
//!
//! The main functionality centers around `create_filesystem()` which takes an OCI image configuration
//! and builds a complete filesystem by processing all layers in order. The `process_entry()` function
//! handles individual tar entries and implements overlayfs whiteout semantics for proper layer merging.

use std::{ffi::OsStr, os::unix::ffi::OsStrExt, rc::Rc};

use anyhow::{ensure, Context, Result};
use oci_spec::image::ImageConfiguration;

use composefs::{
    fsverity::FsVerityHashValue,
    repository::Repository,
    tree::{Directory, FileSystem, Inode, Leaf},
};

use crate::tar::{TarEntry, TarItem};

/// Processes a single tar entry and adds it to the filesystem.
///
/// Handles various tar entry types (regular files, directories, symlinks, hardlinks, devices, fifos)
/// and implements overlayfs whiteout semantics for proper layer merging. Files named `.wh.<name>`
/// delete the corresponding file, and `.wh..wh.opq` marks a directory as opaque (clearing all contents).
///
/// Returns an error if the entry cannot be processed or added to the filesystem.
pub fn process_entry<ObjectID: FsVerityHashValue>(
    filesystem: &mut FileSystem<ObjectID>,
    entry: TarEntry<ObjectID>,
) -> Result<()> {
    if entry.path.file_name().is_none() {
        // special handling for the root directory
        ensure!(
            matches!(entry.item, TarItem::Directory),
            "Unpacking layer tar: filename {:?} must be a directory",
            entry.path
        );

        // Update the stat, but don't do anything else
        filesystem.set_root_stat(entry.stat);
        return Ok(());
    }

    let inode = match entry.item {
        TarItem::Directory => Inode::Directory(Box::from(Directory::new(entry.stat))),
        TarItem::Leaf(content) => Inode::Leaf(Rc::new(Leaf {
            stat: entry.stat,
            content,
        })),
        TarItem::Hardlink(target) => {
            let (dir, filename) = filesystem.root.split(&target)?;
            Inode::Leaf(dir.ref_leaf(filename)?)
        }
    };

    let (dir, filename) = filesystem
        .root
        .split_mut(entry.path.as_os_str())
        .with_context(|| {
            format!(
                "Error unpacking container layer file {:?} {:?}",
                entry.path, inode
            )
        })?;

    let bytes = filename.as_bytes();
    if let Some(whiteout) = bytes.strip_prefix(b".wh.") {
        if whiteout == b".wh..opq" {
            // complete name is '.wh..wh..opq'
            dir.clear();
        } else {
            dir.remove(OsStr::from_bytes(whiteout));
        }
    } else {
        dir.merge(filename, inode);
    }

    Ok(())
}

/// Creates a filesystem from the given OCI container.  No special transformations are performed to
/// make the filesystem bootable.
pub fn create_filesystem<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    config_name: &str,
    config_verity: Option<&ObjectID>,
) -> Result<FileSystem<ObjectID>> {
    let mut filesystem = FileSystem::default();

    let mut config_stream = repo.open_stream(config_name, config_verity)?;
    let config = ImageConfiguration::from_reader(&mut config_stream)?;

    for diff_id in config.rootfs().diff_ids() {
        let layer_sha256 = super::sha256_from_digest(diff_id)?;
        let layer_verity = config_stream.lookup(&layer_sha256)?;

        let mut layer_stream = repo.open_stream(&hex::encode(layer_sha256), Some(layer_verity))?;
        while let Some(entry) = crate::tar::get_entry(&mut layer_stream)? {
            process_entry(&mut filesystem, entry)?;
        }
    }

    Ok(filesystem)
}

#[cfg(test)]
mod test {
    use composefs::{
        dumpfile::write_dumpfile,
        fsverity::Sha256HashValue,
        tree::{LeafContent, RegularFile, Stat},
    };
    use std::{cell::RefCell, collections::BTreeMap, io::BufRead, path::PathBuf};

    use super::*;

    fn file_entry<ObjectID: FsVerityHashValue>(path: &str) -> TarEntry<ObjectID> {
        TarEntry {
            path: PathBuf::from(path),
            stat: Stat {
                st_mode: 0o644,
                st_uid: 0,
                st_gid: 0,
                st_mtim_sec: 0,
                xattrs: RefCell::new(BTreeMap::new()),
            },
            item: TarItem::Leaf(LeafContent::Regular(RegularFile::Inline([].into()))),
        }
    }

    fn dir_entry<ObjectID: FsVerityHashValue>(path: &str) -> TarEntry<ObjectID> {
        TarEntry {
            path: PathBuf::from(path),
            stat: Stat {
                st_mode: 0o755,
                st_uid: 0,
                st_gid: 0,
                st_mtim_sec: 0,
                xattrs: RefCell::new(BTreeMap::new()),
            },
            item: TarItem::Directory,
        }
    }

    fn assert_files(fs: &FileSystem<impl FsVerityHashValue>, expected: &[&str]) -> Result<()> {
        let mut out = vec![];
        write_dumpfile(&mut out, fs)?;
        let actual: Vec<String> = out
            .lines()
            .map(|line| line.unwrap().split_once(' ').unwrap().0.into())
            .collect();

        similar_asserts::assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    fn test_process_entry() -> Result<()> {
        let mut fs = FileSystem::<Sha256HashValue>::default();

        // both with and without leading slash should be supported
        process_entry(&mut fs, dir_entry("/a"))?;
        process_entry(&mut fs, dir_entry("b"))?;
        process_entry(&mut fs, dir_entry("c"))?;
        assert_files(&fs, &["/", "/a", "/b", "/c"])?;

        // add some files
        process_entry(&mut fs, file_entry("/a/b"))?;
        process_entry(&mut fs, file_entry("/a/c"))?;
        process_entry(&mut fs, file_entry("/b/a"))?;
        process_entry(&mut fs, file_entry("/b/c"))?;
        process_entry(&mut fs, file_entry("/c/a"))?;
        process_entry(&mut fs, file_entry("/c/c"))?;
        assert_files(
            &fs,
            &[
                "/", "/a", "/a/b", "/a/c", "/b", "/b/a", "/b/c", "/c", "/c/a", "/c/c",
            ],
        )?;

        // try some whiteouts
        process_entry(&mut fs, file_entry(".wh.a"))?; // entire dir
        process_entry(&mut fs, file_entry("/b/.wh..wh..opq"))?; // opaque dir
        process_entry(&mut fs, file_entry("/c/.wh.c"))?; // single file
        assert_files(&fs, &["/", "/b", "/c", "/c/a"])?;

        Ok(())
    }
}
