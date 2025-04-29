use std::{ffi::OsStr, os::unix::ffi::OsStrExt, rc::Rc};

use anyhow::{ensure, Context, Result};
use oci_spec::image::ImageConfiguration;

use crate::{
    dumpfile::write_dumpfile,
    erofs::writer::mkfs_erofs,
    fsverity::FsVerityHashValue,
    oci::{
        self,
        tar::{TarEntry, TarItem},
    },
    repository::Repository,
    selabel::selabel,
    tree::{Directory, FileSystem, Inode, Leaf},
};

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
        if whiteout == b".wh.opq" {
            // complete name is '.wh..wh.opq'
            dir.clear();
        } else {
            dir.remove(OsStr::from_bytes(whiteout));
        }
    } else {
        dir.merge(filename, inode);
    }

    Ok(())
}

pub fn compose_filesystem<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    layers: &[String],
) -> Result<FileSystem<ObjectID>> {
    let mut filesystem = FileSystem::default();

    for layer in layers {
        let mut split_stream = repo.open_stream(layer, None)?;
        while let Some(entry) = oci::tar::get_entry(&mut split_stream)? {
            process_entry(&mut filesystem, entry)?;
        }
    }

    selabel(&mut filesystem, repo)?;
    filesystem.ensure_root_stat();

    Ok(filesystem)
}

pub fn create_dumpfile(repo: &Repository<impl FsVerityHashValue>, layers: &[String]) -> Result<()> {
    let filesystem = compose_filesystem(repo, layers)?;
    let mut stdout = std::io::stdout();
    write_dumpfile(&mut stdout, &filesystem)?;
    Ok(())
}

pub fn create_image<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    config: &str,
    name: Option<&str>,
    verity: Option<&ObjectID>,
) -> Result<ObjectID> {
    let mut filesystem = FileSystem::default();

    let mut config_stream = repo.open_stream(config, verity)?;
    let config = ImageConfiguration::from_reader(&mut config_stream)?;

    for diff_id in config.rootfs().diff_ids() {
        let layer_sha256 = super::sha256_from_digest(diff_id)?;
        let layer_verity = config_stream.lookup(&layer_sha256)?;

        let mut layer_stream = repo.open_stream(&hex::encode(layer_sha256), Some(layer_verity))?;
        while let Some(entry) = oci::tar::get_entry(&mut layer_stream)? {
            process_entry(&mut filesystem, entry)?;
        }
    }

    selabel(&mut filesystem, repo)?;
    filesystem.ensure_root_stat();

    let erofs = mkfs_erofs(&filesystem);
    repo.write_image(name, &erofs)
}

#[cfg(test)]
mod test {
    use crate::{
        fsverity::Sha256HashValue,
        tree::{LeafContent, RegularFile, Stat},
    };
    use std::{cell::RefCell, collections::BTreeMap, io::BufRead, path::PathBuf};

    use super::*;

    fn file_entry<ObjectID: FsVerityHashValue>(path: &str) -> oci::tar::TarEntry<ObjectID> {
        oci::tar::TarEntry {
            path: PathBuf::from(path),
            stat: Stat {
                st_mode: 0o644,
                st_uid: 0,
                st_gid: 0,
                st_mtim_sec: 0,
                xattrs: RefCell::new(BTreeMap::new()),
            },
            item: oci::tar::TarItem::Leaf(LeafContent::Regular(RegularFile::Inline([].into()))),
        }
    }

    fn dir_entry<ObjectID: FsVerityHashValue>(path: &str) -> oci::tar::TarEntry<ObjectID> {
        oci::tar::TarEntry {
            path: PathBuf::from(path),
            stat: Stat {
                st_mode: 0o755,
                st_uid: 0,
                st_gid: 0,
                st_mtim_sec: 0,
                xattrs: RefCell::new(BTreeMap::new()),
            },
            item: oci::tar::TarItem::Directory,
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
        process_entry(&mut fs, file_entry("/b/.wh..wh.opq"))?; // opaque dir
        process_entry(&mut fs, file_entry("/c/.wh.c"))?; // single file
        assert_files(&fs, &["/", "/b", "/c", "/c/a"])?;

        Ok(())
    }
}
