use std::{ffi::OsStr, os::unix::ffi::OsStrExt, rc::Rc};

use anyhow::Result;
use oci_spec::image::ImageConfiguration;

use crate::{
    dumpfile::write_dumpfile,
    erofs::writer::mkfs_erofs,
    fsverity::Sha256HashValue,
    image::{Directory, FileSystem, Inode, Leaf},
    oci::{
        self,
        tar::{TarEntry, TarItem},
    },
    repository::Repository,
    selabel::selabel,
};

pub fn process_entry(filesystem: &mut FileSystem, entry: TarEntry) -> Result<()> {
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

    let (dir, filename) = filesystem.root.split_mut(entry.path.as_os_str())?;

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

pub fn compose_filesystem(repo: &Repository, layers: &[String]) -> Result<FileSystem> {
    let mut filesystem = FileSystem::new();

    for layer in layers {
        let mut split_stream = repo.open_stream(layer, None)?;
        while let Some(entry) = oci::tar::get_entry(&mut split_stream)? {
            process_entry(&mut filesystem, entry)?;
        }
    }

    selabel(&mut filesystem, repo)?;
    filesystem.done();

    Ok(filesystem)
}

pub fn create_dumpfile(repo: &Repository, layers: &[String]) -> Result<()> {
    let filesystem = compose_filesystem(repo, layers)?;
    let mut stdout = std::io::stdout();
    write_dumpfile(&mut stdout, &filesystem)?;
    Ok(())
}

pub fn create_image(
    repo: &Repository,
    config: &str,
    name: Option<&str>,
    verity: Option<&Sha256HashValue>,
) -> Result<Sha256HashValue> {
    let mut filesystem = FileSystem::new();

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
    filesystem.done();

    let erofs = mkfs_erofs(&filesystem);
    repo.write_image(name, &erofs)
}

#[cfg(test)]
mod test {
    use crate::image::{LeafContent, RegularFile, Stat};
    use std::{cell::RefCell, collections::BTreeMap, io::BufRead, path::PathBuf};

    use super::*;

    fn file_entry(path: &str) -> oci::tar::TarEntry {
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

    fn dir_entry(path: &str) -> oci::tar::TarEntry {
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

    fn assert_files(fs: &FileSystem, expected: &[&str]) -> Result<()> {
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
        let mut fs = FileSystem::new();

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
