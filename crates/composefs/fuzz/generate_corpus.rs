//! Generate seed corpus files for the EROFS fuzz targets.
//!
//! Each seed is a valid EROFS image that exercises a distinct reader code path:
//! inline/external files, special file types, xattrs, directory
//! layouts, hardlinks, and edge cases around inode sizing.
//!
//! Run via: `cargo run --manifest-path crates/composefs/fuzz/Cargo.toml --bin generate-corpus`
//! or:      `just generate-corpus`

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;

use composefs::erofs::writer::mkfs_erofs;
use composefs::fsverity::{FsVerityHashValue, Sha256HashValue};
use composefs::generic_tree::{self, Stat};
use composefs::tree::{self, FileSystem, RegularFile};

type Dir = tree::Directory<Sha256HashValue>;
type Leaf = tree::Leaf<Sha256HashValue>;
type Inode = tree::Inode<Sha256HashValue>;
type LeafContent = tree::LeafContent<Sha256HashValue>;

/// Create a Stat with the given mode, uid, gid, mtime.
fn stat(mode: u32, uid: u32, gid: u32, mtime: i64) -> Stat {
    Stat {
        st_mode: mode,
        st_uid: uid,
        st_gid: gid,
        st_mtim_sec: mtime,
        xattrs: RwLock::new(BTreeMap::new()),
    }
}

/// Create a default directory stat (0o755, root, mtime=0).
fn dir_stat() -> Stat {
    stat(0o755, 0, 0, 0)
}

/// Create a default file stat (0o644, root, mtime=0).
fn file_stat() -> Stat {
    stat(0o644, 0, 0, 0)
}

/// Build a FileSystem with just an empty root directory.
fn empty_root() -> FileSystem<Sha256HashValue> {
    FileSystem::new(dir_stat())
}

/// Insert a leaf into a directory.
fn insert_leaf(dir: &mut Dir, name: &str, leaf: Leaf) {
    dir.insert(OsStr::new(name), Inode::Leaf(Arc::new(leaf)));
}

/// Insert a subdirectory into a directory, returning a mutable reference to it.
fn insert_dir<'a>(parent: &'a mut Dir, name: &str, s: Stat) -> &'a mut Dir {
    parent.insert(
        OsStr::new(name),
        Inode::Directory(Arc::new(generic_tree::Directory::new(s))),
    );
    parent.get_directory_mut(OsStr::new(name)).unwrap()
}

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    let mut seeds: Vec<(&str, Vec<u8>)> = Vec::new();

    // 1. Empty root
    {
        let fs = empty_root();
        let image = mkfs_erofs(&fs);
        seeds.push(("empty_root", image.into()));
    }

    // 2. Single inline file (small content stored in inode)
    {
        let mut fs = empty_root();
        insert_leaf(
            &mut fs.root,
            "hello.txt",
            Leaf {
                stat: file_stat(),
                content: LeafContent::Regular(RegularFile::Inline(
                    b"Hello, world!".to_vec().into_boxed_slice(),
                )),
            },
        );
        let image = mkfs_erofs(&fs);
        seeds.push(("single_inline_file", image.into()));
    }

    // 3. Single external (chunk-based) regular file
    {
        let mut fs = empty_root();
        // Use a dummy hash and a realistic file size
        let hash = Sha256HashValue::EMPTY;
        insert_leaf(
            &mut fs.root,
            "data.bin",
            Leaf {
                stat: file_stat(),
                content: LeafContent::Regular(RegularFile::External(hash, 65536)),
            },
        );
        let image = mkfs_erofs(&fs);
        seeds.push(("single_external_file", image.into()));
    }

    // 4. Symlink
    {
        let mut fs = empty_root();
        insert_leaf(
            &mut fs.root,
            "link",
            Leaf {
                stat: stat(0o777, 0, 0, 0),
                content: LeafContent::Symlink(OsString::from("/target/path").into_boxed_os_str()),
            },
        );
        let image = mkfs_erofs(&fs);
        seeds.push(("symlink", image.into()));
    }

    // 5. FIFO
    {
        let mut fs = empty_root();
        insert_leaf(
            &mut fs.root,
            "mypipe",
            Leaf {
                stat: file_stat(),
                content: LeafContent::Fifo,
            },
        );
        let image = mkfs_erofs(&fs);
        seeds.push(("fifo", image.into()));
    }

    // 6. Character device
    {
        let mut fs = empty_root();
        insert_leaf(
            &mut fs.root,
            "null",
            Leaf {
                stat: stat(0o666, 0, 0, 0),
                content: LeafContent::CharacterDevice(makedev(1, 3)),
            },
        );
        let image = mkfs_erofs(&fs);
        seeds.push(("chardev", image.into()));
    }

    // 7. Block device
    {
        let mut fs = empty_root();
        insert_leaf(
            &mut fs.root,
            "sda",
            Leaf {
                stat: stat(0o660, 0, 6, 0),
                content: LeafContent::BlockDevice(makedev(8, 0)),
            },
        );
        let image = mkfs_erofs(&fs);
        seeds.push(("blockdev", image.into()));
    }

    // 8. Socket
    {
        let mut fs = empty_root();
        insert_leaf(
            &mut fs.root,
            "mysock",
            Leaf {
                stat: file_stat(),
                content: LeafContent::Socket,
            },
        );
        let image = mkfs_erofs(&fs);
        seeds.push(("socket", image.into()));
    }

    // 9. Nested directories: /a/b/c/file
    {
        let mut fs = empty_root();
        let a = insert_dir(&mut fs.root, "a", dir_stat());
        let b = insert_dir(a, "b", dir_stat());
        let c = insert_dir(b, "c", dir_stat());
        insert_leaf(
            c,
            "file",
            Leaf {
                stat: file_stat(),
                content: LeafContent::Regular(RegularFile::Inline(
                    b"nested content".to_vec().into_boxed_slice(),
                )),
            },
        );
        let image = mkfs_erofs(&fs);
        seeds.push(("nested_dirs", image.into()));
    }

    // 10. Many entries (20+ files to exercise multi-block directories)
    {
        let mut fs = empty_root();
        for i in 0..25 {
            let name = format!("file_{i:03}");
            let content = format!("content of file {i}");
            insert_leaf(
                &mut fs.root,
                &name,
                Leaf {
                    stat: file_stat(),
                    content: LeafContent::Regular(RegularFile::Inline(
                        content.into_bytes().into_boxed_slice(),
                    )),
                },
            );
        }
        let image = mkfs_erofs(&fs);
        seeds.push(("many_entries", image.into()));
    }

    // 11. Extended attributes
    {
        let mut fs = empty_root();
        let xattr_stat = file_stat();
        {
            let mut xattrs = xattr_stat.xattrs.write().unwrap();
            xattrs.insert(
                Box::from(OsStr::new("security.selinux")),
                Box::from(b"system_u:object_r:usr_t:s0".as_slice()),
            );
            xattrs.insert(
                Box::from(OsStr::new("user.test")),
                Box::from(b"test_value".as_slice()),
            );
        }
        insert_leaf(
            &mut fs.root,
            "xattr_file",
            Leaf {
                stat: xattr_stat,
                content: LeafContent::Regular(RegularFile::Inline(
                    b"has xattrs".to_vec().into_boxed_slice(),
                )),
            },
        );
        let image = mkfs_erofs(&fs);
        seeds.push(("xattrs", image.into()));
    }

    // 12. Mixed types — one of every file type in a single directory
    {
        let mut fs = empty_root();
        insert_leaf(
            &mut fs.root,
            "regular",
            Leaf {
                stat: file_stat(),
                content: LeafContent::Regular(RegularFile::Inline(
                    b"data".to_vec().into_boxed_slice(),
                )),
            },
        );
        insert_leaf(
            &mut fs.root,
            "link",
            Leaf {
                stat: stat(0o777, 0, 0, 0),
                content: LeafContent::Symlink(OsString::from("regular").into_boxed_os_str()),
            },
        );
        insert_leaf(
            &mut fs.root,
            "pipe",
            Leaf {
                stat: file_stat(),
                content: LeafContent::Fifo,
            },
        );
        insert_leaf(
            &mut fs.root,
            "sock",
            Leaf {
                stat: file_stat(),
                content: LeafContent::Socket,
            },
        );
        insert_leaf(
            &mut fs.root,
            "chrdev",
            Leaf {
                stat: stat(0o666, 0, 0, 0),
                content: LeafContent::CharacterDevice(makedev(1, 3)),
            },
        );
        insert_leaf(
            &mut fs.root,
            "blkdev",
            Leaf {
                stat: stat(0o660, 0, 6, 0),
                content: LeafContent::BlockDevice(makedev(8, 0)),
            },
        );
        insert_dir(&mut fs.root, "subdir", dir_stat());
        let hash = Sha256HashValue::EMPTY;
        insert_leaf(
            &mut fs.root,
            "external",
            Leaf {
                stat: file_stat(),
                content: LeafContent::Regular(RegularFile::External(hash, 4096)),
            },
        );
        let image = mkfs_erofs(&fs);
        seeds.push(("mixed_types", image.into()));
    }

    // 13. Hardlink — two entries sharing the same Arc<Leaf> (nlink > 1)
    {
        let mut fs = empty_root();
        let shared = Arc::new(Leaf {
            stat: file_stat(),
            content: LeafContent::Regular(RegularFile::Inline(
                b"shared content".to_vec().into_boxed_slice(),
            )),
        });
        fs.root.insert(
            OsStr::new("original").into(),
            Inode::Leaf(Arc::clone(&shared)),
        );
        fs.root
            .insert(OsStr::new("hardlink").into(), Inode::Leaf(shared));
        let image = mkfs_erofs(&fs);
        seeds.push(("hardlink", image.into()));
    }

    // 14. Large inline — file with maximum inline content (just under 4096 bytes)
    {
        let mut fs = empty_root();
        let content = vec![0xABu8; 4000]; // just under block size
        insert_leaf(
            &mut fs.root,
            "large_inline.bin",
            Leaf {
                stat: file_stat(),
                content: LeafContent::Regular(RegularFile::Inline(content.into_boxed_slice())),
            },
        );
        let image = mkfs_erofs(&fs);
        seeds.push(("large_inline", image.into()));
    }

    // 15. Deep nesting — 8 levels of directories
    {
        let mut fs = empty_root();
        let names = ["d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8"];
        let mut current = &mut fs.root;
        for name in &names {
            current = insert_dir(current, name, dir_stat());
        }
        insert_leaf(
            current,
            "deep_file",
            Leaf {
                stat: file_stat(),
                content: LeafContent::Regular(RegularFile::Inline(
                    b"deep".to_vec().into_boxed_slice(),
                )),
            },
        );
        let image = mkfs_erofs(&fs);
        seeds.push(("deep_nesting", image.into()));
    }

    // 16. Nonzero mtime
    {
        let mut fs = FileSystem::new(stat(0o755, 0, 0, 1000000));
        insert_leaf(
            &mut fs.root,
            "old",
            Leaf {
                stat: stat(0o644, 0, 0, 500000),
                content: LeafContent::Regular(RegularFile::Inline(
                    b"old file".to_vec().into_boxed_slice(),
                )),
            },
        );
        insert_leaf(
            &mut fs.root,
            "new",
            Leaf {
                stat: stat(0o644, 0, 0, 1700000000),
                content: LeafContent::Regular(RegularFile::Inline(
                    b"new file".to_vec().into_boxed_slice(),
                )),
            },
        );
        let image = mkfs_erofs(&fs);
        seeds.push(("nonzero_mtime", image.into()));
    }

    // 17. Large uid/gid — forces extended inodes
    {
        let big_id = u16::MAX as u32 + 1; // 65536, won't fit in u16
        let mut fs = FileSystem::new(stat(0o755, big_id, big_id, 0));
        insert_leaf(
            &mut fs.root,
            "bigids.txt",
            Leaf {
                stat: stat(0o644, big_id, big_id, 0),
                content: LeafContent::Regular(RegularFile::Inline(
                    b"big ids".to_vec().into_boxed_slice(),
                )),
            },
        );
        let image = mkfs_erofs(&fs);
        seeds.push(("large_uid_gid", image.into()));
    }

    // Write seeds to corpus directories for both fuzz targets
    let targets = ["read_image", "debug_image"];
    for target in &targets {
        let corpus_dir = manifest_dir.join("corpus").join(target);
        fs::create_dir_all(&corpus_dir)
            .unwrap_or_else(|e| panic!("create {}: {e}", corpus_dir.display()));
    }

    let mut count = 0;
    for (name, data) in &seeds {
        for target in &targets {
            let corpus_dir = manifest_dir.join("corpus").join(target);
            let path = corpus_dir.join(name);
            fs::write(&path, data).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        }
        count += 1;
        println!("{count:>4}  {size:>6} bytes  {name}", size = data.len());
    }
    println!(
        "\nGenerated {count} seed files for {} fuzz targets",
        targets.len()
    );
}

/// Encode major/minor device numbers into a single u64 (Linux encoding).
fn makedev(major: u32, minor: u32) -> u64 {
    let maj = major as u64;
    let min = minor as u64;
    ((maj & 0xfffff000) << 32) | ((maj & 0xfff) << 8) | ((min & 0xffffff00) << 12) | (min & 0xff)
}
