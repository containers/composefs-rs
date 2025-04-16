use std::{
    cell::RefCell,
    collections::BTreeMap,
    ffi::OsStr,
    io::Write,
    process::{Command, Stdio},
    rc::Rc,
};

use similar_asserts::assert_eq;
use tempfile::NamedTempFile;

use composefs::{
    dumpfile::write_dumpfile,
    erofs::{debug::debug_img, writer::mkfs_erofs},
    fsverity::{FsVerityHashValue, Sha256HashValue},
    image::{Directory, FileSystem, Inode, Leaf, LeafContent, RegularFile, Stat},
};

fn debug_fs(mut fs: FileSystem) -> String {
    fs.done();
    let image = mkfs_erofs(&fs);
    let mut output = vec![];
    debug_img(&mut output, &image).unwrap();
    String::from_utf8(output).unwrap()
}

fn empty(_fs: &mut FileSystem) {}

#[test]
fn test_empty() {
    let mut fs = FileSystem::new();
    empty(&mut fs);
    insta::assert_snapshot!(debug_fs(fs));
}

fn add_leaf(dir: &mut Directory, name: impl AsRef<OsStr>, content: LeafContent) {
    dir.insert(
        name.as_ref(),
        Inode::Leaf(Rc::new(Leaf {
            content,
            stat: Stat {
                st_gid: 0,
                st_uid: 0,
                st_mode: 0,
                st_mtim_sec: 0,
                xattrs: RefCell::new(BTreeMap::new()),
            },
        })),
    );
}

fn simple(fs: &mut FileSystem) {
    let ext_id = Sha256HashValue::from_hex(
        "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
    )
    .unwrap();
    add_leaf(&mut fs.root, "fifo", LeafContent::Fifo);
    add_leaf(
        &mut fs.root,
        "regular-inline",
        LeafContent::Regular(RegularFile::Inline((*b"hihi").into())),
    );
    add_leaf(
        &mut fs.root,
        "regular-external",
        LeafContent::Regular(RegularFile::External(ext_id, 1234)),
    );
    add_leaf(&mut fs.root, "chrdev", LeafContent::CharacterDevice(123));
    add_leaf(&mut fs.root, "blkdev", LeafContent::BlockDevice(123));
    add_leaf(&mut fs.root, "socket", LeafContent::Socket);
    add_leaf(
        &mut fs.root,
        "symlink",
        LeafContent::Symlink(OsStr::new("/target").into()),
    );
}

#[test]
fn test_simple() {
    let mut fs = FileSystem::new();
    simple(&mut fs);
    insta::assert_snapshot!(debug_fs(fs));
}

fn foreach_case(f: fn(&FileSystem)) {
    for case in [empty, simple] {
        let mut fs = FileSystem::new();
        case(&mut fs);
        fs.done();
        f(&fs);
    }
}

#[test_with::executable(fsck.erofs)]
fn test_fsck() {
    foreach_case(|fs| {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&mkfs_erofs(fs)).unwrap();
        let mut fsck = Command::new("fsck.erofs").arg(tmp.path()).spawn().unwrap();
        assert!(fsck.wait().unwrap().success());
    });
}

fn dump_image(img: &[u8]) -> String {
    let mut dump = vec![];
    debug_img(&mut dump, img).unwrap();
    String::from_utf8(dump).unwrap()
}

#[should_panic]
#[test_with::executable(mkcomposefs)]
fn test_vs_mkcomposefs() {
    foreach_case(|fs| {
        let image = mkfs_erofs(fs);

        let mut mkcomposefs = Command::new("mkcomposefs")
            .args(["--min-version=3", "--from-file", "-", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        let mut stdin = mkcomposefs.stdin.take().unwrap();
        write_dumpfile(&mut stdin, fs).unwrap();
        drop(stdin);

        let output = mkcomposefs.wait_with_output().unwrap();
        assert!(output.status.success());
        let mkcomposefs_image = output.stdout.into_boxed_slice();

        if image != mkcomposefs_image {
            let dump = dump_image(&image);
            let mkcomposefs_dump = dump_image(&mkcomposefs_image);
            assert_eq!(mkcomposefs_dump, dump);
        }
        assert_eq!(image, mkcomposefs_image); // fallback if the dump is somehow the same
    });
}
