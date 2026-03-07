//! Tests for mkfs

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
    dumpfile::{dumpfile_to_filesystem, write_dumpfile},
    erofs::{
        debug::debug_img,
        dump::dump_erofs,
        format::{
            ComposefsHeader, FormatVersion, COMPOSEFS_VERSION_V1_0, COMPOSEFS_VERSION_V1_1,
            XATTR_PREFIXES,
        },
        reader::{Image, InodeHeader, InodeOps, InodeType},
        writer::mkfs_erofs,
    },
    fsverity::{FsVerityHashValue, Sha256HashValue},
    tree::{Directory, FileSystem, Inode, Leaf, LeafContent, RegularFile, Stat},
};
use zerocopy::FromBytes;

fn default_stat() -> Stat {
    Stat {
        st_mode: 0o755,
        st_uid: 0,
        st_gid: 0,
        st_mtim_sec: 0,
        xattrs: RefCell::new(BTreeMap::new()),
    }
}

fn mkfs_erofs_default<ObjectID: FsVerityHashValue>(fs: &FileSystem<ObjectID>) -> Box<[u8]> {
    mkfs_erofs(fs, FormatVersion::default())
}

/// Create a Format 1.0 compatible image with all transformations applied.
/// This includes adding the whiteout table and overlay.opaque xattr.
///
/// Note: This takes ownership of the filesystem to avoid Rc clone issues.
/// When FileSystem is cloned, Rc<Leaf> strong_count increments, which would
/// incorrectly affect nlink calculations in the writer.
fn mkfs_erofs_v1_0(mut fs: FileSystem<Sha256HashValue>) -> Box<[u8]> {
    // Apply Format 1.0 transformations (whiteouts + opaque xattr added by mkfs_erofs for V1_0)
    fs.add_overlay_whiteouts();
    mkfs_erofs(&fs, FormatVersion::V1_0)
}

fn debug_fs(fs: FileSystem<impl FsVerityHashValue>) -> String {
    let image = mkfs_erofs_default(&fs);
    let mut output = vec![];
    debug_img(&mut output, &image).unwrap();
    String::from_utf8(output).unwrap()
}

fn empty(_fs: &mut FileSystem<impl FsVerityHashValue>) {}

#[test]
fn test_empty() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    empty(&mut fs);
    insta::assert_snapshot!(debug_fs(fs));
}

fn add_leaf<ObjectID: FsVerityHashValue>(
    dir: &mut Directory<ObjectID>,
    name: impl AsRef<OsStr>,
    content: LeafContent<ObjectID>,
) {
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

fn simple(fs: &mut FileSystem<Sha256HashValue>) {
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
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    simple(&mut fs);
    insta::assert_snapshot!(debug_fs(fs));
}

/// Test nested directory structure to establish baseline for V1_1 format.
///
/// This test creates a multi-level directory structure with files at various depths
/// to verify the BFS inode ordering is correctly captured in snapshots. The ordering
/// matches C mkcomposefs for bit-for-bit compatibility in V1_0 format, and this
/// same ordering is used for V1_1 format for consistency.
fn nested(fs: &mut FileSystem<Sha256HashValue>) {
    let ext_id = Sha256HashValue::from_hex(
        "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
    )
    .unwrap();

    // Create /a/b/c/deep-file
    let mut dir_c = Directory::new(default_stat());
    add_leaf(
        &mut dir_c,
        "deep-file",
        LeafContent::Regular(RegularFile::Inline((*b"deep content").into())),
    );

    let mut dir_b = Directory::new(default_stat());
    dir_b.insert(OsStr::new("c"), Inode::Directory(Box::new(dir_c)));
    add_leaf(
        &mut dir_b,
        "mid-file",
        LeafContent::Regular(RegularFile::Inline((*b"mid content").into())),
    );

    let mut dir_a = Directory::new(default_stat());
    dir_a.insert(OsStr::new("b"), Inode::Directory(Box::new(dir_b)));
    add_leaf(
        &mut dir_a,
        "shallow-file",
        LeafContent::Regular(RegularFile::External(ext_id.clone(), 4096)),
    );

    fs.root
        .insert(OsStr::new("a"), Inode::Directory(Box::new(dir_a)));

    // Create /x/y/z-file to test BFS ordering across sibling directories
    let mut dir_y = Directory::new(default_stat());
    add_leaf(
        &mut dir_y,
        "z-file",
        LeafContent::Regular(RegularFile::Inline((*b"xyz").into())),
    );

    let mut dir_x = Directory::new(default_stat());
    dir_x.insert(OsStr::new("y"), Inode::Directory(Box::new(dir_y)));

    fs.root
        .insert(OsStr::new("x"), Inode::Directory(Box::new(dir_x)));

    // Add a file at root level too
    add_leaf(
        &mut fs.root,
        "root-file",
        LeafContent::Regular(RegularFile::Inline((*b"root").into())),
    );
}

/// Snapshot test for nested directory structure.
///
/// This establishes the baseline for V1_1 format with subdirectories.
/// The inode ordering follows BFS (breadth-first search) to match C mkcomposefs,
/// which processes all nodes at depth N before any nodes at depth N+1.
#[test]
fn test_nested() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    nested(&mut fs);
    insta::assert_snapshot!(debug_fs(fs));
}

fn foreach_case(f: fn(&FileSystem<Sha256HashValue>)) {
    for case in [empty, simple, nested] {
        let mut fs = FileSystem::new(default_stat());
        case(&mut fs);
        f(&fs);
    }
}

#[test_with::executable(fsck.erofs)]
fn test_fsck() {
    foreach_case(|fs| {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&mkfs_erofs_default(fs)).unwrap();
        let mut fsck = Command::new("fsck.erofs").arg(tmp.path()).spawn().unwrap();
        assert!(fsck.wait().unwrap().success());
    });
}

fn dump_image(img: &[u8]) -> String {
    let mut dump = vec![];
    debug_img(&mut dump, img).unwrap();
    String::from_utf8(dump).unwrap()
}

/// Get the path to mkcomposefs binary.
/// Uses MKCOMPOSEFS_PATH env var if set, otherwise looks for "mkcomposefs" in PATH.
fn mkcomposefs_path() -> std::path::PathBuf {
    std::env::var("MKCOMPOSEFS_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("mkcomposefs"))
}

#[test_with::executable(mkcomposefs)]
fn test_vs_mkcomposefs() {
    let mkcomposefs_cmd = mkcomposefs_path();

    // Build two separate filesystems for each test case to avoid Rc clone issues.
    // When FileSystem is cloned, Rc<Leaf> strong_count increments, which would
    // incorrectly affect nlink calculations in the writer.
    for case in [empty, simple, nested] {
        // Build filesystem for Rust mkfs
        let mut fs_rust = FileSystem::new(default_stat());
        case(&mut fs_rust);

        // Build separate filesystem for C mkcomposefs (to preserve Rc counts)
        let mut fs_c = FileSystem::new(default_stat());
        case(&mut fs_c);

        // Use Format 1.0 for Rust to match C mkcomposefs --min-version=0
        // This includes whiteout table and overlay.opaque transformations
        let image = mkfs_erofs_v1_0(fs_rust);

        let mut mkcomposefs = Command::new(&mkcomposefs_cmd)
            .args(["--min-version=0", "--from-file", "-", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        let mut stdin = mkcomposefs.stdin.take().unwrap();
        write_dumpfile(&mut stdin, &fs_c).unwrap();
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
    }
}

// ============================================================================
// Format version difference tests (V1_0 vs V1_1)
// ============================================================================

/// Helper to get the composefs header from raw image bytes.
fn get_composefs_header(image: &[u8]) -> &ComposefsHeader {
    ComposefsHeader::ref_from_prefix(image)
        .expect("header err")
        .0
}

/// Helper to collect xattr (name, value) pairs from a reader inode.
fn collect_inode_xattrs(img: &Image, inode: &InodeType<'_>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut xattrs = Vec::new();
    if let Some(inode_xattrs) = inode.xattrs() {
        for id in inode_xattrs.shared() {
            let xattr = img.shared_xattr(id.get());
            let prefix_idx = xattr.header.name_index as usize;
            let prefix: &[u8] = if prefix_idx < XATTR_PREFIXES.len() {
                XATTR_PREFIXES[prefix_idx]
            } else {
                b""
            };
            let mut full_name = prefix.to_vec();
            full_name.extend_from_slice(xattr.suffix());
            xattrs.push((full_name, xattr.value().to_vec()));
        }
        for xattr in inode_xattrs.local() {
            let prefix_idx = xattr.header.name_index as usize;
            let prefix: &[u8] = if prefix_idx < XATTR_PREFIXES.len() {
                XATTR_PREFIXES[prefix_idx]
            } else {
                b""
            };
            let mut full_name = prefix.to_vec();
            full_name.extend_from_slice(xattr.suffix());
            xattrs.push((full_name, xattr.value().to_vec()));
        }
    }
    xattrs
}

#[test]
fn test_format_version_composefs_header() {
    let fs = FileSystem::<Sha256HashValue>::new(default_stat());

    let image_v10 = mkfs_erofs(&fs, FormatVersion::V1_0);
    let image_v11 = mkfs_erofs(&fs, FormatVersion::V1_1);

    let header_v10 = get_composefs_header(&image_v10);
    let header_v11 = get_composefs_header(&image_v11);

    assert_eq!(
        header_v10.composefs_version, COMPOSEFS_VERSION_V1_0,
        "V1_0 should have composefs_version=0"
    );
    assert_eq!(
        header_v11.composefs_version, COMPOSEFS_VERSION_V1_1,
        "V1_1 should have composefs_version=2"
    );
    // Both should share the same magic
    assert_eq!(header_v10.magic, header_v11.magic);
}

#[test]
fn test_format_version_build_time() {
    // V1_0: build_time should be the minimum mtime across all inodes
    // V1_1: build_time should be 0
    let mut fs = FileSystem::<Sha256HashValue>::new(Stat {
        st_mode: 0o755,
        st_uid: 0,
        st_gid: 0,
        st_mtim_sec: 100,
        xattrs: RefCell::new(BTreeMap::new()),
    });
    add_leaf(
        &mut fs.root,
        "file1",
        LeafContent::Regular(RegularFile::Inline((*b"hello").into())),
    );

    let image_v11 = mkfs_erofs(&fs, FormatVersion::V1_1);
    let img_v11 = Image::open(&image_v11);
    assert_eq!(
        img_v11.sb.build_time.get(),
        0,
        "V1_1 build_time should be 0"
    );

    // For V1_0 we need a fresh filesystem (Rc counts)
    let mut fs2 = FileSystem::<Sha256HashValue>::new(Stat {
        st_mode: 0o755,
        st_uid: 0,
        st_gid: 0,
        st_mtim_sec: 100,
        xattrs: RefCell::new(BTreeMap::new()),
    });
    add_leaf(
        &mut fs2.root,
        "file1",
        LeafContent::Regular(RegularFile::Inline((*b"hello").into())),
    );
    fs2.add_overlay_whiteouts();
    let image_v10 = mkfs_erofs(&fs2, FormatVersion::V1_0);
    let img_v10 = Image::open(&image_v10);

    // build_time is the minimum mtime. Root has mtime=100, file has mtime=0.
    // The file's stat has st_mtim_sec=0 (from default_stat in add_leaf),
    // so min mtime across all inodes should be 0.
    assert_eq!(
        img_v10.sb.build_time.get(),
        0,
        "V1_0 build_time should be minimum mtime (0 here)"
    );
}

#[test]
fn test_format_version_build_time_nonzero_min() {
    // When all inodes have mtime >= 500, V1_0 build_time should be 500.
    let stat_500 = Stat {
        st_mode: 0o644,
        st_uid: 0,
        st_gid: 0,
        st_mtim_sec: 500,
        xattrs: RefCell::new(BTreeMap::new()),
    };
    let mut fs = FileSystem::<Sha256HashValue>::new(Stat {
        st_mode: 0o755,
        st_uid: 0,
        st_gid: 0,
        st_mtim_sec: 1000,
        xattrs: RefCell::new(BTreeMap::new()),
    });
    fs.root.insert(
        OsStr::new("file"),
        Inode::Leaf(Rc::new(Leaf {
            content: LeafContent::Regular(RegularFile::Inline((*b"x").into())),
            stat: stat_500,
        })),
    );
    fs.add_overlay_whiteouts();
    let image = mkfs_erofs(&fs, FormatVersion::V1_0);
    let img = Image::open(&image);
    assert_eq!(
        img.sb.build_time.get(),
        500,
        "V1_0 build_time should be minimum mtime across all inodes (500)"
    );
}

#[test]
fn test_format_v1_0_compact_inodes() {
    // V1_0 should use compact inodes when conditions are met:
    // mtime matches min_mtime, uid/gid fit in u16, size fits in u32.
    let stat = Stat {
        st_mode: 0o755,
        st_uid: 0,
        st_gid: 0,
        st_mtim_sec: 0,
        xattrs: RefCell::new(BTreeMap::new()),
    };
    let mut fs = FileSystem::<Sha256HashValue>::new(stat);
    add_leaf(
        &mut fs.root,
        "compact_file",
        LeafContent::Regular(RegularFile::Inline((*b"compact").into())),
    );
    fs.add_overlay_whiteouts();
    let image = mkfs_erofs(&fs, FormatVersion::V1_0);
    let img = Image::open(&image);

    let root = img.root();
    assert!(
        matches!(root, InodeType::Compact(_)),
        "V1_0 root with mtime=0, uid/gid=0 should use compact inode"
    );
}

#[test]
fn test_format_v1_1_always_extended_inodes() {
    // V1_1 should always use extended inodes (never compact).
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    add_leaf(
        &mut fs.root,
        "extended_file",
        LeafContent::Regular(RegularFile::Inline((*b"extended").into())),
    );
    let image = mkfs_erofs(&fs, FormatVersion::V1_1);
    let img = Image::open(&image);

    let root = img.root();
    assert!(
        matches!(root, InodeType::Extended(_)),
        "V1_1 should always use extended inodes"
    );
}

#[test]
fn test_format_v1_0_overlay_opaque_on_root() {
    // V1_0 should add trusted.overlay.opaque=y xattr on the root inode.
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    add_leaf(
        &mut fs.root,
        "file",
        LeafContent::Regular(RegularFile::Inline((*b"data").into())),
    );
    fs.add_overlay_whiteouts();
    let image = mkfs_erofs(&fs, FormatVersion::V1_0);
    let img = Image::open(&image);

    let root = img.root();
    let xattrs = collect_inode_xattrs(&img, &root);
    let has_opaque = xattrs
        .iter()
        .any(|(k, v)| k == b"trusted.overlay.opaque" && v == b"y");
    assert!(
        has_opaque,
        "V1_0 root should have trusted.overlay.opaque=y, got xattrs: {:?}",
        xattrs
            .iter()
            .map(|(k, v)| (String::from_utf8_lossy(k).to_string(), v.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_format_v1_1_no_overlay_opaque_on_root() {
    // V1_1 should NOT have trusted.overlay.opaque xattr on root.
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    add_leaf(
        &mut fs.root,
        "file",
        LeafContent::Regular(RegularFile::Inline((*b"data").into())),
    );
    let image = mkfs_erofs(&fs, FormatVersion::V1_1);
    let img = Image::open(&image);

    let root = img.root();
    let xattrs = collect_inode_xattrs(&img, &root);
    let has_opaque = xattrs.iter().any(|(k, _)| k == b"trusted.overlay.opaque");
    assert!(
        !has_opaque,
        "V1_1 root should NOT have trusted.overlay.opaque xattr"
    );
}

#[test]
fn test_format_v1_0_extended_when_uid_too_large() {
    // Even in V1_0, inodes with uid > u16::MAX should use extended format.
    let stat = Stat {
        st_mode: 0o644,
        st_uid: 70000, // Doesn't fit in u16
        st_gid: 0,
        st_mtim_sec: 0,
        xattrs: RefCell::new(BTreeMap::new()),
    };
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    fs.root.insert(
        OsStr::new("biguid"),
        Inode::Leaf(Rc::new(Leaf {
            content: LeafContent::Regular(RegularFile::Inline((*b"x").into())),
            stat,
        })),
    );
    fs.add_overlay_whiteouts();
    let image = mkfs_erofs(&fs, FormatVersion::V1_0);
    let img = Image::open(&image);

    // Find the file's inode through the root directory
    let root = img.root();
    if let Some(inline) = root.inline() {
        if let Ok(block) = composefs::erofs::reader::DirectoryBlock::ref_from_bytes(inline) {
            for entry in block.entries() {
                if entry.name == b"biguid" {
                    let inode = img.inode(entry.header.inode_offset.get());
                    assert!(
                        matches!(inode, InodeType::Extended(_)),
                        "V1_0 inode with uid=70000 should use extended format"
                    );
                    assert_eq!(inode.uid(), 70000);
                }
            }
        }
    }
}

// ============================================================================
// Full roundtrip: fs -> image -> dump -> parse -> image -> byte-for-byte match
// ============================================================================

#[test]
fn test_dump_parse_regenerate_bytewise_match() {
    // For each test case, generate image, dump it, parse back, regenerate, verify match.
    // Note: `simple` is excluded because it contains a socket, which the dumpfile
    // parser doesn't support (sockets can't be serialized in the dump format).
    for case in [empty, nested] {
        let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
        case(&mut fs);

        // Step 1: Generate EROFS image (V1_1)
        let image1 = mkfs_erofs(&fs, FormatVersion::V1_1);

        // Step 2: Dump the image to dumpfile format
        let mut dump_buf = Vec::new();
        dump_erofs(&mut dump_buf, &image1, &[]).unwrap();
        let dump_str = String::from_utf8(dump_buf).unwrap();

        // Step 3: Parse the dumpfile back into a filesystem
        let fs2 = dumpfile_to_filesystem::<Sha256HashValue>(&dump_str).unwrap();

        // Step 4: Regenerate the image
        let image2 = mkfs_erofs(&fs2, FormatVersion::V1_1);

        // Step 5: Verify byte-for-byte match
        if image1 != image2 {
            let dump1 = dump_image(&image1);
            let dump2 = dump_image(&image2);
            similar_asserts::assert_eq!(dump1, dump2, "Debug dumps differ for roundtrip");
        }
        assert_eq!(
            image1, image2,
            "Image bytes differ after dump→parse→regenerate roundtrip"
        );
    }
}

#[test]
fn test_v1_0_v1_1_produce_different_images() {
    // V1_0 and V1_1 should produce structurally different images due to:
    // - Different composefs_version header
    // - Different inode formats (compact vs extended)
    // - overlay.opaque xattr on root in V1_0
    let mut fs1 = FileSystem::<Sha256HashValue>::new(default_stat());
    simple(&mut fs1);

    let mut fs2 = FileSystem::<Sha256HashValue>::new(default_stat());
    simple(&mut fs2);
    fs2.add_overlay_whiteouts();

    let image_v11 = mkfs_erofs(&fs1, FormatVersion::V1_1);
    let image_v10 = mkfs_erofs(&fs2, FormatVersion::V1_0);

    assert_ne!(
        image_v10, image_v11,
        "V1_0 and V1_1 should produce different images"
    );
}

#[test]
fn test_deterministic_output_v1_0() {
    // Same filesystem produced twice with V1_0 should be identical.
    for _ in 0..2 {
        let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
        simple(&mut fs);
        fs.add_overlay_whiteouts();
        let img1 = mkfs_erofs(&fs, FormatVersion::V1_0);

        let mut fs2 = FileSystem::<Sha256HashValue>::new(default_stat());
        simple(&mut fs2);
        fs2.add_overlay_whiteouts();
        let img2 = mkfs_erofs(&fs2, FormatVersion::V1_0);

        assert_eq!(img1, img2, "V1_0 should be deterministic");
    }
}

#[test]
fn test_deterministic_output_v1_1() {
    // Same filesystem produced twice with V1_1 should be identical.
    let mut fs1 = FileSystem::<Sha256HashValue>::new(default_stat());
    simple(&mut fs1);
    let img1 = mkfs_erofs(&fs1, FormatVersion::V1_1);

    let mut fs2 = FileSystem::<Sha256HashValue>::new(default_stat());
    simple(&mut fs2);
    let img2 = mkfs_erofs(&fs2, FormatVersion::V1_1);

    assert_eq!(img1, img2, "V1_1 should be deterministic");
}
