//! Round-trip tests verifying dump→mkfs→dump reproducibility.
//!
//! These tests verify that filesystem structures can be written to an EROFS
//! image and read back with equivalent content. This is similar to the C
//! composefs `test-checksums.sh` which tests the full pipeline.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    rc::Rc,
};

use composefs::{
    dumpfile::dumpfile_to_filesystem,
    erofs::{
        dump::dump_erofs,
        format::{self, FormatVersion, XATTR_PREFIXES},
        reader::{DirectoryBlock, Image, InodeHeader, InodeOps, InodeType},
        writer::mkfs_erofs,
    },
    fsverity::{FsVerityHashValue, Sha256HashValue},
    tree::{Directory, FileSystem, Inode, Leaf, LeafContent, RegularFile, Stat},
};
use zerocopy::FromBytes;

type SetupFn = fn(&mut FileSystem<Sha256HashValue>);

/// Helper to create a default Stat
fn default_stat() -> Stat {
    Stat {
        st_mode: 0o755,
        st_uid: 0,
        st_gid: 0,
        st_mtim_sec: 0,
        xattrs: RefCell::new(BTreeMap::new()),
    }
}

/// Helper to add a leaf inode
fn add_leaf(
    dir: &mut Directory<Sha256HashValue>,
    name: &OsStr,
    content: LeafContent<Sha256HashValue>,
) {
    dir.insert(
        name,
        Inode::Leaf(Rc::new(Leaf {
            content,
            stat: default_stat(),
        })),
    );
}

/// Helper to add a leaf with custom stat
fn add_leaf_with_stat(
    dir: &mut Directory<Sha256HashValue>,
    name: &OsStr,
    content: LeafContent<Sha256HashValue>,
    stat: Stat,
) {
    dir.insert(name, Inode::Leaf(Rc::new(Leaf { content, stat })));
}

/// Helper to add an empty subdirectory
fn add_subdir(dir: &mut Directory<Sha256HashValue>, name: &OsStr) {
    dir.insert(
        name,
        Inode::Directory(Box::new(Directory::new(default_stat()))),
    );
}

fn mkfs_erofs_default(fs: &FileSystem<Sha256HashValue>) -> Box<[u8]> {
    mkfs_erofs(fs, FormatVersion::default())
}

// ============================================================================
// Filesystem reconstruction from EROFS image
// ============================================================================

/// Reconstructed entry from reading an EROFS image
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReconstructedEntry {
    name: OsString,
    is_dir: bool,
    mode_permissions: u16, // Just the permission bits (lower 12 bits)
    size: u64,
    inline_data: Option<Vec<u8>>,
    xattrs: Vec<(String, Vec<u8>)>, // (full name, value)
}

/// Gets the inode number from a directory entry header
fn entry_nid(entry: &composefs::erofs::reader::DirectoryEntry<'_>) -> u64 {
    entry.header.inode_offset.get()
}

/// Collects directory entries from an EROFS image starting at the given inode
fn collect_entries(img: &Image, nid: u64) -> Vec<ReconstructedEntry> {
    let inode = img.inode(nid).unwrap();
    let mut entries = Vec::new();

    // Collect from inline directory data
    if let Some(inline) = inode.inline() {
        if inode.mode().is_dir() {
            if let Ok(inline_block) = DirectoryBlock::ref_from_bytes(inline) {
                for entry in inline_block.entries() {
                    let entry = entry.unwrap();

                    if entry.name != b"." && entry.name != b".." {
                        entries.push(reconstruct_entry(img, entry.name, entry_nid(&entry)));
                    }
                }
            }
        }
    }

    // Collect from directory blocks
    for blkid in inode.blocks(img.blkszbits).unwrap() {
        let block = img.directory_block(blkid).unwrap();
        for entry in block.entries() {
            let entry = entry.unwrap();

            if entry.name != b"." && entry.name != b".." {
                entries.push(reconstruct_entry(img, entry.name, entry_nid(&entry)));
            }
        }
    }

    // Sort by name for consistent comparison
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

/// Reconstructs an entry from an inode
fn reconstruct_entry(img: &Image, name: &[u8], nid: u64) -> ReconstructedEntry {
    let inode = img.inode(nid).unwrap();
    let mode = inode.mode().0.get();
    let is_dir = inode.mode().is_dir();
    let size = inode.size();

    // Get inline data for non-directories
    let inline_data = if !is_dir {
        inode.inline().map(|d| d.to_vec())
    } else {
        None
    };

    // Collect xattrs
    let mut xattrs = Vec::new();
    if let Some(inode_xattrs) = inode.xattrs().unwrap() {
        // Shared xattrs
        for id in inode_xattrs.shared().unwrap() {
            let xattr = img.shared_xattr(id.get()).unwrap();
            let prefix_idx = xattr.header.name_index as usize;
            let prefix: &[u8] = if prefix_idx < XATTR_PREFIXES.len() {
                XATTR_PREFIXES[prefix_idx]
            } else {
                b""
            };
            let full_name = format!(
                "{}{}",
                String::from_utf8_lossy(prefix),
                String::from_utf8_lossy(xattr.suffix())
            );
            xattrs.push((full_name, xattr.value().to_vec()));
        }

        // Local xattrs
        for xattr in inode_xattrs.local() {
            let xattr = xattr.unwrap();
            let prefix_idx = xattr.header.name_index as usize;
            let prefix: &[u8] = if prefix_idx < XATTR_PREFIXES.len() {
                XATTR_PREFIXES[prefix_idx]
            } else {
                b""
            };
            let full_name = format!(
                "{}{}",
                String::from_utf8_lossy(prefix),
                String::from_utf8_lossy(xattr.suffix())
            );
            xattrs.push((full_name, xattr.value().to_vec()));
        }
    }
    xattrs.sort_by(|a, b| a.0.cmp(&b.0));

    ReconstructedEntry {
        name: OsStr::from_bytes(name).to_os_string(),
        is_dir,
        mode_permissions: mode & 0o7777,
        size,
        inline_data,
        xattrs,
    }
}

/// Verifies that an entry exists in the image with expected properties
fn verify_entry_exists<'a>(
    entries: &'a [ReconstructedEntry],
    name: &str,
) -> &'a ReconstructedEntry {
    entries
        .iter()
        .find(|e| e.name == OsStr::new(name))
        .unwrap_or_else(|| panic!("Entry '{}' not found in image", name))
}

// ============================================================================
// Test cases
// ============================================================================

/// Test case definition for data-driven testing
struct RoundtripTestCase {
    name: &'static str,
    setup: fn(&mut FileSystem<Sha256HashValue>),
    verify: fn(&Image, &[ReconstructedEntry]),
}

/// Empty filesystem test
fn setup_empty(_fs: &mut FileSystem<Sha256HashValue>) {
    // Nothing to add - empty filesystem
}

fn verify_empty(_img: &Image, entries: &[ReconstructedEntry]) {
    assert!(
        entries.is_empty(),
        "Empty filesystem should have no entries"
    );
}

/// Simple inline file test
fn setup_simple_inline_file(fs: &mut FileSystem<Sha256HashValue>) {
    add_leaf(
        &mut fs.root,
        OsStr::new("hello.txt"),
        LeafContent::Regular(RegularFile::Inline(b"Hello, World!".to_vec().into())),
    );
}

fn verify_simple_inline_file(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let entry = verify_entry_exists(entries, "hello.txt");
    assert!(!entry.is_dir);
    assert_eq!(entry.size, 13);
    assert_eq!(entry.inline_data, Some(b"Hello, World!".to_vec()));
}

/// Multiple files test
fn setup_multiple_files(fs: &mut FileSystem<Sha256HashValue>) {
    add_leaf(
        &mut fs.root,
        OsStr::new("file1.txt"),
        LeafContent::Regular(RegularFile::Inline(b"content1".to_vec().into())),
    );
    add_leaf(
        &mut fs.root,
        OsStr::new("file2.txt"),
        LeafContent::Regular(RegularFile::Inline(b"content2".to_vec().into())),
    );
    add_leaf(
        &mut fs.root,
        OsStr::new("file3.txt"),
        LeafContent::Regular(RegularFile::Inline(b"content3".to_vec().into())),
    );
}

fn verify_multiple_files(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 3);
    let e1 = verify_entry_exists(entries, "file1.txt");
    assert_eq!(e1.inline_data, Some(b"content1".to_vec()));
    let e2 = verify_entry_exists(entries, "file2.txt");
    assert_eq!(e2.inline_data, Some(b"content2".to_vec()));
    let e3 = verify_entry_exists(entries, "file3.txt");
    assert_eq!(e3.inline_data, Some(b"content3".to_vec()));
}

/// Directory with entries test
fn setup_directory_with_entries(fs: &mut FileSystem<Sha256HashValue>) {
    add_subdir(&mut fs.root, OsStr::new("subdir"));
    let subdir = fs.root.get_directory_mut(OsStr::new("subdir")).unwrap();
    subdir.insert(
        OsStr::new("nested.txt"),
        Inode::Leaf(Rc::new(Leaf {
            content: LeafContent::Regular(RegularFile::Inline(b"nested content".to_vec().into())),
            stat: default_stat(),
        })),
    );
}

fn verify_directory_with_entries(img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let subdir_entry = verify_entry_exists(entries, "subdir");
    assert!(subdir_entry.is_dir);

    // Find the subdir's nid and verify its contents
    let root_nid = img.sb.root_nid.get() as u64;
    let root_inode = img.inode(root_nid).unwrap();

    let mut subdir_nid = None;
    if let Some(inline) = root_inode.inline() {
        if let Ok(block) = DirectoryBlock::ref_from_bytes(inline) {
            for entry in block.entries() {
                let entry = entry.unwrap();
                if entry.name == b"subdir" {
                    subdir_nid = Some(entry_nid(&entry));
                }
            }
        }
    }

    let subdir_nid = subdir_nid.expect("subdir not found");
    let subdir_entries = collect_entries(img, subdir_nid);
    assert_eq!(subdir_entries.len(), 1);
    let nested = verify_entry_exists(&subdir_entries, "nested.txt");
    assert_eq!(nested.inline_data, Some(b"nested content".to_vec()));
}

/// Symlink test
fn setup_symlink(fs: &mut FileSystem<Sha256HashValue>) {
    add_leaf(
        &mut fs.root,
        OsStr::new("link"),
        LeafContent::Symlink(Box::from(OsStr::new("/target/path"))),
    );
}

fn verify_symlink(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let entry = verify_entry_exists(entries, "link");
    assert!(!entry.is_dir);
    // Symlink target is stored as inline data
    assert_eq!(entry.inline_data, Some(b"/target/path".to_vec()));
}

/// FIFO test
fn setup_fifo(fs: &mut FileSystem<Sha256HashValue>) {
    add_leaf(&mut fs.root, OsStr::new("myfifo"), LeafContent::Fifo);
}

fn verify_fifo(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let entry = verify_entry_exists(entries, "myfifo");
    assert!(!entry.is_dir);
    assert_eq!(entry.size, 0);
}

/// Device files test
fn setup_devices(fs: &mut FileSystem<Sha256HashValue>) {
    add_leaf(
        &mut fs.root,
        OsStr::new("chardev"),
        LeafContent::CharacterDevice(0x0501), // major=5, minor=1 (like /dev/console)
    );
    add_leaf(
        &mut fs.root,
        OsStr::new("blockdev"),
        LeafContent::BlockDevice(0x0801), // major=8, minor=1 (like /dev/sda1)
    );
}

fn verify_devices(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 2);
    let _ = verify_entry_exists(entries, "chardev");
    let _ = verify_entry_exists(entries, "blockdev");
}

/// External file (with fsverity hash) test
fn setup_external_file(fs: &mut FileSystem<Sha256HashValue>) {
    let hash = Sha256HashValue::from_hex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .unwrap();
    add_leaf(
        &mut fs.root,
        OsStr::new("external"),
        LeafContent::Regular(RegularFile::External(hash, 4096)),
    );
}

fn verify_external_file(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let entry = verify_entry_exists(entries, "external");
    assert!(!entry.is_dir);
    assert_eq!(entry.size, 4096);
    // External files have xattrs for overlay.metacopy and overlay.redirect
    assert!(
        entry
            .xattrs
            .iter()
            .any(|(k, _): &(String, Vec<u8>)| k.contains("metacopy")),
        "External file should have metacopy xattr"
    );
}

/// File with xattrs test
fn setup_file_with_xattrs(fs: &mut FileSystem<Sha256HashValue>) {
    let mut xattrs = BTreeMap::new();
    xattrs.insert(
        Box::from(OsStr::new("user.custom")),
        Box::from(b"custom_value".as_slice()),
    );
    xattrs.insert(
        Box::from(OsStr::new("security.selinux")),
        Box::from(b"system_u:object_r:user_t:s0".as_slice()),
    );

    let stat = Stat {
        st_mode: 0o644,
        st_uid: 1000,
        st_gid: 1000,
        st_mtim_sec: 1234567890,
        xattrs: RefCell::new(xattrs),
    };

    add_leaf_with_stat(
        &mut fs.root,
        OsStr::new("with_xattrs"),
        LeafContent::Regular(RegularFile::Inline(b"data".to_vec().into())),
        stat,
    );
}

fn verify_file_with_xattrs(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let entry = verify_entry_exists(entries, "with_xattrs");
    assert!(!entry.is_dir);
    assert_eq!(entry.mode_permissions, 0o644);

    // Verify xattrs are present
    assert!(
        entry
            .xattrs
            .iter()
            .any(|(k, v)| k == "user.custom" && v == b"custom_value"),
        "Should have user.custom xattr"
    );
    assert!(
        entry.xattrs.iter().any(|(k, _)| k == "security.selinux"),
        "Should have security.selinux xattr"
    );
}

/// Hardlinks test
fn setup_hardlinks(fs: &mut FileSystem<Sha256HashValue>) {
    let shared_leaf = Rc::new(Leaf {
        content: LeafContent::Regular(RegularFile::Inline(b"shared content".to_vec().into())),
        stat: default_stat(),
    });

    fs.root
        .insert(OsStr::new("file1"), Inode::Leaf(Rc::clone(&shared_leaf)));
    fs.root
        .insert(OsStr::new("file2"), Inode::Leaf(Rc::clone(&shared_leaf)));
    fs.root
        .insert(OsStr::new("file3"), Inode::Leaf(shared_leaf));
}

fn verify_hardlinks(img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 3);

    // All three should have the same content
    let e1 = verify_entry_exists(entries, "file1");
    let e2 = verify_entry_exists(entries, "file2");
    let e3 = verify_entry_exists(entries, "file3");

    assert_eq!(e1.inline_data, Some(b"shared content".to_vec()));
    assert_eq!(e2.inline_data, Some(b"shared content".to_vec()));
    assert_eq!(e3.inline_data, Some(b"shared content".to_vec()));

    // Verify they point to the same inode in the image
    let root_nid = img.sb.root_nid.get() as u64;
    let root_inode = img.inode(root_nid).unwrap();

    let mut nids = Vec::new();
    if let Some(inline) = root_inode.inline() {
        if let Ok(block) = DirectoryBlock::ref_from_bytes(inline) {
            for entry in block.entries() {
                let entry = entry.unwrap();
                if entry.name == b"file1" || entry.name == b"file2" || entry.name == b"file3" {
                    nids.push(entry_nid(&entry));
                }
            }
        }
    }
    for blkid in root_inode.blocks(img.blkszbits).unwrap() {
        let block = img.directory_block(blkid).unwrap();
        for entry in block.entries() {
            let entry = entry.unwrap();
            if entry.name == b"file1" || entry.name == b"file2" || entry.name == b"file3" {
                nids.push(entry_nid(&entry));
            }
        }
    }

    // All hardlinks should point to the same nid
    assert_eq!(nids.len(), 3);
    assert!(
        nids.iter().all(|&n| n == nids[0]),
        "Hardlinks should point to same inode"
    );
}

/// Deep nested directories test
fn setup_deep_nesting(fs: &mut FileSystem<Sha256HashValue>) {
    add_subdir(&mut fs.root, OsStr::new("a"));
    let a = fs.root.get_directory_mut(OsStr::new("a")).unwrap();
    a.insert(
        OsStr::new("b"),
        Inode::Directory(Box::new(Directory::new(default_stat()))),
    );
    let b = a.get_directory_mut(OsStr::new("b")).unwrap();
    b.insert(
        OsStr::new("c"),
        Inode::Directory(Box::new(Directory::new(default_stat()))),
    );
    let c = b.get_directory_mut(OsStr::new("c")).unwrap();
    c.insert(
        OsStr::new("deepfile.txt"),
        Inode::Leaf(Rc::new(Leaf {
            content: LeafContent::Regular(RegularFile::Inline(b"deep content".to_vec().into())),
            stat: default_stat(),
        })),
    );
}

fn verify_deep_nesting(img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let a = verify_entry_exists(entries, "a");
    assert!(a.is_dir);

    // Navigate through the nested structure
    let root_nid = img.sb.root_nid.get() as u64;

    // Helper to find a directory entry by name
    let find_entry_nid = |parent_nid: u64, name: &[u8]| -> Option<u64> {
        let inode = img.inode(parent_nid).unwrap();
        if let Some(inline) = inode.inline() {
            if let Ok(block) = DirectoryBlock::ref_from_bytes(inline) {
                for entry in block.entries() {
                    let entry = entry.unwrap();
                    if entry.name == name {
                        return Some(entry_nid(&entry));
                    }
                }
            }
        }
        for blkid in inode.blocks(img.blkszbits).unwrap() {
            let block = img.directory_block(blkid).unwrap();
            for entry in block.entries() {
                let entry = entry.unwrap();
                if entry.name == name {
                    return Some(entry_nid(&entry));
                }
            }
        }
        None
    };

    let a_nid = find_entry_nid(root_nid, b"a").expect("a not found");
    let b_nid = find_entry_nid(a_nid, b"b").expect("b not found");
    let c_nid = find_entry_nid(b_nid, b"c").expect("c not found");
    let c_entries = collect_entries(img, c_nid);
    assert_eq!(c_entries.len(), 1);
    let deepfile = verify_entry_exists(&c_entries, "deepfile.txt");
    assert_eq!(deepfile.inline_data, Some(b"deep content".to_vec()));
}

/// Large directory (many entries) test
fn setup_large_directory(fs: &mut FileSystem<Sha256HashValue>) {
    // Add enough entries to span multiple directory blocks
    for i in 0..100 {
        let name = format!("file{:03}", i);
        add_leaf(
            &mut fs.root,
            OsStr::new(&name),
            LeafContent::Regular(RegularFile::Inline(
                format!("content{}", i).into_bytes().into(),
            )),
        );
    }
}

fn verify_large_directory(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 100);
    for i in 0..100 {
        let name = format!("file{:03}", i);
        let entry = verify_entry_exists(entries, &name);
        assert!(!entry.is_dir);
        assert_eq!(
            entry.inline_data,
            Some(format!("content{}", i).into_bytes())
        );
    }
}

/// Empty file test
fn setup_empty_file(fs: &mut FileSystem<Sha256HashValue>) {
    add_leaf(
        &mut fs.root,
        OsStr::new("empty"),
        LeafContent::Regular(RegularFile::Inline(Box::new([]))),
    );
}

fn verify_empty_file(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let entry = verify_entry_exists(entries, "empty");
    assert!(!entry.is_dir);
    assert_eq!(entry.size, 0);
    // Empty inline files may have None or Some([]) for inline_data
}

/// Mixed content test
fn setup_mixed_content(fs: &mut FileSystem<Sha256HashValue>) {
    // Regular inline file
    add_leaf(
        &mut fs.root,
        OsStr::new("inline.txt"),
        LeafContent::Regular(RegularFile::Inline(b"inline".to_vec().into())),
    );

    // Symlink
    add_leaf(
        &mut fs.root,
        OsStr::new("link"),
        LeafContent::Symlink(Box::from(OsStr::new("target"))),
    );

    // FIFO
    add_leaf(&mut fs.root, OsStr::new("fifo"), LeafContent::Fifo);

    // Subdirectory with content
    add_subdir(&mut fs.root, OsStr::new("subdir"));
    let subdir = fs.root.get_directory_mut(OsStr::new("subdir")).unwrap();
    subdir.insert(
        OsStr::new("nested"),
        Inode::Leaf(Rc::new(Leaf {
            content: LeafContent::Regular(RegularFile::Inline(b"nested".to_vec().into())),
            stat: default_stat(),
        })),
    );
}

fn verify_mixed_content(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 4);
    let _ = verify_entry_exists(entries, "inline.txt");
    let _ = verify_entry_exists(entries, "link");
    let _ = verify_entry_exists(entries, "fifo");
    let subdir = verify_entry_exists(entries, "subdir");
    assert!(subdir.is_dir);
}

// ============================================================================
// Test runner
// ============================================================================

const TEST_CASES: &[RoundtripTestCase] = &[
    RoundtripTestCase {
        name: "empty",
        setup: setup_empty,
        verify: verify_empty,
    },
    RoundtripTestCase {
        name: "simple_inline_file",
        setup: setup_simple_inline_file,
        verify: verify_simple_inline_file,
    },
    RoundtripTestCase {
        name: "multiple_files",
        setup: setup_multiple_files,
        verify: verify_multiple_files,
    },
    RoundtripTestCase {
        name: "directory_with_entries",
        setup: setup_directory_with_entries,
        verify: verify_directory_with_entries,
    },
    RoundtripTestCase {
        name: "symlink",
        setup: setup_symlink,
        verify: verify_symlink,
    },
    RoundtripTestCase {
        name: "fifo",
        setup: setup_fifo,
        verify: verify_fifo,
    },
    RoundtripTestCase {
        name: "devices",
        setup: setup_devices,
        verify: verify_devices,
    },
    RoundtripTestCase {
        name: "external_file",
        setup: setup_external_file,
        verify: verify_external_file,
    },
    RoundtripTestCase {
        name: "file_with_xattrs",
        setup: setup_file_with_xattrs,
        verify: verify_file_with_xattrs,
    },
    RoundtripTestCase {
        name: "hardlinks",
        setup: setup_hardlinks,
        verify: verify_hardlinks,
    },
    RoundtripTestCase {
        name: "deep_nesting",
        setup: setup_deep_nesting,
        verify: verify_deep_nesting,
    },
    RoundtripTestCase {
        name: "large_directory",
        setup: setup_large_directory,
        verify: verify_large_directory,
    },
    RoundtripTestCase {
        name: "empty_file",
        setup: setup_empty_file,
        verify: verify_empty_file,
    },
    RoundtripTestCase {
        name: "mixed_content",
        setup: setup_mixed_content,
        verify: verify_mixed_content,
    },
];

/// Runs all data-driven test cases
#[test]
fn test_roundtrip_all_cases() {
    for case in TEST_CASES {
        println!("Running test case: {}", case.name);

        // Setup filesystem
        let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
        (case.setup)(&mut fs);

        // Generate EROFS image
        let image = mkfs_erofs_default(&fs);

        // Open and read the image
        let img = Image::open(&image).unwrap();

        // Collect root entries
        let root_nid = img.sb.root_nid.get() as u64;
        let entries = collect_entries(&img, root_nid);

        // Run verification
        (case.verify)(&img, &entries);

        println!("  PASSED: {}", case.name);
    }
}

// ============================================================================
// Individual test functions for better error reporting
// ============================================================================

#[test]
fn test_roundtrip_empty() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_empty(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_empty(&img, &entries);
}

#[test]
fn test_roundtrip_simple_inline_file() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_simple_inline_file(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_simple_inline_file(&img, &entries);
}

#[test]
fn test_roundtrip_multiple_files() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_multiple_files(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_multiple_files(&img, &entries);
}

#[test]
fn test_roundtrip_directory_with_entries() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_directory_with_entries(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_directory_with_entries(&img, &entries);
}

#[test]
fn test_roundtrip_symlink() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_symlink(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_symlink(&img, &entries);
}

#[test]
fn test_roundtrip_fifo() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_fifo(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_fifo(&img, &entries);
}

#[test]
fn test_roundtrip_devices() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_devices(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_devices(&img, &entries);
}

#[test]
fn test_roundtrip_external_file() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_external_file(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_external_file(&img, &entries);
}

#[test]
fn test_roundtrip_file_with_xattrs() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_file_with_xattrs(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_file_with_xattrs(&img, &entries);
}

#[test]
fn test_roundtrip_hardlinks() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_hardlinks(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_hardlinks(&img, &entries);
}

#[test]
fn test_roundtrip_deep_nesting() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_deep_nesting(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_deep_nesting(&img, &entries);
}

#[test]
fn test_roundtrip_large_directory() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_large_directory(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_large_directory(&img, &entries);
}

#[test]
fn test_roundtrip_empty_file() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_empty_file(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_empty_file(&img, &entries);
}

#[test]
fn test_roundtrip_mixed_content() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_mixed_content(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_mixed_content(&img, &entries);
}

// ============================================================================
// Dumpfile roundtrip tests (dump -> parse -> mkfs -> read)
// ============================================================================

/// Tests that a dumpfile can be parsed, converted to mkfs, and read back
#[test]
fn test_dumpfile_roundtrip_simple() {
    let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/file.txt 5 100644 1 0 0 0 1000.0 - hello -
/subdir 4096 40755 2 0 0 0 1000.0 - - -
/subdir/nested.txt 6 100644 1 0 0 0 1000.0 - world! -
"#;

    let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();

    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);

    assert_eq!(entries.len(), 2);
    let file = verify_entry_exists(&entries, "file.txt");
    assert_eq!(file.inline_data, Some(b"hello".to_vec()));

    let subdir = verify_entry_exists(&entries, "subdir");
    assert!(subdir.is_dir);
}

/// Tests dumpfile roundtrip with various file types
#[test]
fn test_dumpfile_roundtrip_file_types() {
    let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/regular 10 100644 1 0 0 0 1000.0 - content123 -
/symlink 7 120777 1 0 0 0 1000.0 /target - -
/fifo 0 10644 1 0 0 0 1000.0 - - -
/chardev 0 20644 1 0 0 1281 1000.0 - - -
/blockdev 0 60644 1 0 0 2049 1000.0 - - -
"#;

    let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();

    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);

    assert_eq!(entries.len(), 5);
    verify_entry_exists(&entries, "regular");
    verify_entry_exists(&entries, "symlink");
    verify_entry_exists(&entries, "fifo");
    verify_entry_exists(&entries, "chardev");
    verify_entry_exists(&entries, "blockdev");
}

/// Tests dumpfile roundtrip with hardlinks
#[test]
fn test_dumpfile_roundtrip_hardlinks() {
    let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/original 11 100644 3 0 0 0 1000.0 - hello_world -
/link1 0 @120000 3 0 0 0 0.0 /original - -
/link2 0 @120000 3 0 0 0 0.0 /original - -
"#;

    let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();

    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);

    assert_eq!(entries.len(), 3);

    // All three should have the same content
    let original = verify_entry_exists(&entries, "original");
    let link1 = verify_entry_exists(&entries, "link1");
    let link2 = verify_entry_exists(&entries, "link2");

    assert_eq!(original.inline_data, Some(b"hello_world".to_vec()));
    assert_eq!(link1.inline_data, Some(b"hello_world".to_vec()));
    assert_eq!(link2.inline_data, Some(b"hello_world".to_vec()));
}

/// Tests dumpfile roundtrip with xattrs
#[test]
fn test_dumpfile_roundtrip_xattrs() {
    let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/with_xattr 4 100644 1 0 0 0 1000.0 - test - user.custom=value123
"#;

    let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();

    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);

    assert_eq!(entries.len(), 1);
    let entry = verify_entry_exists(&entries, "with_xattr");

    // Verify xattr is present
    assert!(
        entry
            .xattrs
            .iter()
            .any(|(k, v)| k == "user.custom" && v == b"value123"),
        "Should have user.custom xattr with value 'value123', got: {:?}",
        entry.xattrs
    );
}

// ============================================================================
// Image consistency tests
// ============================================================================

/// Verifies that writing the same filesystem twice produces identical images
#[test]
fn test_deterministic_output() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    add_leaf(
        &mut fs.root,
        OsStr::new("file1"),
        LeafContent::Regular(RegularFile::Inline(b"content1".to_vec().into())),
    );
    add_leaf(
        &mut fs.root,
        OsStr::new("file2"),
        LeafContent::Regular(RegularFile::Inline(b"content2".to_vec().into())),
    );
    add_subdir(&mut fs.root, OsStr::new("dir"));

    let image1 = mkfs_erofs_default(&fs);

    // Build the same filesystem again
    let mut fs2 = FileSystem::<Sha256HashValue>::new(default_stat());
    add_leaf(
        &mut fs2.root,
        OsStr::new("file1"),
        LeafContent::Regular(RegularFile::Inline(b"content1".to_vec().into())),
    );
    add_leaf(
        &mut fs2.root,
        OsStr::new("file2"),
        LeafContent::Regular(RegularFile::Inline(b"content2".to_vec().into())),
    );
    add_subdir(&mut fs2.root, OsStr::new("dir"));

    let image2 = mkfs_erofs_default(&fs2);

    assert_eq!(
        image1, image2,
        "Same filesystem should produce identical images"
    );
}

/// Tests that the image can be opened and basic metadata is correct
#[test]
fn test_image_metadata() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    add_leaf(
        &mut fs.root,
        OsStr::new("test"),
        LeafContent::Regular(RegularFile::Inline(b"test".to_vec().into())),
    );

    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();

    // Verify basic image properties
    assert_eq!(img.sb.magic.get(), format::MAGIC_V1.get());
    assert_eq!(img.blkszbits, format::BLOCK_BITS);
    assert_eq!(img.block_size, format::BLOCK_SIZE as usize);

    // Verify root inode is a directory
    let root = img.root().unwrap();
    assert!(root.mode().is_dir());
}

// ============================================================================
// Format version roundtrip tests
// ============================================================================

/// Verify that V1_0 images can be generated, opened, and read without panics.
///
/// V1_0 adds overlay whiteout entries to the root directory, so entry counts differ
/// from V1_1. Instead of reusing the V1_1 verify functions, we just verify the
/// images are structurally valid and the root is readable.
#[test]
fn test_roundtrip_all_cases_v1_0() {
    let setups: &[(&str, SetupFn)] = &[
        ("empty", setup_empty),
        ("simple_inline_file", setup_simple_inline_file),
        ("multiple_files", setup_multiple_files),
        ("directory_with_entries", setup_directory_with_entries),
        ("symlink", setup_symlink),
        ("fifo", setup_fifo),
        ("devices", setup_devices),
        ("external_file", setup_external_file),
        ("deep_nesting", setup_deep_nesting),
        ("empty_file", setup_empty_file),
        ("mixed_content", setup_mixed_content),
    ];

    for (name, setup) in setups {
        println!("Running V1_0 test case: {name}");
        let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
        setup(&mut fs);
        fs.add_overlay_whiteouts();
        let image = mkfs_erofs(&fs, FormatVersion::V1_0);
        let img = Image::open(&image).unwrap();

        // Verify basic structure
        let root = img.root().unwrap();
        assert!(root.mode().is_dir(), "V1_0 root should be a directory");

        // Verify root entries can be read
        let root_nid = img.sb.root_nid.get() as u64;
        let entries = collect_entries(&img, root_nid);
        println!("  V1_0 root has {} entries, PASSED: {name}", entries.len());
    }
}

/// Verify that V1_0 images use compact inodes where possible.
#[test]
fn test_v1_0_uses_compact_root() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_simple_inline_file(&mut fs);
    fs.add_overlay_whiteouts();

    let image = mkfs_erofs(&fs, FormatVersion::V1_0);
    let img = Image::open(&image).unwrap();
    let root = img.root().unwrap();

    // With all mtimes=0, uid/gid=0, the root should be a compact inode in V1_0.
    assert!(
        matches!(root, InodeType::Compact(_)),
        "V1_0 root with mtime=0, uid/gid=0 should use compact inode"
    );
}

/// Verify that V1_1 images always use extended inodes.
#[test]
fn test_v1_1_uses_extended_root() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_simple_inline_file(&mut fs);

    let image = mkfs_erofs(&fs, FormatVersion::V1_1);
    let img = Image::open(&image).unwrap();
    let root = img.root().unwrap();

    assert!(
        matches!(root, InodeType::Extended(_)),
        "V1_1 should always use extended inodes"
    );
}

// ============================================================================
// Xattr edge cases
// ============================================================================

/// Test file with empty xattr value
fn setup_xattr_empty_value(fs: &mut FileSystem<Sha256HashValue>) {
    let mut xattrs = BTreeMap::new();
    xattrs.insert(
        Box::from(OsStr::new("user.emptyval")),
        Box::from(b"".as_slice()),
    );
    let stat = Stat {
        st_mode: 0o644,
        st_uid: 0,
        st_gid: 0,
        st_mtim_sec: 0,
        xattrs: RefCell::new(xattrs),
    };
    add_leaf_with_stat(
        &mut fs.root,
        OsStr::new("empty_xattr_val"),
        LeafContent::Regular(RegularFile::Inline(b"data".to_vec().into())),
        stat,
    );
}

fn verify_xattr_empty_value(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let entry = verify_entry_exists(entries, "empty_xattr_val");
    // Verify the xattr with empty value is present
    assert!(
        entry
            .xattrs
            .iter()
            .any(|(k, v)| k == "user.emptyval" && v.is_empty()),
        "Should have user.emptyval xattr with empty value, got: {:?}",
        entry.xattrs
    );
}

/// Test file with large xattr value (close to the 64KB limit)
fn setup_xattr_large_value(fs: &mut FileSystem<Sha256HashValue>) {
    let mut xattrs = BTreeMap::new();
    // Use a moderately large value (4KB) - not too close to the 64KB limit
    // to avoid cross-block-boundary complications.
    let large_value: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    xattrs.insert(
        Box::from(OsStr::new("user.largeval")),
        large_value.into_boxed_slice(),
    );
    let stat = Stat {
        st_mode: 0o644,
        st_uid: 0,
        st_gid: 0,
        st_mtim_sec: 0,
        xattrs: RefCell::new(xattrs),
    };
    add_leaf_with_stat(
        &mut fs.root,
        OsStr::new("large_xattr"),
        LeafContent::Regular(RegularFile::Inline(b"x".to_vec().into())),
        stat,
    );
}

fn verify_xattr_large_value(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let entry = verify_entry_exists(entries, "large_xattr");
    let xattr = entry
        .xattrs
        .iter()
        .find(|(k, _)| k == "user.largeval")
        .expect("Should have user.largeval xattr");
    assert_eq!(
        xattr.1.len(),
        4096,
        "Large xattr value should be 4096 bytes"
    );
    // Verify the content pattern
    for (i, byte) in xattr.1.iter().enumerate() {
        assert_eq!(*byte, (i % 256) as u8, "Byte mismatch at position {i}");
    }
}

/// Test file with many xattrs
fn setup_xattr_many(fs: &mut FileSystem<Sha256HashValue>) {
    let mut xattrs = BTreeMap::new();
    for i in 0..20 {
        let key = format!("user.attr_{i:02}");
        let val = format!("value_{i:02}");
        xattrs.insert(
            Box::from(OsStr::new(&key)),
            val.into_bytes().into_boxed_slice(),
        );
    }
    let stat = Stat {
        st_mode: 0o644,
        st_uid: 0,
        st_gid: 0,
        st_mtim_sec: 0,
        xattrs: RefCell::new(xattrs),
    };
    add_leaf_with_stat(
        &mut fs.root,
        OsStr::new("many_xattrs"),
        LeafContent::Regular(RegularFile::Inline(b"data".to_vec().into())),
        stat,
    );
}

fn verify_xattr_many(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let entry = verify_entry_exists(entries, "many_xattrs");
    // Should have at least 20 xattrs (may also have overlay xattrs)
    assert!(
        entry.xattrs.len() >= 20,
        "Should have at least 20 xattrs, got {}",
        entry.xattrs.len()
    );
    for i in 0..20 {
        let key = format!("user.attr_{i:02}");
        let val = format!("value_{i:02}");
        assert!(
            entry
                .xattrs
                .iter()
                .any(|(k, v)| k == &key && v == val.as_bytes()),
            "Missing xattr {key}={val}"
        );
    }
}

#[test]
fn test_roundtrip_xattr_empty_value() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_xattr_empty_value(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_xattr_empty_value(&img, &entries);
}

#[test]
fn test_roundtrip_xattr_large_value() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_xattr_large_value(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_xattr_large_value(&img, &entries);
}

#[test]
fn test_roundtrip_xattr_many() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_xattr_many(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_xattr_many(&img, &entries);
}

// ============================================================================
// Hardlinks across directories
// ============================================================================

fn setup_hardlinks_across_dirs(fs: &mut FileSystem<Sha256HashValue>) {
    let shared_leaf = Rc::new(Leaf {
        content: LeafContent::Regular(RegularFile::Inline(b"shared across dirs".to_vec().into())),
        stat: default_stat(),
    });

    // Put the same leaf in root and in a subdirectory
    fs.root.insert(
        OsStr::new("root_link"),
        Inode::Leaf(Rc::clone(&shared_leaf)),
    );

    let mut subdir = Directory::new(default_stat());
    subdir.insert(OsStr::new("sub_link"), Inode::Leaf(Rc::clone(&shared_leaf)));
    fs.root
        .insert(OsStr::new("dir"), Inode::Directory(Box::new(subdir)));

    // And in a nested subdirectory
    let mut subdir2 = Directory::new(default_stat());
    subdir2.insert(OsStr::new("deep_link"), Inode::Leaf(shared_leaf));
    let dir2 = fs.root.get_directory_mut(OsStr::new("dir")).unwrap();
    dir2.insert(OsStr::new("nested"), Inode::Directory(Box::new(subdir2)));
}

fn verify_hardlinks_across_dirs(img: &Image, entries: &[ReconstructedEntry]) {
    // Root should have root_link and dir
    assert_eq!(entries.len(), 2);
    let root_link = verify_entry_exists(entries, "root_link");
    assert_eq!(root_link.inline_data, Some(b"shared across dirs".to_vec()));
    let dir = verify_entry_exists(entries, "dir");
    assert!(dir.is_dir);

    // Navigate into dir to find sub_link and nested/deep_link
    let root_nid = img.sb.root_nid.get() as u64;
    let find_child_nid = |parent_nid: u64, name: &[u8]| -> Option<u64> {
        let inode = img.inode(parent_nid).unwrap();
        if let Some(inline) = inode.inline() {
            if let Ok(block) = DirectoryBlock::ref_from_bytes(inline) {
                for entry in block.entries() {
                    let entry = entry.unwrap();
                    if entry.name == name {
                        return Some(entry.header.inode_offset.get());
                    }
                }
            }
        }
        for blkid in inode.blocks(img.blkszbits).unwrap() {
            let block = img.directory_block(blkid).unwrap();
            for entry in block.entries() {
                let entry = entry.unwrap();
                if entry.name == name {
                    return Some(entry.header.inode_offset.get());
                }
            }
        }
        None
    };

    let dir_nid = find_child_nid(root_nid, b"dir").expect("dir not found");
    let root_link_nid = find_child_nid(root_nid, b"root_link").expect("root_link not found");
    let sub_link_nid = find_child_nid(dir_nid, b"sub_link").expect("sub_link not found");
    let nested_nid = find_child_nid(dir_nid, b"nested").expect("nested not found");
    let deep_link_nid = find_child_nid(nested_nid, b"deep_link").expect("deep_link not found");

    // All three hardlinks should point to the same inode
    assert_eq!(
        root_link_nid, sub_link_nid,
        "root_link and sub_link should share inode"
    );
    assert_eq!(
        root_link_nid, deep_link_nid,
        "root_link and deep_link should share inode"
    );
}

#[test]
fn test_roundtrip_hardlinks_across_dirs() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_hardlinks_across_dirs(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_hardlinks_across_dirs(&img, &entries);
}

// ============================================================================
// Deeply nested paths
// ============================================================================

fn setup_deeply_nested(fs: &mut FileSystem<Sha256HashValue>) {
    // Create a 10-level deep path: /d0/d1/d2/.../d9/leaf.txt
    let mut current = &mut fs.root;
    for i in 0..10 {
        let name = format!("d{i}");
        current.insert(
            OsStr::new(&name),
            Inode::Directory(Box::new(Directory::new(default_stat()))),
        );
        current = current.get_directory_mut(OsStr::new(&name)).unwrap();
    }
    current.insert(
        OsStr::new("leaf.txt"),
        Inode::Leaf(Rc::new(Leaf {
            content: LeafContent::Regular(RegularFile::Inline(b"ten levels deep".to_vec().into())),
            stat: default_stat(),
        })),
    );
}

fn verify_deeply_nested(img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let d0 = verify_entry_exists(entries, "d0");
    assert!(d0.is_dir);

    // Navigate down to the leaf
    let find_child_nid = |parent_nid: u64, name: &[u8]| -> Option<u64> {
        let inode = img.inode(parent_nid).unwrap();
        if let Some(inline) = inode.inline() {
            if let Ok(block) = DirectoryBlock::ref_from_bytes(inline) {
                for entry in block.entries() {
                    let entry = entry.unwrap();
                    if entry.name == name {
                        return Some(entry.header.inode_offset.get());
                    }
                }
            }
        }
        for blkid in inode.blocks(img.blkszbits).unwrap() {
            let block = img.directory_block(blkid).unwrap();
            for entry in block.entries() {
                let entry = entry.unwrap();
                if entry.name == name {
                    return Some(entry.header.inode_offset.get());
                }
            }
        }
        None
    };

    let root_nid = img.sb.root_nid.get() as u64;
    let mut nid = root_nid;
    for i in 0..10 {
        let name = format!("d{i}");
        nid = find_child_nid(nid, name.as_bytes())
            .unwrap_or_else(|| panic!("Directory {name} not found at depth {i}"));
    }
    let leaf_nid = find_child_nid(nid, b"leaf.txt").expect("leaf.txt not found at depth 10");
    let leaf_inode = img.inode(leaf_nid).unwrap();
    let inline = leaf_inode.inline().expect("leaf should have inline data");
    assert_eq!(inline, b"ten levels deep");
}

#[test]
fn test_roundtrip_deeply_nested() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_deeply_nested(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_deeply_nested(&img, &entries);
}

// ============================================================================
// Maximum filename length (255 bytes)
// ============================================================================

fn setup_max_filename(fs: &mut FileSystem<Sha256HashValue>) {
    // POSIX maximum filename is 255 bytes
    let long_name: String = (0..255).map(|i| (b'a' + (i % 26) as u8) as char).collect();
    add_leaf(
        &mut fs.root,
        OsStr::new(&long_name),
        LeafContent::Regular(RegularFile::Inline(b"long name file".to_vec().into())),
    );
}

fn verify_max_filename(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 1);
    let long_name: String = (0..255).map(|i| (b'a' + (i % 26) as u8) as char).collect();
    let entry = verify_entry_exists(entries, &long_name);
    assert_eq!(entry.inline_data, Some(b"long name file".to_vec()));
    assert_eq!(entry.name.len(), 255);
}

#[test]
fn test_roundtrip_max_filename() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_max_filename(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_max_filename(&img, &entries);
}

// ============================================================================
// All file types in the same directory
// ============================================================================

fn setup_all_types(fs: &mut FileSystem<Sha256HashValue>) {
    let ext_hash = Sha256HashValue::from_hex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .unwrap();

    add_leaf(
        &mut fs.root,
        OsStr::new("inline_file"),
        LeafContent::Regular(RegularFile::Inline(b"inline content".to_vec().into())),
    );
    add_leaf(
        &mut fs.root,
        OsStr::new("external_file"),
        LeafContent::Regular(RegularFile::External(ext_hash, 8192)),
    );
    add_leaf(
        &mut fs.root,
        OsStr::new("symlink"),
        LeafContent::Symlink(Box::from(OsStr::new("/usr/bin/target"))),
    );
    add_leaf(&mut fs.root, OsStr::new("fifo"), LeafContent::Fifo);
    add_leaf(&mut fs.root, OsStr::new("socket"), LeafContent::Socket);
    add_leaf(
        &mut fs.root,
        OsStr::new("chardev"),
        LeafContent::CharacterDevice(0x0501),
    );
    add_leaf(
        &mut fs.root,
        OsStr::new("blockdev"),
        LeafContent::BlockDevice(0x0801),
    );
    add_leaf(
        &mut fs.root,
        OsStr::new("empty_file"),
        LeafContent::Regular(RegularFile::Inline(Box::new([]))),
    );

    // Also add a subdirectory
    add_subdir(&mut fs.root, OsStr::new("subdir"));
}

fn verify_all_types(_img: &Image, entries: &[ReconstructedEntry]) {
    assert_eq!(entries.len(), 9, "Should have 9 entries (8 files + 1 dir)");

    let inline = verify_entry_exists(entries, "inline_file");
    assert_eq!(inline.inline_data, Some(b"inline content".to_vec()));
    assert!(!inline.is_dir);

    let external = verify_entry_exists(entries, "external_file");
    assert_eq!(external.size, 8192);
    assert!(!external.is_dir);

    let sym = verify_entry_exists(entries, "symlink");
    assert_eq!(sym.inline_data, Some(b"/usr/bin/target".to_vec()));
    assert!(!sym.is_dir);

    let fifo_entry = verify_entry_exists(entries, "fifo");
    assert!(!fifo_entry.is_dir);
    assert_eq!(fifo_entry.size, 0);

    let socket_entry = verify_entry_exists(entries, "socket");
    assert!(!socket_entry.is_dir);
    assert_eq!(socket_entry.size, 0);

    let _ = verify_entry_exists(entries, "chardev");
    let _ = verify_entry_exists(entries, "blockdev");

    let empty = verify_entry_exists(entries, "empty_file");
    assert_eq!(empty.size, 0);

    let subdir = verify_entry_exists(entries, "subdir");
    assert!(subdir.is_dir);
}

#[test]
fn test_roundtrip_all_types() {
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    setup_all_types(&mut fs);
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();
    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    verify_all_types(&img, &entries);
}

// ============================================================================
// Dump→parse→mkfs→dump roundtrip consistency
// ============================================================================

/// Tests that dump→parse→mkfs→dump produces semantically identical output.
/// This is a stronger test than binary comparison because it tests the full pipeline.
#[test]
fn test_dumpfile_full_roundtrip_consistency() {
    // Build various filesystems, dump them, parse back, rebuild, dump again, compare.
    let setups: Vec<(&str, SetupFn)> = vec![
        ("empty", setup_empty),
        ("simple_inline_file", setup_simple_inline_file),
        ("multiple_files", setup_multiple_files),
        ("symlink", setup_symlink),
        ("fifo", setup_fifo),
        ("devices", setup_devices),
        ("external_file", setup_external_file),
        ("deep_nesting", setup_deep_nesting),
        // Note: setup_all_types is excluded because it includes a socket,
        // which the dumpfile parser doesn't support.
    ];

    for (name, setup) in setups {
        println!("Testing dump roundtrip: {name}");

        let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
        setup(&mut fs);

        // Generate image and dump it
        let image1 = mkfs_erofs_default(&fs);
        let mut dump1_buf = Vec::new();
        dump_erofs(&mut dump1_buf, &image1, &[]).unwrap();
        let dump1 = String::from_utf8(dump1_buf).unwrap();

        // Parse the dump back and regenerate
        let fs2 = dumpfile_to_filesystem::<Sha256HashValue>(&dump1).unwrap();
        let image2 = mkfs_erofs_default(&fs2);
        let mut dump2_buf = Vec::new();
        dump_erofs(&mut dump2_buf, &image2, &[]).unwrap();
        let dump2 = String::from_utf8(dump2_buf).unwrap();

        // The two dumps should be identical
        similar_asserts::assert_eq!(dump1, dump2, "Dump roundtrip failed for: {name}");
        println!("  PASSED: {name}");
    }
}

// ============================================================================
// Stat preservation tests
// ============================================================================

/// Tests that uid/gid/mode/mtime survive the roundtrip
#[test]
fn test_roundtrip_preserves_stat_fields() {
    let stat = Stat {
        st_mode: 0o4755, // setuid + rwxr-xr-x
        st_uid: 1000,
        st_gid: 2000,
        st_mtim_sec: 1700000000,
        xattrs: RefCell::new(BTreeMap::new()),
    };
    let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
    add_leaf_with_stat(
        &mut fs.root,
        OsStr::new("special_file"),
        LeafContent::Regular(RegularFile::Inline(b"data".to_vec().into())),
        stat,
    );

    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();

    let root_nid = img.sb.root_nid.get() as u64;
    let entries = collect_entries(&img, root_nid);
    let entry = verify_entry_exists(&entries, "special_file");

    // mode_permissions includes setuid bit
    assert_eq!(
        entry.mode_permissions, 0o4755,
        "Mode should preserve setuid bit"
    );

    // Also check uid/gid/mtime by inspecting the raw inode
    let find_child_nid = |parent_nid: u64, name: &[u8]| -> Option<u64> {
        let inode = img.inode(parent_nid).unwrap();
        if let Some(inline) = inode.inline() {
            if let Ok(block) = DirectoryBlock::ref_from_bytes(inline) {
                for entry in block.entries() {
                    let entry = entry.unwrap();
                    if entry.name == name {
                        return Some(entry.header.inode_offset.get());
                    }
                }
            }
        }
        for blkid in inode.blocks(img.blkszbits).unwrap() {
            let block = img.directory_block(blkid).unwrap();
            for entry in block.entries() {
                let entry = entry.unwrap();
                if entry.name == name {
                    return Some(entry.header.inode_offset.get());
                }
            }
        }
        None
    };
    let file_nid = find_child_nid(root_nid, b"special_file").unwrap();
    let file_inode = img.inode(file_nid).unwrap();
    assert_eq!(file_inode.uid(), 1000);
    assert_eq!(file_inode.gid(), 2000);
    assert_eq!(file_inode.mtime(), 1700000000);
}

/// Tests that the permissions-only bits (sticky, setgid, setuid) survive roundtrip
#[test]
fn test_roundtrip_special_mode_bits() {
    let test_modes = [
        (0o1755, "sticky"),
        (0o2755, "setgid"),
        (0o4755, "setuid"),
        (0o7777, "all special bits"),
        (0o0000, "no permissions"),
        (0o0644, "regular file perms"),
    ];

    for (mode, desc) in test_modes {
        let stat = Stat {
            st_mode: mode,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 0,
            xattrs: RefCell::new(BTreeMap::new()),
        };
        let mut fs = FileSystem::<Sha256HashValue>::new(default_stat());
        add_leaf_with_stat(
            &mut fs.root,
            OsStr::new("file"),
            LeafContent::Regular(RegularFile::Inline(b"x".to_vec().into())),
            stat,
        );

        let image = mkfs_erofs_default(&fs);
        let img = Image::open(&image).unwrap();
        let root_nid = img.sb.root_nid.get() as u64;
        let entries = collect_entries(&img, root_nid);
        let entry = verify_entry_exists(&entries, "file");

        assert_eq!(
            entry.mode_permissions, mode as u16,
            "Mode bits {desc} (0o{mode:o}) should survive roundtrip"
        );
    }
}
