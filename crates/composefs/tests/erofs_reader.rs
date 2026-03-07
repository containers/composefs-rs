//! Tests for EROFS reader functionality.
//!
//! These tests exercise the reader code (now in composefs-erofs) using
//! the writer and dumpfile utilities from composefs.

use std::collections::HashMap;

use composefs::{
    dumpfile::dumpfile_to_filesystem,
    erofs::{
        reader::{collect_objects, DirectoryBlock, Image, InodeHeader, InodeOps},
        writer::mkfs_erofs_default,
    },
    fsverity::Sha256HashValue,
};
use zerocopy::FromBytes;

/// Helper to validate that directory entries can be read correctly
fn validate_directory_entries(img: &Image, nid: u64, expected_names: &[&str]) {
    let inode = img.inode(nid).unwrap();
    assert!(inode.mode().is_dir(), "Expected directory inode");

    let mut found_names = Vec::new();

    // Read inline entries if present
    if let Some(inline) = inode.inline() {
        let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
        for entry in inline_block.entries() {
            let entry = entry.unwrap();
            let name = std::str::from_utf8(entry.name).unwrap();
            found_names.push(name.to_string());
        }
    }

    // Read block entries
    for blkid in inode.blocks(img.blkszbits).unwrap() {
        let block = img.directory_block(blkid).unwrap();
        for entry in block.entries() {
            let entry = entry.unwrap();
            let name = std::str::from_utf8(entry.name).unwrap();
            found_names.push(name.to_string());
        }
    }

    // Sort for comparison (entries should include . and ..)
    found_names.sort();
    let mut expected_sorted: Vec<_> = expected_names.iter().map(|s| s.to_string()).collect();
    expected_sorted.sort();

    assert_eq!(
        found_names, expected_sorted,
        "Directory entries mismatch for nid {nid}"
    );
}

#[test]
fn test_empty_directory() {
    // Create filesystem with empty directory
    let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/empty_dir 4096 40755 2 0 0 0 1000.0 - - -
"#;

    let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();

    // Root should have . and .. and empty_dir
    let root_nid = img.sb.root_nid.get() as u64;
    validate_directory_entries(&img, root_nid, &[".", "..", "empty_dir"]);

    // Find empty_dir entry
    let root_inode = img.root().unwrap();
    let mut empty_dir_nid = None;
    if let Some(inline) = root_inode.inline() {
        let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
        for entry in inline_block.entries() {
            let entry = entry.unwrap();
            if entry.name == b"empty_dir" {
                empty_dir_nid = Some(entry.nid());
                break;
            }
        }
    }
    for blkid in root_inode.blocks(img.blkszbits).unwrap() {
        let block = img.directory_block(blkid).unwrap();
        for entry in block.entries() {
            let entry = entry.unwrap();
            if entry.name == b"empty_dir" {
                empty_dir_nid = Some(entry.nid());
                break;
            }
        }
    }

    let empty_dir_nid = empty_dir_nid.expect("empty_dir not found");
    validate_directory_entries(&img, empty_dir_nid, &[".", ".."]);
}

#[test]
fn test_directory_with_inline_entries() {
    // Create filesystem with directory that has a few entries (should be inline)
    let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/dir1 4096 40755 2 0 0 0 1000.0 - - -
/dir1/file1 5 100644 1 0 0 0 1000.0 - hello -
/dir1/file2 5 100644 1 0 0 0 1000.0 - world -
"#;

    let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();

    // Find dir1
    let root_inode = img.root().unwrap();
    let mut dir1_nid = None;
    if let Some(inline) = root_inode.inline() {
        let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
        for entry in inline_block.entries() {
            let entry = entry.unwrap();
            if entry.name == b"dir1" {
                dir1_nid = Some(entry.nid());
                break;
            }
        }
    }
    for blkid in root_inode.blocks(img.blkszbits).unwrap() {
        let block = img.directory_block(blkid).unwrap();
        for entry in block.entries() {
            let entry = entry.unwrap();
            if entry.name == b"dir1" {
                dir1_nid = Some(entry.nid());
                break;
            }
        }
    }

    let dir1_nid = dir1_nid.expect("dir1 not found");
    validate_directory_entries(&img, dir1_nid, &[".", "..", "file1", "file2"]);
}

#[test]
fn test_directory_with_many_entries() {
    // Create a directory with many entries to force block storage
    let mut dumpfile = String::from("/ 4096 40755 2 0 0 0 1000.0 - - -\n");
    dumpfile.push_str("/bigdir 4096 40755 2 0 0 0 1000.0 - - -\n");

    // Add many files to force directory blocks
    for i in 0..100 {
        dumpfile.push_str(&format!(
            "/bigdir/file{i:03} 5 100644 1 0 0 0 1000.0 - hello -\n"
        ));
    }

    let fs = dumpfile_to_filesystem::<Sha256HashValue>(&dumpfile).unwrap();
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();

    // Find bigdir
    let root_inode = img.root().unwrap();
    let mut bigdir_nid = None;
    if let Some(inline) = root_inode.inline() {
        let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
        for entry in inline_block.entries() {
            let entry = entry.unwrap();
            if entry.name == b"bigdir" {
                bigdir_nid = Some(entry.nid());
                break;
            }
        }
    }
    for blkid in root_inode.blocks(img.blkszbits).unwrap() {
        let block = img.directory_block(blkid).unwrap();
        for entry in block.entries() {
            let entry = entry.unwrap();
            if entry.name == b"bigdir" {
                bigdir_nid = Some(entry.nid());
                break;
            }
        }
    }

    let bigdir_nid = bigdir_nid.expect("bigdir not found");

    // Build expected names
    let mut expected: Vec<String> = vec![".".to_string(), "..".to_string()];
    for i in 0..100 {
        expected.push(format!("file{i:03}"));
    }
    let expected_refs: Vec<&str> = expected.iter().map(|s| s.as_str()).collect();

    validate_directory_entries(&img, bigdir_nid, &expected_refs);
}

#[test]
fn test_nested_directories() {
    // Test deeply nested directory structure
    let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/a 4096 40755 2 0 0 0 1000.0 - - -
/a/b 4096 40755 2 0 0 0 1000.0 - - -
/a/b/c 4096 40755 2 0 0 0 1000.0 - - -
/a/b/c/file.txt 5 100644 1 0 0 0 1000.0 - hello -
"#;

    let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();

    // Navigate through the structure
    let root_nid = img.sb.root_nid.get() as u64;
    validate_directory_entries(&img, root_nid, &[".", "..", "a"]);

    let a_nid = img
        .find_child_nid(root_nid, b"a")
        .unwrap()
        .expect("a not found");
    validate_directory_entries(&img, a_nid, &[".", "..", "b"]);

    let b_nid = img
        .find_child_nid(a_nid, b"b")
        .unwrap()
        .expect("b not found");
    validate_directory_entries(&img, b_nid, &[".", "..", "c"]);

    let c_nid = img
        .find_child_nid(b_nid, b"c")
        .unwrap()
        .expect("c not found");
    validate_directory_entries(&img, c_nid, &[".", "..", "file.txt"]);
}

#[test]
fn test_mixed_entry_types() {
    // Test directory with various file types
    let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/mixed 4096 40755 2 0 0 0 1000.0 - - -
/mixed/regular 10 100644 1 0 0 0 1000.0 - content123 -
/mixed/symlink 7 120777 1 0 0 0 1000.0 /target - -
/mixed/fifo 0 10644 1 0 0 0 1000.0 - - -
/mixed/subdir 4096 40755 2 0 0 0 1000.0 - - -
"#;

    let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();

    let root_inode = img.root().unwrap();
    let mut mixed_nid = None;
    if let Some(inline) = root_inode.inline() {
        let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
        for entry in inline_block.entries() {
            let entry = entry.unwrap();
            if entry.name == b"mixed" {
                mixed_nid = Some(entry.nid());
                break;
            }
        }
    }
    for blkid in root_inode.blocks(img.blkszbits).unwrap() {
        let block = img.directory_block(blkid).unwrap();
        for entry in block.entries() {
            let entry = entry.unwrap();
            if entry.name == b"mixed" {
                mixed_nid = Some(entry.nid());
                break;
            }
        }
    }

    let mixed_nid = mixed_nid.expect("mixed not found");
    validate_directory_entries(
        &img,
        mixed_nid,
        &[".", "..", "regular", "symlink", "fifo", "subdir"],
    );
}

#[test]
fn test_collect_objects_traversal() {
    // Test that object collection properly traverses all directories
    let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/dir1 4096 40755 2 0 0 0 1000.0 - - -
/dir1/file1 5 100644 1 0 0 0 1000.0 - hello -
/dir2 4096 40755 2 0 0 0 1000.0 - - -
/dir2/subdir 4096 40755 2 0 0 0 1000.0 - - -
/dir2/subdir/file2 5 100644 1 0 0 0 1000.0 - world -
"#;

    let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
    let image = mkfs_erofs_default(&fs);

    // This should traverse all directories without error
    let result = collect_objects::<Sha256HashValue>(&image, &[]);
    assert!(
        result.is_ok(),
        "Failed to collect objects: {:?}",
        result.err()
    );
}

#[test_with::executable(mkcomposefs)]
#[test]
fn test_pr188_empty_inline_directory() -> anyhow::Result<()> {
    // Regression test for https://github.com/containers/composefs-rs/pull/188
    //
    // The bug: ObjectCollector::visit_inode at lines 553-554 unconditionally does:
    //   let tail = DirectoryBlock::ref_from_bytes(inode.inline()).unwrap();
    //   self.visit_directory_block(tail);
    //
    // When inode.inline() is empty, DirectoryBlock::ref_from_bytes succeeds but then
    // visit_directory_block calls n_entries() which panics trying to read 12 bytes
    // from an empty slice.
    //
    // This test generates an erofs image using C mkcomposefs, which creates directories
    // with empty inline sections (unlike the Rust implementation which always includes
    // . and .. entries).

    // Generate a C-generated erofs image using mkcomposefs
    let dumpfile_content = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/empty_dir 4096 40755 2 0 0 0 1000.0 - - -
"#;

    // Create temporary files for dumpfile and erofs output
    let temp_dir = tempfile::TempDir::new()?;
    let temp_dir = temp_dir.path();
    let dumpfile_path = temp_dir.join("pr188_test.dump");
    let erofs_path = temp_dir.join("pr188_test.erofs");

    // Write dumpfile
    std::fs::write(&dumpfile_path, dumpfile_content).expect("Failed to write test dumpfile");

    // Run mkcomposefs to generate erofs image
    let output = std::process::Command::new("mkcomposefs")
        .arg("--from-file")
        .arg(&dumpfile_path)
        .arg(&erofs_path)
        .output()
        .expect("Failed to run mkcomposefs - is it installed?");

    assert!(
        output.status.success(),
        "mkcomposefs failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Read the generated erofs image
    let image = std::fs::read(&erofs_path).expect("Failed to read generated erofs");

    // The C mkcomposefs creates directories with empty inline sections.
    let r = collect_objects::<Sha256HashValue>(&image, &[]).unwrap();
    assert_eq!(r.len(), 0);

    Ok(())
}

#[test]
fn test_round_trip_basic() {
    // Full round-trip: dumpfile -> tree -> erofs -> read back -> validate
    let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/file1 5 100644 1 0 0 0 1000.0 - hello -
/file2 6 100644 1 0 0 0 1000.0 - world! -
/dir1 4096 40755 2 0 0 0 1000.0 - - -
/dir1/nested 8 100644 1 0 0 0 1000.0 - content1 -
"#;

    let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
    let image = mkfs_erofs_default(&fs);
    let img = Image::open(&image).unwrap();

    // Verify root entries
    let root_nid = img.sb.root_nid.get() as u64;
    validate_directory_entries(&img, root_nid, &[".", "..", "file1", "file2", "dir1"]);

    // Collect all entries and verify structure
    let mut entries_map: HashMap<Vec<u8>, u64> = HashMap::new();
    let root_inode = img.root().unwrap();

    if let Some(inline) = root_inode.inline() {
        let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
        for entry in inline_block.entries() {
            let entry = entry.unwrap();
            entries_map.insert(entry.name.to_vec(), entry.nid());
        }
    }

    for blkid in root_inode.blocks(img.blkszbits).unwrap() {
        let block = img.directory_block(blkid).unwrap();
        for entry in block.entries() {
            let entry = entry.unwrap();
            entries_map.insert(entry.name.to_vec(), entry.nid());
        }
    }

    // Verify we can read file contents
    let file1_nid = entries_map
        .get(b"file1".as_slice())
        .expect("file1 not found");
    let file1_inode = img.inode(*file1_nid).unwrap();
    assert!(!file1_inode.mode().is_dir());
    assert_eq!(file1_inode.size(), 5);

    let inline_data = file1_inode.inline();
    assert_eq!(inline_data, Some(b"hello".as_slice()));
}

#[test]
fn test_invalid_image_data() {
    // Image::open should return Err on garbage data, not panic
    assert!(Image::open(&[]).is_err());
    assert!(Image::open(&[0u8; 100]).is_err());

    // An all-zeros 1152-byte buffer is actually parseable (blkszbits=0 means
    // block_size=1), so just verify it doesn't panic
    let _ = Image::open(&[0u8; 1152]);

    // A buffer with blkszbits=255 should not panic with shift overflow
    let mut data = vec![0u8; 4096];
    // Put something at offset 1024 for the superblock, with blkszbits=255
    if data.len() > 1024 + 12 {
        data[1024 + 12] = 255; // blkszbits field
    }
    assert!(Image::open(&data).is_err());

    // blkszbits=64 should also fail (shift overflow)
    let mut data2 = vec![0u8; 4096];
    data2[1024 + 12] = 64;
    assert!(Image::open(&data2).is_err());
}
