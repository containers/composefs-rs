//! Fuzz target: feed arbitrary bytes into the EROFS reader.
//!
//! Invariants under test:
//! - The reader must never panic on any input.
//! - All reader methods should return errors or handle gracefully on
//!   malformed data rather than panicking via unwrap/expect.
//! - Errors are fine; panics are bugs.

#![no_main]

use libfuzzer_sys::fuzz_target;

use composefs::erofs::reader::{Image, InodeHeader, InodeOps};

/// Exercise every reader API we can reach from an opened image.
///
/// Any panic here is a real bug — the fuzzer will capture it as a crash.
fn exercise_image(data: &[u8]) {
    let Ok(image) = Image::open(data) else {
        return;
    };

    // Read superblock fields
    let _ = image.blkszbits;
    let _ = image.block_size;
    let _ = image.sb.root_nid.get();
    let _ = image.sb.meta_blkaddr.get();
    let _ = image.sb.xattr_blkaddr.get();
    let _ = image.sb.blkszbits;
    let _ = image.sb.blocks.get();

    // Read root inode and exercise header methods
    let Ok(root) = image.root() else {
        return;
    };

    let _ = root.mode();
    let _ = root.size();
    let _ = root.u();
    let _ = root.nlink();
    let _ = root.xattr_icount();
    let _ = root.xattr_size();

    // Xattr iteration
    if let Ok(Some(xattrs)) = root.xattrs() {
        if let Ok(shared) = xattrs.shared() {
            for id in shared {
                if let Ok(xattr) = image.shared_xattr(id.get()) {
                    let _ = xattr.suffix();
                    let _ = xattr.value();
                    let _ = xattr.padding();
                    let _ = xattr.header.name_index;
                    let _ = xattr.header.name_len;
                    let _ = xattr.header.value_size;
                }
            }
        }
        if let Ok(local) = xattrs.local() {
            for xattr in local {
                if let Ok(xattr) = xattr {
                    let _ = xattr.suffix();
                    let _ = xattr.value();
                    let _ = xattr.padding();
                }
            }
        }
    }

    // Inline data
    let _ = root.inline();

    // Block iteration
    let Ok(blocks) = image.inode_blocks(&root) else {
        return;
    };
    for blkid in blocks {
        let _ = image.block(blkid);
        let _ = image.data_block(blkid);

        let Ok(db) = image.directory_block(blkid) else {
            continue;
        };
        let Ok(entries) = db.entries() else {
            continue;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                continue;
            };
            let _ = entry.name;
            let nid = entry.nid();

            // Read child inodes
            let Ok(child) = image.inode(nid) else {
                continue;
            };
            let _ = child.mode();
            let _ = child.size();
            let _ = child.inline();
            let _ = child.xattrs();
        }
    }

    // High-level API
    let _ = composefs::erofs::reader::collect_objects::<composefs::fsverity::Sha256HashValue>(data);

    // Round-trip through erofs_to_filesystem + write_dumpfile
    if let Ok(fs) =
        composefs::erofs::reader::erofs_to_filesystem::<composefs::fsverity::Sha256HashValue>(data)
    {
        let mut buf = Vec::new();
        let _ = composefs::dumpfile::write_dumpfile(&mut buf, &fs);
    }
}

fuzz_target!(|data: &[u8]| {
    exercise_image(data);
});
