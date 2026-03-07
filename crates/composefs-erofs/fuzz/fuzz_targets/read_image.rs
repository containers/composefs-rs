//! Fuzz target: feed arbitrary bytes into the EROFS reader.
//!
//! Invariants under test:
//! - The reader must never panic on any input.
//! - All reader methods should return errors or handle gracefully on
//!   malformed data rather than panicking via unwrap/expect.
//! - Errors are fine; panics are bugs.
//!
//! The EROFS reader currently has several unwrap() calls on untrusted
//! data. Each panic the fuzzer finds is a real bug that should be fixed
//! by converting the unwrap to proper error handling.

#![no_main]

use libfuzzer_sys::fuzz_target;

use composefs_erofs::reader::{Image, InodeHeader, InodeOps};

/// Exercise every reader API we can reach from an opened image.
///
/// Any panic here is a real bug — the fuzzer will capture it as a crash.
fn exercise_image(data: &[u8]) {
    let image = Image::open(data);

    // Read superblock fields
    let _ = image.blkszbits;
    let _ = image.block_size;
    let _ = image.sb.root_nid.get();
    let _ = image.sb.meta_blkaddr.get();
    let _ = image.sb.xattr_blkaddr.get();
    let _ = image.sb.blkszbits;
    let _ = image.sb.blocks.get();

    // Read root inode and exercise header methods
    let root = image.root();

    let _ = root.mode();
    let _ = root.size();
    let _ = root.uid();
    let _ = root.gid();
    let _ = root.nlink();
    let _ = root.mtime();
    let _ = root.mtime_nsec();
    let _ = root.u();
    let _ = root.xattr_icount();
    let _ = root.xattr_size();

    // Xattr iteration
    if let Some(xattrs) = root.xattrs() {
        for id in xattrs.shared() {
            let xattr = image.shared_xattr(id.get());
            let _ = xattr.suffix();
            let _ = xattr.value();
            let _ = xattr.padding();
            let _ = xattr.header.name_index;
            let _ = xattr.header.name_len;
            let _ = xattr.header.value_size;
        }
        for xattr in xattrs.local() {
            let _ = xattr.suffix();
            let _ = xattr.value();
            let _ = xattr.padding();
        }
    }

    // Inline data
    let _ = root.inline();

    // Block iteration
    let blocks = root.blocks(image.blkszbits);
    for blkid in blocks {
        let _ = image.block(blkid);
        let _ = image.data_block(blkid);

        let db = image.directory_block(blkid);
        for entry in db.entries() {
            let _ = entry.name;
            let nid = entry.nid();

            // Read child inodes
            let child = image.inode(nid);
            let _ = child.mode();
            let _ = child.size();
            let _ = child.inline();
            let _ = child.xattrs();
        }
    }

    // High-level API
    let _ = composefs_erofs::reader::collect_objects::<composefs_types::fsverity::Sha256HashValue>(
        data,
        &[],
    );
}

fuzz_target!(|data: &[u8]| {
    // The image needs at least enough bytes for the composefs header + superblock.
    // ComposefsHeader is 32 bytes, superblock starts at offset 1024 and is 128 bytes,
    // so we need at least 1152 bytes for any meaningful parsing.
    if data.len() < 1152 {
        return;
    }

    exercise_image(data);
});
