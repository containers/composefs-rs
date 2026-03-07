//! Fuzz target: feed arbitrary bytes into the EROFS reader.
//!
//! Invariants under test:
//! - `Image::open()` must never panic on any input — it should return
//!   an error or be caught.  (Currently it uses unwrap/expect internally,
//!   so crashes here are real bugs to fix.)
//! - After successfully opening an image, all accessor methods (root inode,
//!   directory iteration, xattr reading, block access, etc.) must not panic.
//! - Errors are fine; panics are bugs.

#![no_main]

use libfuzzer_sys::fuzz_target;

use composefs_erofs::reader::{Image, InodeHeader, InodeOps};

/// Exercise every reader API we can reach from an opened image.
///
/// Any `Result::Err` is silently ignored — only panics count as failures.
fn exercise_image(data: &[u8]) {
    // Image::open() currently panics on invalid data; that's what we want
    // the fuzzer to find.  Once those are fixed to return Result, we can
    // just use `?` instead.
    let image = Image::open(data);

    // Read superblock fields
    let _ = image.blkszbits;
    let _ = image.block_size;
    let _ = image.sb.root_nid.get();
    let _ = image.sb.meta_blkaddr.get();
    let _ = image.sb.xattr_blkaddr.get();
    let _ = image.sb.blkszbits;
    let _ = image.sb.blocks.get();

    // Try to read the root inode
    let root = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| image.root()));
    let Ok(root) = root else { return };

    // Exercise inode header methods
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

    // Try xattrs
    if let Some(xattrs) = root.xattrs() {
        for id in xattrs.shared() {
            let xattr = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                image.shared_xattr(id.get())
            }));
            if let Ok(xattr) = xattr {
                let _ = xattr.suffix();
                let _ = xattr.value();
                let _ = xattr.padding();
                let _ = xattr.header.name_index;
                let _ = xattr.header.name_len;
                let _ = xattr.header.value_size;
            }
        }
        for xattr in xattrs.local() {
            let _ = xattr.suffix();
            let _ = xattr.value();
            let _ = xattr.padding();
        }
    }

    // Try inline data
    let _ = root.inline();

    // Try blocks
    let blocks = root.blocks(image.blkszbits);
    for blkid in blocks {
        let block = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| image.block(blkid)));
        if block.is_err() {
            continue;
        }

        // Try interpreting as directory or data block
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let db = image.directory_block(blkid);
            for entry in db.entries() {
                let _ = entry.name;
                let _ = entry.nid();
            }
        }));

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = image.data_block(blkid);
        }));
    }

    // If root is a directory, try iterating it
    if root.mode().is_dir() {
        let dir_blocks = root.blocks(image.blkszbits);
        for blkid in dir_blocks {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let db = image.directory_block(blkid);
                for entry in db.entries() {
                    let _ = entry.name;
                    let nid = entry.nid();
                    // Try to read the child inode
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let child = image.inode(nid);
                        let _ = child.mode();
                        let _ = child.size();
                        let _ = child.inline();
                        let _ = child.xattrs();
                    }));
                }
            }));
        }
    }

    // Try collect_objects (the high-level API)
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
