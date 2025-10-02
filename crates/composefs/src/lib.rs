//! Rust bindings and utilities for working with composefs images and repositories.
//!
//! Composefs is a read-only FUSE filesystem that enables efficient sharing
//! of container filesystem layers by using content-addressable storage
//! and fs-verity for integrity verification.

pub mod dumpfile;
pub mod dumpfile_parse;
pub mod erofs;
pub mod filesystem_ops;
pub mod fs;
pub mod fsverity;
pub mod mount;
pub mod mountcompat;
pub mod repository;
pub mod splitstream;
pub mod tree;
pub mod util;

pub mod generic_tree;
#[cfg(any(test, feature = "test"))]
pub mod test;

/// All files that contain 64 or fewer bytes (size <= INLINE_CONTENT_MAX) should be stored inline
/// in the erofs image (and also in splitstreams).  All files with 65 or more bytes (size > MAX)
/// should be written to the object storage and referred to from the image (and splitstreams).
pub const INLINE_CONTENT_MAX: usize = 64;
