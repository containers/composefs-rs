//! Rust bindings and utilities for working with composefs images and repositories.
//!
//! Composefs is a read-only FUSE filesystem that enables efficient sharing
//! of container filesystem layers by using content-addressable storage
//! and fs-verity for integrity verification.

#![forbid(unsafe_code)]

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

/// Internal constants shared across workspace crates.
///
/// Not part of the public API — may change without notice.
#[doc(hidden)]
pub mod shared_internals {
    /// Default I/O buffer capacity for BufWriter/BufReader in streaming paths.
    ///
    /// The stdlib default of 8 KiB is suboptimal for large file I/O.
    /// 64 KiB provides significantly better throughput.
    /// See <https://github.com/bootc-dev/ocidir-rs/pull/63>.
    pub const IO_BUF_CAPACITY: usize = 64 * 1024;
}
