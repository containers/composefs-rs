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

pub use composefs_types::INLINE_CONTENT_MAX;
