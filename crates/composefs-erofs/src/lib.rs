//! EROFS (Enhanced Read-Only File System) format support for composefs.
//!
//! This crate provides functionality to read and write EROFS filesystem images,
//! which are used as the underlying storage format for composefs images.

#![forbid(unsafe_code)]
// Several on-disk format structs intentionally omit Debug derives on the struct
// definition; their Debug impls live in the debug module instead.
#![allow(missing_debug_implementations)]

pub mod composefs;
mod debug;
pub mod format;
