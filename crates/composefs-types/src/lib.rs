//! Core types for composefs: hash values and constants.

#![forbid(unsafe_code)]

pub mod fsverity;

/// All files that contain 64 or fewer bytes (size <= INLINE_CONTENT_MAX) should be stored inline
/// in the erofs image (and also in splitstreams).  All files with 65 or more bytes (size > MAX)
/// should be written to the object storage and referred to from the image (and splitstreams).
pub const INLINE_CONTENT_MAX: usize = 64;
