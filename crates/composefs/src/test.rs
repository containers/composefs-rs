//! Test utilities for composefs.
//!
//! This module provides helpers for writing tests, including temporary
//! directory allocation and repository initialization.

use std::{ffi::OsString, fs::create_dir_all, path::PathBuf, sync::Arc};

use once_cell::sync::Lazy;
use rustix::fs::CWD;
use tempfile::TempDir;

use crate::{fsverity::FsVerityHashValue, repository::Repository};

static TMPDIR: Lazy<OsString> = Lazy::new(|| {
    if let Some(path) = std::env::var_os("CFS_TEST_TMPDIR") {
        eprintln!("temporary directory from $CFS_TEST_TMPDIR: {path:?}");
        path
    } else {
        // We can't use /tmp because that's usually a tmpfs (no fsverity)
        // We also can't use /var/tmp because it's an overlayfs in toolbox (no fsverity)
        // So let's try something in the user's homedir?
        let home = std::env::var("HOME").expect("$HOME must be set when running tests");
        let tmp = PathBuf::from(home).join(".var/tmp");
        create_dir_all(&tmp).expect("can't create ~/.var/tmp");
        eprintln!("temporary directory from ~/.var/tmp: {tmp:?}");
        tmp.into()
    }
});

/// Allocate a temporary directory.
///
/// This creates a temporary directory in a location that supports fs-verity
/// when possible (avoiding tmpfs and overlayfs).
pub fn tempdir() -> TempDir {
    TempDir::with_prefix_in("composefs-test-", TMPDIR.as_os_str()).unwrap()
}

#[cfg(test)]
pub(crate) fn tempfile() -> std::fs::File {
    tempfile::tempfile_in(TMPDIR.as_os_str()).unwrap()
}

/// A test repository with its backing temporary directory.
///
/// The repository is configured in insecure mode so tests can run on
/// filesystems that don't support fs-verity. The temporary directory
/// is cleaned up when this struct is dropped.
#[derive(Debug)]
pub struct TestRepo<ObjectID: FsVerityHashValue> {
    /// The repository, wrapped in Arc for sharing.
    pub repo: Arc<Repository<ObjectID>>,
    /// The backing temporary directory (kept alive for the repo's lifetime).
    _tempdir: TempDir,
}

impl<ObjectID: FsVerityHashValue> TestRepo<ObjectID> {
    /// Create a new test repository in insecure mode.
    ///
    /// The repository is created in a temporary directory and configured
    /// to work without fs-verity support.
    pub fn new() -> Self {
        let dir = tempdir();
        let mut repo = Repository::open_path(CWD, dir.path()).unwrap();
        repo.set_insecure(true);
        Self {
            repo: Arc::new(repo),
            _tempdir: dir,
        }
    }
}

impl<ObjectID: FsVerityHashValue> Default for TestRepo<ObjectID> {
    fn default() -> Self {
        Self::new()
    }
}
