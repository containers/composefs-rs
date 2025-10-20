//! High-level filesystem operations for composefs trees.
//!
//! This module provides convenience methods for common operations on
//! FileSystem objects, including computing image IDs, committing to
//! repositories, and generating dumpfiles.

use anyhow::Result;

use crate::{
    dumpfile::write_dumpfile,
    erofs::writer::mkfs_erofs,
    fsverity::{compute_verity, FsVerityHashValue},
    repository::Repository,
    tree::FileSystem,
};

impl<ObjectID: FsVerityHashValue> FileSystem<ObjectID> {
    /// Commits this filesystem as an EROFS image to the repository.
    ///
    /// Ensures the root directory stat is computed, generates an EROFS filesystem image,
    /// and writes it to the repository with the optional name. Returns the fsverity digest
    /// of the committed image.
    pub fn commit_image(
        &mut self,
        repository: &Repository<ObjectID>,
        image_name: Option<&str>,
    ) -> Result<ObjectID> {
        self.ensure_root_stat();
        repository.write_image(image_name, &mkfs_erofs(self))
    }

    /// Computes the fsverity digest for this filesystem as an EROFS image.
    ///
    /// Ensures the root directory stat is computed, generates the EROFS image,
    /// and returns its fsverity digest without writing to a repository.
    pub fn compute_image_id(&mut self) -> ObjectID {
        self.ensure_root_stat();
        compute_verity(&mkfs_erofs(self))
    }

    /// Prints this filesystem in dumpfile format to stdout.
    ///
    /// Ensures the root directory stat is computed and serializes the entire
    /// filesystem tree to stdout in composefs dumpfile text format.
    pub fn print_dumpfile(&mut self) -> Result<()> {
        self.ensure_root_stat();
        write_dumpfile(&mut std::io::stdout(), self)
    }
}
