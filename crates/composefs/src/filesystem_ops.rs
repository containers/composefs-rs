//! High-level filesystem operations for composefs trees.
//!
//! This module provides convenience methods for common operations on
//! FileSystem objects, including computing image IDs, committing to
//! repositories, and generating dumpfiles.

use std::collections::HashMap;

use anyhow::Result;
use fn_error_context::context;

use crate::{
    dumpfile::write_dumpfile,
    erofs::{
        format::FormatVersion,
        writer::{mkfs_erofs_inner, validate_filesystem},
    },
    fsverity::{FsVerityHashValue, compute_verity},
    repository::Repository,
    tree::FileSystem,
};

impl<ObjectID: FsVerityHashValue> FileSystem<ObjectID> {
    /// Commits this filesystem as EROFS images for each format version in the repository config.
    ///
    /// Returns a map from [`FormatVersion`] to the fsverity digest of the
    /// stored image for that version.
    ///
    /// The `image_name` named ref (if provided) is assigned to the **default**
    /// version from `repository.format_config()`.  All `extra` versions are
    /// stored anonymously (no named ref).
    ///
    /// Note: Callers should ensure root metadata is set before calling this,
    /// typically via `copy_root_metadata_from_usr()` or `set_root_stat()`.
    #[context("Committing filesystem as EROFS images")]
    pub fn commit_images(
        &self,
        repository: &Repository<ObjectID>,
        image_name: Option<&str>,
    ) -> Result<HashMap<FormatVersion, ObjectID>> {
        // Validate once before writing any version.
        // add_overlay_whiteouts() for V1 is called inside mkfs_erofs_inner (on a clone).
        validate_filesystem(self)?;
        let formats = repository.format_config();
        let mut result = HashMap::new();
        let mut first = true;
        for version in formats.versions() {
            // Only the default (first) version claims the named ref.
            let name = if first { image_name } else { None };
            first = false;
            let image_data = mkfs_erofs_inner(
                self,
                version,
                #[cfg(test)]
                None,
            );
            let id = repository.write_image(name, &image_data)?;
            result.insert(version, id);
        }
        Ok(result)
    }

    /// Commits this filesystem as an EROFS image to the repository.
    ///
    /// Generates an EROFS filesystem image using the repository's configured
    /// EROFS format version and writes it with the optional name. Returns the
    /// fsverity digest of the committed image for the default format version.
    ///
    /// Note: Callers should ensure root metadata is set before calling this,
    /// typically via `copy_root_metadata_from_usr()` or `set_root_stat()`.
    #[context("Committing filesystem as EROFS image")]
    pub fn commit_image(
        &self,
        repository: &Repository<ObjectID>,
        image_name: Option<&str>,
    ) -> Result<ObjectID> {
        let version = repository.format_config().default;
        let mut map = self.commit_images(repository, image_name)?;
        Ok(map.remove(&version).expect("format version must be in map"))
    }

    /// Commits this filesystem as an EROFS image of the given `version`,
    /// regardless of the repository's configured default/extra format versions.
    ///
    /// Useful when a caller needs a *non-default* format version committed
    /// — e.g. one the repository wasn't configured to generate — but
    /// doesn't already know the resulting digest. Callers that already have
    /// (or want) the digest before deciding whether to persist should use
    /// [`Self::compute_image_bytes`] followed by [`Repository::write_image`]
    /// instead, to avoid serializing the tree twice.
    ///
    /// Note: Callers should ensure root metadata is set before calling this,
    /// typically via `copy_root_metadata_from_usr()` or `set_root_stat()`.
    #[context("Committing filesystem as EROFS image (explicit version)")]
    pub fn commit_image_version(
        &self,
        repository: &Repository<ObjectID>,
        version: FormatVersion,
        image_name: Option<&str>,
    ) -> Result<ObjectID> {
        validate_filesystem(self)?;
        let image_data = mkfs_erofs_inner(
            self,
            version,
            #[cfg(test)]
            None,
        );
        repository.write_image(image_name, &image_data)
    }

    /// Computes the EROFS image bytes for this filesystem at `version`,
    /// along with their fsverity digest.
    ///
    /// Useful for callers that need to know the digest before deciding
    /// whether to persist the image (e.g. matching against an expected
    /// digest via `composefs_oci::boot::find_matching_boot_image`): they can
    /// pass the returned bytes to [`Repository::write_image`] directly
    /// instead of regenerating them via [`Self::commit_image_version`],
    /// which would otherwise serialize the same tree a second time.
    ///
    /// Note: Callers should ensure root metadata is set before calling this,
    /// typically via `copy_root_metadata_from_usr()` or `set_root_stat()`.
    pub fn compute_image_bytes(&self, version: FormatVersion) -> (Box<[u8]>, ObjectID) {
        // Callers are responsible for ensuring the tree is valid before calling this.
        // In practice this is always called on freshly-built trees that don't have
        // invalid constructs like hardlinked whiteouts.
        let image_data = mkfs_erofs_inner(
            self,
            version,
            #[cfg(test)]
            None,
        );
        let id = compute_verity(&image_data);
        (image_data, id)
    }

    /// Computes the fsverity digest for this filesystem as an EROFS image.
    ///
    /// The digest depends on the EROFS format version: V1 and V2 produce
    /// different on-disk layouts and therefore different digests.  Callers
    /// must supply the version explicitly so that the digest matches what is
    /// actually stored (or will be stored) in the repository.
    ///
    /// Note: Callers should ensure root metadata is set before calling this,
    /// typically via `copy_root_metadata_from_usr()` or `set_root_stat()`.
    pub fn compute_image_id(&self, version: FormatVersion) -> ObjectID {
        self.compute_image_bytes(version).1
    }

    /// Prints this filesystem in dumpfile format to stdout.
    ///
    /// Serializes the entire filesystem tree to stdout in composefs dumpfile
    /// text format.
    ///
    /// Note: Callers should ensure root metadata is set before calling this,
    /// typically via `copy_root_metadata_from_usr()` or `set_root_stat()`.
    #[context("Printing filesystem as dumpfile")]
    pub fn print_dumpfile(&self) -> Result<()> {
        write_dumpfile(&mut std::io::stdout(), self)
    }
}
