//! Boot image management for OCI containers.
//!
//! A bootable EROFS image is a derived artifact from an OCI container image
//! that filters out some components (such as the UKI) to avoid circular references.

use std::sync::Arc;

use anyhow::Result;

use composefs::fsverity::FsVerityHashValue;
use composefs::repository::Repository;

/// The name used for the bootable image reference in the config.
pub const BOOT_IMAGE_REF_NAME: &str = "cfs-oci-for-bootable";

/// Generate a bootable EROFS image from a pulled OCI manifest (idempotent).
#[cfg(feature = "boot")]
pub fn generate_boot_image<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    manifest_digest: &str,
) -> Result<ObjectID> {
    if let Some(existing) = boot_image(repo, manifest_digest)? {
        return Ok(existing);
    }

    let erofs_id = crate::ensure_oci_composefs_erofs_boot(repo, manifest_digest, None, None)?
        .expect("container image should produce boot EROFS");

    Ok(erofs_id)
}

/// Returns the boot EROFS image verity, if one exists.
pub fn boot_image<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    manifest_digest: &str,
) -> Result<Option<ObjectID>> {
    crate::composefs_boot_erofs_for_manifest(repo, manifest_digest, None)
}

/// Remove the bootable EROFS image reference (idempotent).
///
/// The EROFS image itself is garbage-collected on the next `repo.gc()`.
pub fn remove_boot_image<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    manifest_digest: &str,
) -> Result<()> {
    let img = crate::oci_image::OciImage::open(repo, manifest_digest, None)?;

    if img.boot_image_ref().is_none() {
        return Ok(());
    }

    let config = img
        .config()
        .ok_or_else(|| anyhow::anyhow!("not a container image"))?
        .clone();

    let (_config_digest, new_config_verity) = crate::write_config(
        repo,
        &config,
        img.layer_refs().clone(),
        img.image_ref(),
        None, // no boot image
    )?;

    let manifest_json = img.read_manifest_json(repo)?;
    let layer_verities = img.layer_refs().clone();

    crate::oci_image::rewrite_manifest(
        repo,
        &manifest_json,
        manifest_digest,
        &new_config_verity,
        &layer_verities,
        None,
    )?;

    Ok(())
}

#[cfg(all(test, feature = "boot"))]
mod test {
    use super::*;
    use composefs::fsverity::Sha256HashValue;
    use composefs::test::TestRepo;
    use composefs_boot::bootloader::get_boot_resources;

    use crate::oci_image::OciImage;
    use crate::test_util;

    #[tokio::test]
    async fn test_boot_image_none_before_generate() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let img = test_util::create_bootable_image(repo, Some("myapp:v1"), 1).await;

        let result = boot_image(repo, &img.manifest_digest).unwrap();
        assert!(result.is_none(), "no boot image should exist yet");
    }

    #[tokio::test]
    async fn test_generate_boot_image() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let img = test_util::create_bootable_image(repo, Some("myapp:v1"), 1).await;

        let image_verity = generate_boot_image(repo, &img.manifest_digest).unwrap();

        let found = boot_image(repo, &img.manifest_digest).unwrap();
        assert_eq!(found, Some(image_verity.clone()));

        // Open by tag since manifest was rewritten
        let oci = OciImage::open_ref(repo, "myapp:v1").unwrap();
        assert_eq!(oci.boot_image_ref(), Some(&image_verity));

        let plain_image = crate::image::create_filesystem(repo, &img.config_digest, None).unwrap();
        let plain_verity = plain_image.compute_image_id();
        assert_ne!(
            image_verity, plain_verity,
            "boot-transformed image should differ from non-transformed image"
        );
    }

    #[tokio::test]
    async fn test_generate_boot_image_idempotent() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let img = test_util::create_bootable_image(repo, Some("myapp:v1"), 1).await;

        let v1 = generate_boot_image(repo, &img.manifest_digest).unwrap();
        let v2 = generate_boot_image(repo, &img.manifest_digest).unwrap();
        assert_eq!(v1, v2);
    }

    #[tokio::test]
    async fn test_remove_boot_image() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let img = test_util::create_bootable_image(repo, Some("myapp:v1"), 1).await;

        generate_boot_image(repo, &img.manifest_digest).unwrap();
        assert!(boot_image(repo, &img.manifest_digest).unwrap().is_some());

        remove_boot_image(repo, &img.manifest_digest).unwrap();
        assert!(
            boot_image(repo, &img.manifest_digest).unwrap().is_none(),
            "boot image should be gone after remove"
        );

        let oci = OciImage::open_ref(repo, "myapp:v1").unwrap();
        assert!(oci.is_container_image());

        let gc = repo.gc(&[]).unwrap();
        assert_eq!(
            gc.images_pruned, 1,
            "exactly the EROFS image should be pruned"
        );
    }

    #[tokio::test]
    async fn test_remove_boot_image_idempotent() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let img = test_util::create_bootable_image(repo, Some("myapp:v1"), 1).await;

        remove_boot_image(repo, &img.manifest_digest).unwrap();

        generate_boot_image(repo, &img.manifest_digest).unwrap();
        remove_boot_image(repo, &img.manifest_digest).unwrap();
        remove_boot_image(repo, &img.manifest_digest).unwrap();

        assert!(boot_image(repo, &img.manifest_digest).unwrap().is_none());
    }

    #[tokio::test]
    async fn test_boot_image_gc_preserves_when_tagged() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let img = test_util::create_bootable_image(repo, Some("myapp:v1"), 1).await;

        let image_verity = generate_boot_image(repo, &img.manifest_digest).unwrap();

        let gc = repo.gc(&[]).unwrap();
        assert_eq!(gc.images_pruned, 0);
        assert_eq!(gc.streams_pruned, 0);

        let oci = OciImage::open_ref(repo, "myapp:v1").unwrap();
        assert_eq!(oci.boot_image_ref(), Some(&image_verity));
    }

    #[tokio::test]
    async fn test_boot_image_gc_collects_after_untag() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let img = test_util::create_bootable_image(repo, Some("myapp:v1"), 1).await;

        generate_boot_image(repo, &img.manifest_digest).unwrap();

        crate::oci_image::untag_image(repo, "myapp:v1").unwrap();

        let gc = repo.gc(&[]).unwrap();
        assert!(gc.objects_removed > 0);
        assert_eq!(gc.images_pruned, 1);
        assert!(gc.streams_pruned > 0);

        let gc2 = repo.gc(&[]).unwrap();
        assert_eq!(gc2.objects_removed, 0);
        assert_eq!(gc2.images_pruned, 0);
        assert_eq!(gc2.streams_pruned, 0);
    }

    #[tokio::test]
    async fn test_remove_boot_image_then_gc_preserves_oci() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let img = test_util::create_bootable_image(repo, Some("myapp:v1"), 1).await;

        generate_boot_image(repo, &img.manifest_digest).unwrap();

        remove_boot_image(repo, &img.manifest_digest).unwrap();
        let gc = repo.gc(&[]).unwrap();
        assert_eq!(gc.images_pruned, 1);

        let oci = OciImage::open_ref(repo, "myapp:v1").unwrap();
        assert!(oci.is_container_image());
        assert!(oci.boot_image_ref().is_none());
    }

    #[tokio::test]
    async fn test_boot_content_assertion() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let img = test_util::create_bootable_image(repo, Some("myapp:v1"), 1).await;

        let boot_verity = generate_boot_image(repo, &img.manifest_digest).unwrap();

        let fs = crate::image::create_filesystem(repo, &img.config_digest, None).unwrap();
        let boot_entries = get_boot_resources(&fs, repo).unwrap();
        assert_eq!(boot_entries.len(), 2);
        assert!(boot_entries.iter().any(|e| matches!(
            e,
            composefs_boot::bootloader::BootEntry::UsrLibModulesVmLinuz(_)
        )),);
        assert!(boot_entries
            .iter()
            .any(|e| matches!(e, composefs_boot::bootloader::BootEntry::Type2(_))),);

        let plain_fs = crate::image::create_filesystem(repo, &img.config_digest, None).unwrap();
        let plain_verity = plain_fs.commit_image(repo, None).unwrap();
        assert_ne!(boot_verity, plain_verity);
    }

    #[tokio::test]
    async fn test_boot_content_uki() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let img = test_util::create_bootable_image(repo, Some("uki:v1"), 1).await;

        let boot_verity = generate_boot_image(repo, &img.manifest_digest).unwrap();

        let fs = crate::image::create_filesystem(repo, &img.config_digest, None).unwrap();
        let boot_entries = get_boot_resources(&fs, repo).unwrap();
        assert_eq!(boot_entries.len(), 2);
        assert!(boot_entries
            .iter()
            .any(|e| matches!(e, composefs_boot::bootloader::BootEntry::Type2(_))),);
        assert!(boot_entries.iter().any(|e| matches!(
            e,
            composefs_boot::bootloader::BootEntry::UsrLibModulesVmLinuz(_)
        )),);

        let plain_fs = crate::image::create_filesystem(repo, &img.config_digest, None).unwrap();
        let plain_verity = plain_fs.commit_image(repo, None).unwrap();
        assert_ne!(boot_verity, plain_verity);
    }
}
