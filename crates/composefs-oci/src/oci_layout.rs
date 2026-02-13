//! Direct OCI layout directory import without the skopeo proxy.
//!
//! This module provides a fast path for importing images from local OCI layout
//! directories (the `oci:` transport). Instead of going through the
//! containers-image-proxy (which spawns skopeo as a subprocess), we read the
//! OCI layout directly using the `ocidir` crate.
//!
//! This is significantly faster for local imports since:
//! - No subprocess overhead from skopeo
//! - No IPC/pipe overhead for blob streaming
//! - Direct file I/O instead of proxy protocol parsing
//!
//! The import produces identical results to the proxy path: the same
//! splitstream format with the same content identifiers.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::thread::available_parallelism;

use anyhow::{bail, Context, Result};
use cap_std_ext::cap_std;
use fn_error_context::context;
use oci_spec::image::{Arch, Descriptor, ImageConfiguration, ImageManifest, MediaType, Os};
use ocidir::OciDir;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::debug;

use composefs::fsverity::FsVerityHashValue;
use composefs::repository::Repository;

use crate::layer::{decompress_async, import_tar_async, is_tar_media_type, store_blob_async};
use crate::skopeo::OCI_BLOB_CONTENT_TYPE;
use crate::oci_image::manifest_identifier;
use crate::skopeo::{OCI_CONFIG_CONTENT_TYPE, OCI_MANIFEST_CONTENT_TYPE};
use crate::{config_identifier, layer_identifier, oci_image::tag_image, PullResult};

/// Parse an OCI layout reference like "/path/to/dir:tag" or "/path/to/dir".
///
/// Returns (path, optional_tag).
fn parse_oci_layout_ref(imgref: &str) -> (&str, Option<&str>) {
    // The format is: path[:tag]
    // We need to be careful: paths can contain colons (on Windows, or weird Unix paths).
    // The convention is that if the last colon is after the last slash, it's a tag separator.
    if let Some(last_slash) = imgref.rfind('/') {
        if let Some(colon_pos) = imgref[last_slash..].rfind(':') {
            let absolute_colon = last_slash + colon_pos;
            let (path, tag_with_colon) = imgref.split_at(absolute_colon);
            return (path, Some(&tag_with_colon[1..]));
        }
    } else if let Some(colon_pos) = imgref.rfind(':') {
        // No slash at all, but there's a colon
        let (path, tag_with_colon) = imgref.split_at(colon_pos);
        return (path, Some(&tag_with_colon[1..]));
    }
    (imgref, None)
}

/// Read a blob from an OCI layout as bytes.
fn read_blob_bytes(ocidir: &OciDir, desc: &Descriptor) -> Result<Vec<u8>> {
    let mut file = ocidir.read_blob(desc)?;
    let mut bytes = Vec::with_capacity(desc.size() as usize);
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Import an image from a local OCI layout directory.
///
/// This is the fast path for `oci:` transport references. It reads the OCI
/// layout directly without going through skopeo.
#[context("Importing OCI layout from {}", layout_path.display())]
pub async fn import_oci_layout<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    layout_path: &Path,
    layout_tag: Option<&str>,
    reference: Option<&str>,
) -> Result<PullResult<ObjectID>> {
    // Open the OCI layout directory
    let dir = cap_std::fs::Dir::open_ambient_dir(layout_path, cap_std::ambient_authority())
        .with_context(|| format!("Opening OCI layout directory {}", layout_path.display()))?;
    let ocidir = OciDir::open(dir).context("Opening OCI directory")?;

    // Resolve the manifest descriptor from the index
    let manifest_descriptor = resolve_manifest_descriptor(&ocidir, layout_tag)
        .context("Resolving manifest from index")?;

    // Reject nested indices - they're allowed by spec but extremely rare in practice
    if *manifest_descriptor.media_type() == MediaType::ImageIndex {
        bail!(
            "Nested image index not supported; the selected manifest points to another index \
             rather than an image manifest"
        );
    }

    let manifest_digest = manifest_descriptor.digest().to_string();

    let raw_manifest =
        read_blob_bytes(&ocidir, &manifest_descriptor).context("Reading manifest blob")?;
    let manifest = ImageManifest::from_reader(&raw_manifest[..]).context("Parsing manifest")?;

    // Import config and layers
    let config_descriptor = manifest.config();
    let layers = manifest.layers();
    let (config_digest, config_verity, layer_verities) =
        import_config_and_layers(repo, &ocidir, layers, config_descriptor)
            .await
            .with_context(|| format!("Failed to import config {}", config_descriptor.digest()))?;

    // Store the manifest
    let manifest_content_id = manifest_identifier(&manifest_digest);
    let manifest_verity = if let Some(verity) = repo.has_stream(&manifest_content_id)? {
        debug!("Already have manifest {manifest_digest}");
        verity
    } else {
        debug!("Storing manifest {manifest_digest}");

        let mut splitstream = repo.create_stream(OCI_MANIFEST_CONTENT_TYPE);

        let config_key = format!("config:{}", config_descriptor.digest());
        splitstream.add_named_stream_ref(&config_key, &config_verity);

        for (diff_id, verity) in &layer_verities {
            splitstream.add_named_stream_ref(diff_id, verity);
        }

        splitstream.write_external(&raw_manifest)?;
        repo.write_stream(splitstream, &manifest_content_id, None)?
    };

    // Tag if requested
    if let Some(name) = reference {
        tag_image(repo, &manifest_digest, name)?;
    }

    Ok(PullResult {
        manifest_digest,
        manifest_verity,
        config_digest,
        config_verity,
    })
}

/// Resolve the manifest descriptor from an OCI layout's index.
///
/// If `tag` is provided, looks for a manifest with that annotation.
/// Otherwise, selects the native platform or the only manifest available.
fn resolve_manifest_descriptor(ocidir: &OciDir, tag: Option<&str>) -> Result<Descriptor> {
    let index = ocidir.read_index().context("Reading index.json")?;
    let manifests = index.manifests();

    if manifests.is_empty() {
        bail!("OCI layout index contains no manifests");
    }

    // If a tag is specified, look for it in annotations
    if let Some(tag) = tag {
        for desc in manifests {
            if let Some(annotations) = desc.annotations() {
                if let Some(ref_tag) = annotations.get("org.opencontainers.image.ref.name") {
                    if ref_tag == tag {
                        return Ok(desc.clone());
                    }
                }
            }
        }
        bail!("Tag '{tag}' not found in OCI layout index");
    }

    // No tag specified - try to find the native platform manifest
    let native_arch = Arch::default();
    let native_os = Os::default();

    for desc in manifests {
        if let Some(platform) = desc.platform() {
            if *platform.architecture() == native_arch && *platform.os() == native_os {
                return Ok(desc.clone());
            }
        }
    }

    let oci_arch = native_arch.to_string();
    let oci_os = native_os.to_string();

    // Fall back to the first manifest if there's only one
    if manifests.len() == 1 {
        return Ok(manifests[0].clone());
    }

    bail!(
        "Could not find manifest for native platform ({oci_os}/{oci_arch}) in OCI layout. \
         Available manifests: {}",
        manifests
            .iter()
            .filter_map(|d| d.platform().as_ref().map(|p| format!(
                "{}/{}",
                p.os(),
                p.architecture()
            )))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// Import config and all layers from an OCI layout.
async fn import_config_and_layers<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    ocidir: &OciDir,
    manifest_layers: &[Descriptor],
    config_descriptor: &Descriptor,
) -> Result<(String, ObjectID, HashMap<String, ObjectID>)> {
    let config_digest: &str = config_descriptor.digest().as_ref();
    let content_id = config_identifier(config_digest);

    if let Some(config_id) = repo.has_stream(&content_id)? {
        // Already have this config - read layer refs from it
        debug!("Already have container config {config_digest}");

        let stream =
            repo.open_stream(&content_id, Some(&config_id), Some(OCI_CONFIG_CONTENT_TYPE))?;
        let layer_refs: HashMap<String, ObjectID> = stream
            .into_named_refs()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();

        return Ok((config_digest.to_string(), config_id, layer_refs));
    }

    // Fetch config
    debug!("Reading config {config_digest}");
    let raw_config = read_blob_bytes(ocidir, config_descriptor).context("Reading config blob")?;

    // Parse config to get diff_ids (if this is a container image)
    let is_image_config = *config_descriptor.media_type() == MediaType::ImageConfig;
    let diff_ids: Vec<String> = if is_image_config {
        let config = ImageConfiguration::from_reader(&raw_config[..])?;
        config.rootfs().diff_ids().to_vec()
    } else {
        // Artifact - use manifest layer digests
        manifest_layers
            .iter()
            .map(|d| d.digest().to_string())
            .collect()
    };

    // Sort layers by size for parallel fetching (largest first)
    let mut layers: Vec<_> = manifest_layers.iter().zip(&diff_ids).collect();
    layers.sort_by_key(|(desc, _)| Reverse(desc.size()));

    let threads = available_parallelism()?;
    let sem = Arc::new(Semaphore::new(threads.into()));
    let mut layer_tasks = JoinSet::new();

    for (idx, (descriptor, diff_id)) in layers.iter().enumerate() {
        let diff_id = diff_id.to_string();
        let repo = Arc::clone(repo);
        let permit = Arc::clone(&sem).acquire_owned().await?;

        // Open a file handle to the layer blob - we'll stream through it
        let layer_file = ocidir
            .read_blob(descriptor)
            .with_context(|| format!("Opening layer blob {}", descriptor.digest()))?;

        let media_type = descriptor.media_type().clone();

        layer_tasks.spawn(async move {
            let _permit = permit;
            let verity = import_layer_from_file(&repo, &diff_id, layer_file, &media_type).await?;
            anyhow::Ok((idx, diff_id, verity))
        });
    }

    // Collect results and sort by index
    let mut results: Vec<_> = layer_tasks
        .join_all()
        .await
        .into_iter()
        .collect::<Result<_, _>>()?;
    results.sort_by_key(|(idx, _, _)| *idx);

    // Build config splitstream with layer refs
    let mut splitstream = repo.create_stream(OCI_CONFIG_CONTENT_TYPE);
    let mut layer_refs = HashMap::new();
    for (_, diff_id, verity) in results {
        splitstream.add_named_stream_ref(&diff_id, &verity);
        layer_refs.insert(diff_id, verity);
    }

    splitstream.write_external(&raw_config)?;
    let config_id = repo.write_stream(splitstream, &content_id, None)?;

    Ok((config_digest.to_string(), config_id, layer_refs))
}

/// Import a single layer by streaming from a file handle.
///
/// This avoids buffering entire layers in memory by streaming through
/// the file handle directly.
async fn import_layer_from_file<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    diff_id: &str,
    layer_file: File,
    media_type: &MediaType,
) -> Result<ObjectID> {
    let content_id = layer_identifier(diff_id);

    if let Some(layer_id) = repo.has_stream(&content_id)? {
        debug!("Already have layer {diff_id}");
        return Ok(layer_id);
    }

    debug!("Importing layer {diff_id}");

    // Convert std::fs::File to tokio::fs::File for async I/O
    let async_file = tokio::fs::File::from_std(layer_file);

    let object_id = if is_tar_media_type(media_type) {
        let reader = decompress_async(async_file, media_type)?;
        import_tar_async(repo.clone(), reader).await?
    } else {
        // Non-tar blob: store as object and create splitstream wrapper
        let (object_id, size) = store_blob_async(repo, async_file).await?;
        let mut stream = repo.create_stream(OCI_BLOB_CONTENT_TYPE);
        stream.add_external_size(size);
        stream.write_reference(object_id)?;
        stream.done()?
    };

    // Register the stream with its content identifier
    repo.register_stream(&object_id, &content_id, None).await?;

    Ok(object_id)
}

/// Check if an image reference is an OCI layout path.
///
/// Returns the path portion if this is an `oci:` reference.
pub fn parse_oci_transport(imgref: &str) -> Option<&str> {
    imgref.strip_prefix("oci:")
}

/// Pull from an OCI layout if the reference uses the `oci:` transport.
///
/// Returns `None` if this is not an OCI transport reference.
pub async fn try_pull_oci_layout<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    imgref: &str,
    reference: Option<&str>,
) -> Result<Option<PullResult<ObjectID>>> {
    let Some(oci_path) = parse_oci_transport(imgref) else {
        return Ok(None);
    };

    let (path_str, layout_tag) = parse_oci_layout_ref(oci_path);
    let layout_path = Path::new(path_str);

    let result = import_oci_layout(repo, layout_path, layout_tag, reference).await?;
    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_oci_layout_ref() {
        let cases = [
            ("/path/to/oci", ("/path/to/oci", None)),
            ("/path/to/oci:latest", ("/path/to/oci", Some("latest"))),
            ("/path/to/oci:v1.0.0", ("/path/to/oci", Some("v1.0.0"))),
            ("./local/oci:mytag", ("./local/oci", Some("mytag"))),
            ("ocidir:latest", ("ocidir", Some("latest"))),
            ("ocidir", ("ocidir", None)),
        ];
        for (input, expected) in cases {
            assert_eq!(parse_oci_layout_ref(input), expected, "input: {input}");
        }
    }

    #[test]
    fn test_parse_oci_transport() {
        let cases = [
            ("oci:/path/to/dir", Some("/path/to/dir")),
            ("oci:/path/to/dir:tag", Some("/path/to/dir:tag")),
            ("docker://image", None),
            ("containers-storage:image", None),
        ];
        for (input, expected) in cases {
            assert_eq!(parse_oci_transport(input), expected, "input: {input}");
        }
    }

    #[tokio::test]
    async fn test_nested_index_rejected() {
        use composefs::fsverity::Sha256HashValue;
        use oci_spec::image::{DescriptorBuilder, ImageIndexBuilder, OciLayoutBuilder};
        use sha2::Digest;

        // Create a temporary OCI layout with a nested index
        let tempdir = tempfile::tempdir().unwrap();
        let layout_path = tempdir.path();

        // Create oci-layout file
        let oci_layout = OciLayoutBuilder::default()
            .image_layout_version("1.0.0".to_string())
            .build()
            .unwrap();
        let oci_layout_path = layout_path.join("oci-layout");
        std::fs::write(&oci_layout_path, oci_layout.to_string().unwrap()).unwrap();

        // Create blobs directory
        let blobs_dir = layout_path.join("blobs/sha256");
        std::fs::create_dir_all(&blobs_dir).unwrap();

        // Create a nested index (the thing we want to reject)
        let nested_index = ImageIndexBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageIndex)
            .manifests(vec![])
            .build()
            .unwrap();
        let nested_index_json = nested_index.to_string().unwrap();
        let nested_index_digest = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(nested_index_json.as_bytes()))
        );
        let nested_blob_path = blobs_dir.join(&nested_index_digest[7..]);
        std::fs::write(&nested_blob_path, &nested_index_json).unwrap();

        // Create the top-level index that points to the nested index
        let nested_desc = DescriptorBuilder::default()
            .media_type(MediaType::ImageIndex)
            .digest(
                nested_index_digest
                    .parse::<oci_spec::image::Digest>()
                    .unwrap(),
            )
            .size(nested_index_json.len() as u64)
            .build()
            .unwrap();

        let top_index = ImageIndexBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageIndex)
            .manifests(vec![nested_desc])
            .build()
            .unwrap();
        let index_path = layout_path.join("index.json");
        std::fs::write(&index_path, top_index.to_string().unwrap()).unwrap();

        // Try to import - should fail with nested index error
        let repo_dir = tempfile::tempdir().unwrap();
        let repo = std::sync::Arc::new(
            composefs::repository::Repository::<Sha256HashValue>::open_path(
                rustix::fs::CWD,
                repo_dir.path(),
            )
            .unwrap(),
        );

        let result = import_oci_layout(&repo, layout_path, None, None).await;
        let err = result.expect_err("should reject nested index");
        let err_msg = format!("{err:#}");
        assert!(
            err_msg.contains("Nested image index not supported"),
            "unexpected error: {err_msg}"
        );
    }
}
