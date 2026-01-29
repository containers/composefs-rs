//! Container image pulling and registry interaction via skopeo/containers-image-proxy.
//!
//! This module provides functionality to pull container images from various registries and import them
//! into composefs repositories. It uses the containers-image-proxy library to interface with skopeo
//! for image operations, handling authentication, transport protocols, and image manifest processing.
//!
//! The main entry point is the `pull()` function which downloads an image, processes its layers
//! asynchronously with parallelism control, and stores them in the composefs repository with proper
//! fs-verity integration. It supports various image formats and compression types.

use std::{cmp::Reverse, process::Command, thread::available_parallelism};

use std::{iter::zip, sync::Arc};

use anyhow::{bail, Context, Result};
use async_compression::tokio::bufread::{GzipDecoder, ZstdDecoder};
use containers_image_proxy::{ImageProxy, ImageProxyConfig, OpenedImage};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use oci_spec::image::{Descriptor, ImageConfiguration, MediaType};
use rustix::process::geteuid;
use tokio::{
    io::{AsyncReadExt, BufReader},
    sync::Semaphore,
};

use composefs::{fsverity::FsVerityHashValue, repository::Repository};

use crate::{
    config_identifier, layer_identifier,
    oci_image::{manifest_identifier, tag_image},
    tar::split_async,
    ContentAndVerity,
};

/// Result of pulling an OCI image.
///
/// Contains digests and fs-verity IDs for both the manifest and config,
/// allowing callers to access either level of the image structure.
#[derive(Debug, Clone)]
pub struct PullResult<ObjectID: FsVerityHashValue> {
    /// The sha256 content digest of the manifest.
    pub manifest_digest: String,
    /// The fs-verity ID of the manifest splitstream.
    pub manifest_verity: ObjectID,
    /// The sha256 content digest of the config.
    pub config_digest: String,
    /// The fs-verity ID of the config splitstream.
    pub config_verity: ObjectID,
}

impl<ObjectID: FsVerityHashValue> PullResult<ObjectID> {
    /// Returns (config_digest, config_verity) for backward compatibility.
    pub fn into_config(self) -> ContentAndVerity<ObjectID> {
        (self.config_digest, self.config_verity)
    }

    /// Returns (manifest_digest, manifest_verity).
    pub fn into_manifest(self) -> ContentAndVerity<ObjectID> {
        (self.manifest_digest, self.manifest_verity)
    }
}

// Content type identifiers stored as ASCII in the splitstream file.
// These are arbitrary 8-byte ASCII strings for identification.
pub(crate) const TAR_LAYER_CONTENT_TYPE: u64 = u64::from_le_bytes(*b"ocilayer");
pub(crate) const OCI_CONFIG_CONTENT_TYPE: u64 = u64::from_le_bytes(*b"ociconfg");
pub(crate) const OCI_MANIFEST_CONTENT_TYPE: u64 = u64::from_le_bytes(*b"ocimanif");
/// Content type for arbitrary blobs (OCI artifacts with non-tar media types).
pub(crate) const OCI_BLOB_CONTENT_TYPE: u64 = u64::from_le_bytes(*b"oci_blob");

struct ImageOp<ObjectID: FsVerityHashValue> {
    repo: Arc<Repository<ObjectID>>,
    proxy: ImageProxy,
    img: OpenedImage,
    progress: MultiProgress,
}

impl<ObjectID: FsVerityHashValue> ImageOp<ObjectID> {
    async fn new(
        repo: &Arc<Repository<ObjectID>>,
        imgref: &str,
        img_proxy_config: Option<ImageProxyConfig>,
    ) -> Result<Self> {
        // See https://github.com/containers/skopeo/issues/2563
        let skopeo_cmd = if imgref.starts_with("containers-storage:") && !geteuid().is_root() {
            let mut cmd = Command::new("podman");
            cmd.args(["unshare", "skopeo"]);
            Some(cmd)
        } else {
            None
        };

        // See https://github.com/containers/skopeo/issues/2750
        let imgref = if let Some(hash) = imgref.strip_prefix("containers-storage:sha256:") {
            &format!("containers-storage:{hash}") // yay temporary lifetime extension!
        } else {
            imgref
        };

        let config = match img_proxy_config {
            Some(mut conf) => {
                if conf.skopeo_cmd.is_none() {
                    conf.skopeo_cmd = skopeo_cmd;
                }

                conf
            }

            None => {
                ImageProxyConfig {
                    skopeo_cmd,
                    // auth_anonymous: true, debug: true, insecure_skip_tls_verification: None,
                    ..ImageProxyConfig::default()
                }
            }
        };

        let proxy = containers_image_proxy::ImageProxy::new_with_config(config).await?;
        let img = proxy.open_image(imgref).await.context("Opening image")?;
        let progress = MultiProgress::new();
        Ok(ImageOp {
            repo: Arc::clone(repo),
            proxy,
            img,
            progress,
        })
    }

    pub async fn ensure_layer(&self, diff_id: &str, descriptor: &Descriptor) -> Result<ObjectID> {
        // We need to use the per_manifest descriptor to download the compressed layer but it gets
        // stored in the repository via the per_config descriptor.  Our return value is the
        // fsverity digest for the corresponding splitstream.
        let content_id = layer_identifier(diff_id);

        if let Some(layer_id) = self.repo.has_stream(&content_id)? {
            self.progress
                .println(format!("Already have layer {diff_id}"))?;
            Ok(layer_id)
        } else {
            // Otherwise, we need to fetch it...
            let (blob_reader, driver) = self.proxy.get_descriptor(&self.img, descriptor).await?;

            // See https://github.com/containers/containers-image-proxy-rs/issues/71
            let blob_reader = blob_reader.take(descriptor.size());

            let bar = self.progress.add(ProgressBar::new(descriptor.size()));
            bar.set_style(ProgressStyle::with_template("[eta {eta}] {bar:40.cyan/blue} {decimal_bytes:>7}/{decimal_total_bytes:7} {msg}")
                .unwrap()
                .progress_chars("##-"));
            let progress = bar.wrap_async_read(blob_reader);
            self.progress.println(format!("Fetching layer {diff_id}"))?;

            let object_id = match descriptor.media_type() {
                MediaType::ImageLayer => {
                    split_async(
                        BufReader::new(progress),
                        self.repo.clone(),
                        TAR_LAYER_CONTENT_TYPE,
                    )
                    .await?
                }
                MediaType::ImageLayerGzip => {
                    split_async(
                        BufReader::new(GzipDecoder::new(BufReader::new(progress))),
                        self.repo.clone(),
                        TAR_LAYER_CONTENT_TYPE,
                    )
                    .await?
                }
                MediaType::ImageLayerZstd => {
                    split_async(
                        BufReader::new(ZstdDecoder::new(BufReader::new(progress))),
                        self.repo.clone(),
                        TAR_LAYER_CONTENT_TYPE,
                    )
                    .await?
                }
                other => bail!("Unsupported layer media type {other:?}"),
            };

            // skopeo is doing data checksums for us to make sure the content we received is equal
            // to the claimed diff_id. We trust it, but we need to check it by awaiting the driver.
            driver.await?;

            // Sync and register the stream with its content identifier
            self.repo
                .register_stream(&object_id, &content_id, None)
                .await?;

            Ok(object_id)
        }
    }

    /// Ensure config is present and return layer verities along with config info.
    async fn ensure_config_with_layers(
        self: &Arc<Self>,
        manifest_layers: &[Descriptor],
        descriptor: &Descriptor,
    ) -> Result<(
        String,
        ObjectID,
        std::collections::HashMap<String, ObjectID>,
    )> {
        let config_digest: &str = descriptor.digest().as_ref();
        let content_id = config_identifier(config_digest);

        if let Some(config_id) = self.repo.has_stream(&content_id)? {
            // We already got this config - need to read the layer refs from it
            self.progress
                .println(format!("Already have container config {config_digest}"))?;

            let stream = self.repo.open_stream(
                &content_id,
                Some(&config_id),
                Some(OCI_CONFIG_CONTENT_TYPE),
            )?;
            let layer_refs: std::collections::HashMap<String, ObjectID> = stream
                .into_named_refs()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect();

            Ok((config_digest.to_string(), config_id, layer_refs))
        } else {
            // We need to add the config to the repo
            self.progress
                .println(format!("Fetching config {config_digest}"))?;

            let (mut config, driver) = self.proxy.get_descriptor(&self.img, descriptor).await?;
            let config = async move {
                let mut s = Vec::new();
                config.read_to_end(&mut s).await?;
                anyhow::Ok(s)
            };
            let (config, driver) = tokio::join!(config, driver);
            let _: () = driver?;
            let raw_config = config?;
            let config = ImageConfiguration::from_reader(&raw_config[..])?;

            // Sort layers by size for parallel fetching
            let mut layers: Vec<_> = zip(manifest_layers, config.rootfs().diff_ids()).collect();
            layers.sort_by_key(|(mld, ..)| Reverse(mld.size()));

            let threads = available_parallelism()?;
            let sem = Arc::new(Semaphore::new(threads.into()));
            let mut entries = vec![];
            for (mld, diff_id) in layers {
                let diff_id_ = diff_id.clone();
                let self_ = Arc::clone(self);
                let permit = Arc::clone(&sem).acquire_owned().await?;
                let descriptor = mld.clone();
                let future = tokio::spawn(async move {
                    let _permit = permit;
                    self_.ensure_layer(&diff_id_, &descriptor).await
                });
                entries.push((diff_id, future));
            }

            let mut splitstream = self.repo.create_stream(OCI_CONFIG_CONTENT_TYPE);
            let mut layer_refs = std::collections::HashMap::new();

            // Collect the results
            for (diff_id, future) in entries {
                let layer_verity = future.await??;
                splitstream.add_named_stream_ref(diff_id, &layer_verity);
                layer_refs.insert(diff_id.clone(), layer_verity);
            }

            splitstream.write_inline(&raw_config);
            let config_id = self.repo.write_stream(splitstream, &content_id, None)?;
            Ok((config_digest.to_string(), config_id, layer_refs))
        }
    }

    /// Pull the image, storing manifest, config, and all layers.
    pub async fn pull(self: &Arc<Self>) -> Result<PullResult<ObjectID>> {
        let (manifest_digest, raw_manifest) = self
            .proxy
            .fetch_manifest_raw_oci(&self.img)
            .await
            .context("Fetching manifest")?;

        // Parse the manifest and pull config + layers
        let manifest = oci_spec::image::ImageManifest::from_reader(raw_manifest.as_slice())?;
        let config_descriptor = manifest.config();
        let layers = manifest.layers();
        let (config_digest, config_verity, layer_verities) = self
            .ensure_config_with_layers(layers, config_descriptor)
            .await
            .with_context(|| format!("Failed to pull config {config_descriptor:?}"))?;

        // Store the manifest with references to config and layers
        let manifest_content_id = manifest_identifier(&manifest_digest);
        let manifest_verity = if let Some(verity) = self.repo.has_stream(&manifest_content_id)? {
            self.progress
                .println(format!("Already have manifest {manifest_digest}"))?;
            verity
        } else {
            self.progress
                .println(format!("Storing manifest {manifest_digest}"))?;

            let mut splitstream = self.repo.create_stream(OCI_MANIFEST_CONTENT_TYPE);

            // Add reference to the config
            let config_key = format!("config:{}", config_descriptor.digest());
            splitstream.add_named_stream_ref(&config_key, &config_verity);

            // Store references to all layers by their diff_id
            for (diff_id, verity) in &layer_verities {
                splitstream.add_named_stream_ref(diff_id, verity);
            }

            // Store the raw manifest bytes
            splitstream.write_inline(&raw_manifest);
            self.repo
                .write_stream(splitstream, &manifest_content_id, None)?
        };

        Ok(PullResult {
            manifest_digest,
            manifest_verity,
            config_digest,
            config_verity,
        })
    }
}

/// Pull the target image, storing manifest, config, and layers.
///
/// Returns `PullResult` containing both manifest and config digests/verities.
/// If `reference` is provided, the manifest is also stored under that name.
///
/// Note: For backward compatibility, use `.into_config()` on the result to get
/// the (config_digest, config_verity) tuple that was previously returned.
pub async fn pull_image<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    imgref: &str,
    reference: Option<&str>,
    img_proxy_config: Option<ImageProxyConfig>,
) -> Result<PullResult<ObjectID>> {
    let op = Arc::new(ImageOp::new(repo, imgref, img_proxy_config).await?);
    let result = op
        .pull()
        .await
        .with_context(|| format!("Unable to pull container image {imgref}"))?;

    if let Some(name) = reference {
        tag_image(repo, &result.manifest_digest, name)?;
    }
    Ok(result)
}

/// Pull the target image, and add the provided tag. If this is a mountable
/// image (i.e. not an artifact), it is *not* unpacked by default.
///
/// Returns (config_digest, config_verity) for backward compatibility.
/// Consider using `pull_image` for access to manifest information.
pub async fn pull<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    imgref: &str,
    reference: Option<&str>,
    img_proxy_config: Option<ImageProxyConfig>,
) -> Result<(String, ObjectID)> {
    let result = pull_image(repo, imgref, reference, img_proxy_config).await?;
    Ok(result.into_config())
}
