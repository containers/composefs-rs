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
use oci_spec::image::{Descriptor, ImageConfiguration, ImageManifest, MediaType};
use rustix::process::geteuid;
use tokio::{io::AsyncReadExt, sync::Semaphore};

use composefs::{
    fsverity::FsVerityHashValue, repository::Repository, splitstream::DigestMap, util::Sha256Digest,
};

use crate::{sha256_from_descriptor, sha256_from_digest, tar::split_async, ContentAndVerity};

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

    pub async fn ensure_layer(
        &self,
        layer_sha256: Sha256Digest,
        descriptor: &Descriptor,
    ) -> Result<ObjectID> {
        // We need to use the per_manifest descriptor to download the compressed layer but it gets
        // stored in the repository via the per_config descriptor.  Our return value is the
        // fsverity digest for the corresponding splitstream.

        if let Some(layer_id) = self.repo.check_stream(&layer_sha256)? {
            self.progress
                .println(format!("Already have layer {}", hex::encode(layer_sha256)))?;
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
            self.progress
                .println(format!("Fetching layer {}", hex::encode(layer_sha256)))?;

            let mut splitstream = self.repo.create_stream(Some(layer_sha256), None);
            match descriptor.media_type() {
                MediaType::ImageLayer => {
                    split_async(progress, &mut splitstream).await?;
                }
                MediaType::ImageLayerGzip => {
                    split_async(GzipDecoder::new(progress), &mut splitstream).await?;
                }
                MediaType::ImageLayerZstd => {
                    split_async(ZstdDecoder::new(progress), &mut splitstream).await?;
                }
                other => bail!("Unsupported layer media type {other:?}"),
            };
            let layer_id = self.repo.write_stream(splitstream, None)?;

            // We intentionally explicitly ignore this, even though we're supposed to check it.
            // See https://github.com/containers/containers-image-proxy-rs/issues/80 for discussion
            // about why.  Note: we only care about the uncompressed layer tar, and we checksum it
            // ourselves.
            drop(driver);

            Ok(layer_id)
        }
    }

    pub async fn ensure_config(
        self: &Arc<Self>,
        manifest_layers: &[Descriptor],
        descriptor: &Descriptor,
    ) -> Result<ContentAndVerity<ObjectID>> {
        let config_sha256 = sha256_from_descriptor(descriptor)?;
        if let Some(config_id) = self.repo.check_stream(&config_sha256)? {
            // We already got this config?  Nice.
            self.progress.println(format!(
                "Already have container config {}",
                hex::encode(config_sha256)
            ))?;
            Ok((config_sha256, config_id))
        } else {
            // We need to add the config to the repo.  We need to parse the config and make sure we
            // have all of the layers first.
            //
            self.progress
                .println(format!("Fetching config {}", hex::encode(config_sha256)))?;

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

            // We want to sort the layers based on size so we can get started on the big layers
            // first.  The last thing we want is to start on the biggest layer right at the end.
            let mut layers: Vec<_> = zip(manifest_layers, config.rootfs().diff_ids()).collect();
            layers.sort_by_key(|(mld, ..)| Reverse(mld.size()));

            // Bound the number of tasks to the available parallelism.
            let threads = available_parallelism()?;
            let sem = Arc::new(Semaphore::new(threads.into()));
            let mut entries = vec![];
            for (mld, diff_id) in layers {
                let self_ = Arc::clone(self);
                let permit = Arc::clone(&sem).acquire_owned().await?;
                let layer_sha256 = sha256_from_digest(diff_id)?;
                let descriptor = mld.clone();
                let future = tokio::spawn(async move {
                    let _permit = permit;
                    self_.ensure_layer(layer_sha256, &descriptor).await
                });
                entries.push((layer_sha256, future));
            }

            // Collect the results.
            let mut config_maps = DigestMap::new();
            for (layer_sha256, future) in entries {
                config_maps.insert(&layer_sha256, &future.await??);
            }

            let mut splitstream = self
                .repo
                .create_stream(Some(config_sha256), Some(config_maps));
            splitstream.write_inline(&raw_config);
            let config_id = self.repo.write_stream(splitstream, None)?;

            Ok((config_sha256, config_id))
        }
    }

    pub async fn pull(self: &Arc<Self>) -> Result<ContentAndVerity<ObjectID>> {
        let (_manifest_digest, raw_manifest) = self
            .proxy
            .fetch_manifest_raw_oci(&self.img)
            .await
            .context("Fetching manifest")?;

        // We need to add the manifest to the repo.  We need to parse the manifest and make
        // sure we have the config first (which will also pull in the layers).
        let manifest = ImageManifest::from_reader(raw_manifest.as_slice())?;
        let config_descriptor = manifest.config();
        let layers = manifest.layers();
        self.ensure_config(layers, config_descriptor)
            .await
            .with_context(|| format!("Failed to pull config {config_descriptor:?}"))
    }
}

/// Pull the target image, and add the provided tag. If this is a mountable
/// image (i.e. not an artifact), it is *not* unpacked by default.
pub async fn pull<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    imgref: &str,
    reference: Option<&str>,
    img_proxy_config: Option<ImageProxyConfig>,
) -> Result<(Sha256Digest, ObjectID)> {
    let op = Arc::new(ImageOp::new(repo, imgref, img_proxy_config).await?);
    let (sha256, id) = op
        .pull()
        .await
        .with_context(|| format!("Unable to pull container image {imgref}"))?;

    if let Some(name) = reference {
        repo.name_stream(sha256, name)?;
    }
    Ok((sha256, id))
}
