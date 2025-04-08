use std::process::Command;

pub mod image;
pub mod tar;

use std::{collections::HashMap, io::Read, iter::zip, path::Path};

use anyhow::{bail, ensure, Context, Result};
use async_compression::tokio::bufread::{GzipDecoder, ZstdDecoder};
use containers_image_proxy::{ImageProxy, ImageProxyConfig, OpenedImage};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use oci_spec::image::{Descriptor, ImageConfiguration, ImageManifest, MediaType};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use crate::{
    fs::write_to_path,
    fsverity::Sha256HashValue,
    oci::tar::{get_entry, split_async},
    repository::Repository,
    splitstream::{
        handle_external_object, DigestMap, EnsureObjectMessages, ResultChannelReceiver,
        ResultChannelSender, WriterMessages,
    },
    util::parse_sha256,
    zstd_encoder,
};

pub fn import_layer(
    repo: &Repository,
    sha256: &Sha256HashValue,
    name: Option<&str>,
    tar_stream: &mut impl Read,
) -> Result<Sha256HashValue> {
    repo.ensure_stream(sha256, |writer| tar::split(tar_stream, writer), name)
}

pub fn ls_layer(repo: &Repository, name: &str) -> Result<()> {
    let mut split_stream = repo.open_stream(name, None)?;

    while let Some(entry) = get_entry(&mut split_stream)? {
        println!("{}", entry);
    }

    Ok(())
}

struct ImageOp<'repo> {
    repo: &'repo Repository,
    proxy: ImageProxy,
    img: OpenedImage,
    progress: MultiProgress,
}

fn sha256_from_descriptor(descriptor: &Descriptor) -> Result<Sha256HashValue> {
    let Some(digest) = descriptor.as_digest_sha256() else {
        bail!("Descriptor in oci config is not sha256");
    };
    parse_sha256(digest)
}

fn sha256_from_digest(digest: &str) -> Result<Sha256HashValue> {
    match digest.strip_prefix("sha256:") {
        Some(rest) => parse_sha256(rest),
        None => bail!("Manifest has non-sha256 digest"),
    }
}

type ContentAndVerity = (Sha256HashValue, Sha256HashValue);

impl<'repo> ImageOp<'repo> {
    async fn new(repo: &'repo Repository, imgref: &str) -> Result<Self> {
        // See https://github.com/containers/skopeo/issues/2563
        let skopeo_cmd = if imgref.starts_with("containers-storage:") {
            let mut cmd = Command::new("podman");
            cmd.args(["unshare", "skopeo"]);
            Some(cmd)
        } else {
            None
        };

        let config = ImageProxyConfig {
            skopeo_cmd,
            // auth_anonymous: true, debug: true, insecure_skip_tls_verification: Some(true),
            ..ImageProxyConfig::default()
        };
        let proxy = containers_image_proxy::ImageProxy::new_with_config(config).await?;
        let img = proxy.open_image(imgref).await.context("Opening image")?;
        let progress = MultiProgress::new();

        Ok(ImageOp {
            repo,
            proxy,
            img,
            progress,
        })
    }

    pub async fn ensure_layer(
        &self,
        layer_sha256: &Sha256HashValue,
        descriptor: &Descriptor,
        layer_num: usize,
        object_sender: crossbeam::channel::Sender<EnsureObjectMessages>,
    ) -> Result<()> {
        // We need to use the per_manifest descriptor to download the compressed layer but it gets
        // stored in the repository via the per_config descriptor.  Our return value is the
        // fsverity digest for the corresponding splitstream.

        // Otherwise, we need to fetch it...
        let (blob_reader, driver) = self.proxy.get_descriptor(&self.img, descriptor).await?;

        // See https://github.com/containers/containers-image-proxy-rs/issues/71
        let blob_reader = blob_reader.take(descriptor.size());

        let bar = self.progress.add(ProgressBar::new(descriptor.size()));
        bar.set_style(
            ProgressStyle::with_template(
                "[eta {eta}] {bar:40.cyan/blue} {decimal_bytes:>7}/{decimal_total_bytes:7} {msg}",
            )
            .unwrap()
            .progress_chars("##-"),
        );
        let progress = bar.wrap_async_read(blob_reader);
        self.progress
            .println(format!("Fetching layer {}", hex::encode(layer_sha256)))?;

        let mut splitstream =
            self.repo
                .create_stream(Some(*layer_sha256), None, Some(object_sender));
        match descriptor.media_type() {
            MediaType::ImageLayer => {
                split_async(progress, &mut splitstream, layer_num).await?;
            }
            MediaType::ImageLayerGzip => {
                split_async(GzipDecoder::new(progress), &mut splitstream, layer_num).await?;
            }
            MediaType::ImageLayerZstd => {
                split_async(ZstdDecoder::new(progress), &mut splitstream, layer_num).await?;
            }
            other => bail!("Unsupported layer media type {:?}", other),
        };
        driver.await?;

        Ok(())
    }

    pub async fn ensure_config(
        &self,
        manifest_layers: &[Descriptor],
        descriptor: &Descriptor,
    ) -> Result<ContentAndVerity> {
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

            let (done_chan_sender, done_chan_recver, object_sender) =
                self.spawn_threads(&config)?;

            let mut config_maps = DigestMap::new();

            let mut idx = 0;

            for (mld, cld) in zip(manifest_layers, config.rootfs().diff_ids()) {
                let layer_sha256 = sha256_from_digest(cld)?;

                if let Some(layer_id) = self.repo.check_stream(&layer_sha256)? {
                    self.progress
                        .println(format!("Already have layer {}", hex::encode(layer_sha256)))?;

                    config_maps.insert(&layer_sha256, &layer_id);
                } else {
                    self.ensure_layer(&layer_sha256, mld, idx, object_sender.clone())
                        .await
                        .with_context(|| format!("Failed to fetch layer {cld} via {mld:?}"))?;

                    idx += 1;
                }
            }

            drop(done_chan_sender);

            while let Ok(res) = done_chan_recver.recv() {
                let (layer_sha256, layer_id) = res?;
                config_maps.insert(&layer_sha256, &layer_id);
            }

            let mut splitstream =
                self.repo
                    .create_stream(Some(config_sha256), Some(config_maps), None);
            splitstream.write_inline(&raw_config);
            let config_id = self.repo.write_stream(splitstream, None)?;

            Ok((config_sha256, config_id))
        }
    }

    fn spawn_threads(
        &self,
        config: &ImageConfiguration,
    ) -> Result<(
        ResultChannelSender,
        ResultChannelReceiver,
        crossbeam::channel::Sender<EnsureObjectMessages>,
    )> {
        use crossbeam::channel::{unbounded, Receiver, Sender};

        let mut encoder_threads = 2;
        let external_object_writer_threads = 4;

        let chunk_len = config.rootfs().diff_ids().len().div_ceil(encoder_threads);

        // Divide the layers into chunks of some specific size so each worker
        // thread can work on multiple deterministic layers
        let diff_ids: Vec<Sha256HashValue> = config
            .rootfs()
            .diff_ids()
            .iter()
            .map(|x| sha256_from_digest(x))
            .collect::<Result<Vec<Sha256HashValue>, _>>()?;

        let mut unhandled_layers = vec![];

        // This becomes pretty unreadable with a filter,map chain
        for id in diff_ids {
            let layer_exists = self.repo.check_stream(&id)?;

            if layer_exists.is_none() {
                unhandled_layers.push(id);
            }
        }

        let mut chunks: Vec<Vec<Sha256HashValue>> = unhandled_layers
            .chunks(chunk_len)
            .map(|x| x.to_vec())
            .collect();

        // Mapping from layer_id -> index in writer_channels
        // This is to make sure that all messages relating to a particular layer
        // always reach the same writer
        let layers_to_chunks = chunks
            .iter()
            .enumerate()
            .flat_map(|(i, chunk)| std::iter::repeat_n(i, chunk.len()).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        encoder_threads = encoder_threads.min(chunks.len());

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(encoder_threads + external_object_writer_threads)
            .build()
            .unwrap();

        // We need this as writers have internal state that can't be shared between threads
        //
        // We'll actually need as many writers (not writer threads, but writer instances) as there are layers.
        let zstd_writer_channels: Vec<(Sender<WriterMessages>, Receiver<WriterMessages>)> =
            (0..encoder_threads).map(|_| unbounded()).collect();

        let (object_sender, object_receiver) = unbounded::<EnsureObjectMessages>();

        // (layer_sha256, layer_id)
        let (done_chan_sender, done_chan_recver) =
            std::sync::mpsc::channel::<Result<(Sha256HashValue, Sha256HashValue)>>();

        for i in 0..encoder_threads {
            let repository = self.repo.try_clone().unwrap();
            let object_sender = object_sender.clone();
            let done_chan_sender = done_chan_sender.clone();
            let chunk = std::mem::take(&mut chunks[i]);
            let receiver = zstd_writer_channels[i].1.clone();

            pool.spawn({
                move || {
                    let start = i * (chunk_len);
                    let end = start + chunk_len;

                    let enc = zstd_encoder::MultipleZstdWriters::new(
                        chunk,
                        repository,
                        object_sender,
                        done_chan_sender,
                    );

                    if let Err(e) = enc.recv_data(receiver, start, end) {
                        eprintln!("zstd_encoder returned with error: {}", e)
                    }
                }
            });
        }

        for _ in 0..external_object_writer_threads {
            pool.spawn({
                let repository = self.repo.try_clone().unwrap();
                let zstd_writer_channels = zstd_writer_channels
                    .iter()
                    .map(|(s, _)| s.clone())
                    .collect::<Vec<_>>();
                let layers_to_chunks = layers_to_chunks.clone();
                let external_object_receiver = object_receiver.clone();

                move || {
                    if let Err(e) = handle_external_object(
                        repository,
                        external_object_receiver,
                        zstd_writer_channels,
                        layers_to_chunks,
                    ) {
                        eprintln!("handle_external_object returned with error: {}", e);
                    }
                }
            });
        }

        Ok((done_chan_sender, done_chan_recver, object_sender))
    }

    pub async fn pull(&self) -> Result<(Sha256HashValue, Sha256HashValue)> {
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
pub async fn pull(repo: &Repository, imgref: &str, reference: Option<&str>) -> Result<()> {
    let op = ImageOp::new(repo, imgref).await?;
    let (sha256, id) = op
        .pull()
        .await
        .with_context(|| format!("Unable to pull container image {imgref}"))?;

    if let Some(name) = reference {
        repo.name_stream(sha256, name)?;
    }
    println!("sha256 {}", hex::encode(sha256));
    println!("verity {}", hex::encode(id));
    Ok(())
}

pub fn open_config(
    repo: &Repository,
    name: &str,
    verity: Option<&Sha256HashValue>,
) -> Result<(ImageConfiguration, DigestMap)> {
    let id = match verity {
        Some(id) => id,
        None => {
            // take the expensive route
            let sha256 = parse_sha256(name)
                .context("Containers must be referred to by sha256 if verity is missing")?;
            &repo
                .check_stream(&sha256)?
                .with_context(|| format!("Object {name} is unknown to us"))?
        }
    };
    let mut stream = repo.open_stream(name, Some(id))?;
    let config = ImageConfiguration::from_reader(&mut stream)?;
    Ok((config, stream.refs))
}

fn hash(bytes: &[u8]) -> Sha256HashValue {
    let mut context = Sha256::new();
    context.update(bytes);
    context.finalize().into()
}

pub fn open_config_shallow(
    repo: &Repository,
    name: &str,
    verity: Option<&Sha256HashValue>,
) -> Result<ImageConfiguration> {
    match verity {
        // with verity deep opens are just as fast as shallow ones
        Some(id) => Ok(open_config(repo, name, Some(id))?.0),
        None => {
            // we need to manually check the content digest
            let expected_hash = parse_sha256(name)
                .context("Containers must be referred to by sha256 if verity is missing")?;
            let mut stream = repo.open_stream(name, None)?;
            let mut raw_config = vec![];
            stream.read_to_end(&mut raw_config)?;
            ensure!(hash(&raw_config) == expected_hash, "Data integrity issue");
            Ok(ImageConfiguration::from_reader(&mut raw_config.as_slice())?)
        }
    }
}

pub fn write_config(
    repo: &Repository,
    config: &ImageConfiguration,
    refs: DigestMap,
) -> Result<(Sha256HashValue, Sha256HashValue)> {
    let json = config.to_string()?;
    let json_bytes = json.as_bytes();
    let sha256 = hash(json_bytes);
    let mut stream = repo.create_stream(Some(sha256), Some(refs), None);
    stream.write_inline(json_bytes);
    let id = repo.write_stream(stream, None)?;
    Ok((sha256, id))
}

pub fn seal(
    repo: &Repository,
    name: &str,
    verity: Option<&Sha256HashValue>,
) -> Result<(Sha256HashValue, Sha256HashValue)> {
    let (mut config, refs) = open_config(repo, name, verity)?;
    let mut myconfig = config.config().clone().context("no config!")?;
    let labels = myconfig.labels_mut().get_or_insert_with(HashMap::new);
    let id = crate::oci::image::create_image(repo, name, None, verity)?;
    labels.insert("containers.composefs.fsverity".to_string(), hex::encode(id));
    config.set_config(Some(myconfig));
    write_config(repo, &config, refs)
}

pub fn mount(
    repo: &Repository,
    name: &str,
    mountpoint: &str,
    verity: Option<&Sha256HashValue>,
) -> Result<()> {
    let config = open_config_shallow(repo, name, verity)?;
    let Some(id) = config.get_config_annotation("containers.composefs.fsverity") else {
        bail!("Can only mount sealed containers");
    };
    repo.mount(id, mountpoint)
}

pub fn meta_layer(repo: &Repository, name: &str, verity: Option<&Sha256HashValue>) -> Result<()> {
    let (config, refs) = open_config(repo, name, verity)?;

    let ids = config.rootfs().diff_ids();
    if ids.len() >= 3 {
        let layer_sha256 = sha256_from_digest(&ids[ids.len() - 2])?;
        let layer_verity = refs.lookup(&layer_sha256).context("bzzt")?;
        repo.merge_splitstream(
            &hex::encode(layer_sha256),
            Some(layer_verity),
            &mut std::io::stdout(),
        )
    } else {
        bail!("No meta layer here");
    }
}

pub fn prepare_boot(
    repo: &Repository,
    name: &str,
    verity: Option<&Sha256HashValue>,
    output_dir: &Path,
) -> Result<()> {
    let (config, refs) = open_config(repo, name, verity)?;

    /* TODO: check created image ID against composefs label on container, if set */
    /* TODO: check created image ID against composefs= .cmdline in UKI or loader entry */
    crate::oci::image::create_image(repo, name, None, verity)?;

    /*
    let layer_digest = config
        .get_config_annotation("containers.composefs.attachments")
        .with_context(|| format!("Can't find attachments layer for container {name}"))?;
    let layer_sha256 = sha256_from_digest(layer_digest)?;
    */

    let ids = config.rootfs().diff_ids();
    ensure!(ids.len() >= 3, "No meta layer here");
    let layer_sha256 = sha256_from_digest(&ids[ids.len() - 2])?;
    let layer_verity = refs
        .lookup(&layer_sha256)
        .with_context(|| "Attachments layer {layer} is not connected to image {name}")?;

    // read the layer into a FileSystem object
    let mut filesystem = crate::image::FileSystem::new();
    let mut split_stream = repo.open_stream(&hex::encode(layer_sha256), Some(layer_verity))?;
    while let Some(entry) = tar::get_entry(&mut split_stream)? {
        image::process_entry(&mut filesystem, entry)?;
    }

    let boot = filesystem
        .root
        .get_directory("composefs-meta/boot".as_ref())?;

    write_to_path(repo, boot, output_dir)
}
