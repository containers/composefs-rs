use std::{cmp::Reverse, process::Command, thread::available_parallelism};

pub mod image;
pub mod tar;

use std::{collections::HashMap, io::Read, iter::zip, sync::Arc};

use anyhow::{bail, ensure, Context, Result};
use async_compression::tokio::bufread::{GzipDecoder, ZstdDecoder};
use containers_image_proxy::{ImageProxy, ImageProxyConfig, OpenedImage};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use oci_spec::image::{Descriptor, ImageConfiguration, ImageManifest, MediaType};
use sha2::{Digest, Sha256};
use tokio::{io::AsyncReadExt, sync::Semaphore};

use crate::{
    fsverity::FsVerityHashValue,
    oci::tar::{get_entry, split_async},
    repository::Repository,
    splitstream::DigestMap,
    util::{parse_sha256, Sha256Digest},
};

pub fn import_layer<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    sha256: &Sha256Digest,
    name: Option<&str>,
    tar_stream: &mut impl Read,
) -> Result<ObjectID> {
    repo.ensure_stream(sha256, |writer| tar::split(tar_stream, writer), name)
}

pub fn ls_layer<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    name: &str,
) -> Result<()> {
    let mut split_stream = repo.open_stream(name, None)?;

    while let Some(entry) = get_entry(&mut split_stream)? {
        println!("{}", entry);
    }

    Ok(())
}

struct ImageOp<ObjectID: FsVerityHashValue> {
    repo: Arc<Repository<ObjectID>>,
    proxy: ImageProxy,
    img: OpenedImage,
    progress: MultiProgress,
}

fn sha256_from_descriptor(descriptor: &Descriptor) -> Result<Sha256Digest> {
    let Some(digest) = descriptor.as_digest_sha256() else {
        bail!("Descriptor in oci config is not sha256");
    };
    Ok(parse_sha256(digest)?)
}

fn sha256_from_digest(digest: &str) -> Result<Sha256Digest> {
    match digest.strip_prefix("sha256:") {
        Some(rest) => Ok(parse_sha256(rest)?),
        None => bail!("Manifest has non-sha256 digest"),
    }
}

type ContentAndVerity<ObjectID> = (Sha256Digest, ObjectID);

impl<ObjectID: FsVerityHashValue> ImageOp<ObjectID> {
    async fn new(repo: &Arc<Repository<ObjectID>>, imgref: &str) -> Result<Self> {
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
                other => bail!("Unsupported layer media type {:?}", other),
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
pub async fn pull(
    repo: &Arc<Repository<impl FsVerityHashValue>>,
    imgref: &str,
    reference: Option<&str>,
) -> Result<()> {
    let op = Arc::new(ImageOp::new(repo, imgref).await?);
    let (sha256, id) = op
        .pull()
        .await
        .with_context(|| format!("Unable to pull container image {imgref}"))?;

    if let Some(name) = reference {
        repo.name_stream(sha256, name)?;
    }
    println!("sha256 {}", hex::encode(sha256));
    println!("verity {}", id.to_hex());
    Ok(())
}

pub fn open_config<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    name: &str,
    verity: Option<&ObjectID>,
) -> Result<(ImageConfiguration, DigestMap<ObjectID>)> {
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

fn hash(bytes: &[u8]) -> Sha256Digest {
    let mut context = Sha256::new();
    context.update(bytes);
    context.finalize().into()
}

pub fn open_config_shallow<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    name: &str,
    verity: Option<&ObjectID>,
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

pub fn write_config<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    config: &ImageConfiguration,
    refs: DigestMap<ObjectID>,
) -> Result<ContentAndVerity<ObjectID>> {
    let json = config.to_string()?;
    let json_bytes = json.as_bytes();
    let sha256 = hash(json_bytes);
    let mut stream = repo.create_stream(Some(sha256), Some(refs));
    stream.write_inline(json_bytes);
    let id = repo.write_stream(stream, None)?;
    Ok((sha256, id))
}

pub fn seal<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    config_name: &str,
    config_verity: Option<&ObjectID>,
) -> Result<ContentAndVerity<ObjectID>> {
    let (mut config, refs) = open_config(repo, config_name, config_verity)?;
    let mut myconfig = config.config().clone().context("no config!")?;
    let labels = myconfig.labels_mut().get_or_insert_with(HashMap::new);
    let mut fs = crate::oci::image::create_filesystem(repo, config_name, config_verity)?;
    let id = fs.compute_image_id();
    labels.insert("containers.composefs.fsverity".to_string(), id.to_hex());
    config.set_config(Some(myconfig));
    write_config(repo, &config, refs)
}

pub fn mount<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    name: &str,
    mountpoint: &str,
    verity: Option<&ObjectID>,
) -> Result<()> {
    let config = open_config_shallow(repo, name, verity)?;
    let Some(id) = config.get_config_annotation("containers.composefs.fsverity") else {
        bail!("Can only mount sealed containers");
    };
    repo.mount(id, mountpoint)
}

#[cfg(test)]
mod test {
    use std::{fmt::Write, io::Read};

    use rustix::fs::CWD;
    use sha2::{Digest, Sha256};

    use crate::{fsverity::Sha256HashValue, repository::Repository, test::tempdir};

    use super::*;

    fn append_data(builder: &mut ::tar::Builder<Vec<u8>>, name: &str, size: usize) {
        let mut header = ::tar::Header::new_ustar();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(0o700);
        header.set_entry_type(::tar::EntryType::Regular);
        header.set_size(size as u64);
        builder
            .append_data(&mut header, name, std::io::repeat(0u8).take(size as u64))
            .unwrap();
    }

    fn example_layer() -> Vec<u8> {
        let mut builder = ::tar::Builder::new(vec![]);
        append_data(&mut builder, "file0", 0);
        append_data(&mut builder, "file4095", 4095);
        append_data(&mut builder, "file4096", 4096);
        append_data(&mut builder, "file4097", 4097);
        builder.into_inner().unwrap()
    }

    #[test]
    fn test_layer() {
        let layer = example_layer();
        let mut context = Sha256::new();
        context.update(&layer);
        let layer_id: [u8; 32] = context.finalize().into();

        let repo_dir = tempdir();
        let repo = Arc::new(Repository::<Sha256HashValue>::open_path(CWD, &repo_dir).unwrap());
        let id = import_layer(&repo, &layer_id, Some("name"), &mut layer.as_slice()).unwrap();

        let mut dump = String::new();
        let mut split_stream = repo.open_stream("refs/name", Some(&id)).unwrap();
        while let Some(entry) = tar::get_entry(&mut split_stream).unwrap() {
            writeln!(dump, "{}", entry).unwrap();
        }
        similar_asserts::assert_eq!(dump, "\
/file0 0 100700 1 0 0 0 0.0 - - -
/file4095 4095 100700 1 0 0 0 0.0 53/72beb83c78537c8970c8361e3254119fafdf1763854ecd57d3f0fe2da7c719 - 5372beb83c78537c8970c8361e3254119fafdf1763854ecd57d3f0fe2da7c719
/file4096 4096 100700 1 0 0 0 0.0 ba/bc284ee4ffe7f449377fbf6692715b43aec7bc39c094a95878904d34bac97e - babc284ee4ffe7f449377fbf6692715b43aec7bc39c094a95878904d34bac97e
/file4097 4097 100700 1 0 0 0 0.0 09/3756e4ea9683329106d4a16982682ed182c14bf076463a9e7f97305cbac743 - 093756e4ea9683329106d4a16982682ed182c14bf076463a9e7f97305cbac743
");
    }
}
