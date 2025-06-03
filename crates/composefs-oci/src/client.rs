// Pull an OCI image using oci-client and zstd-chunked (if applicable)

use async_compression::tokio::bufread::{GzipDecoder, ZstdDecoder};
use std::{
    collections::HashMap,
    fmt,
    iter::zip,
    ops::Range,
    sync::Arc,
    sync::Mutex,
    thread,
    time::{Duration, Instant},
    pin::pin
};

use anyhow::{bail, ensure, Context, Result};
use async_stream::stream;
use bytes::Bytes;
use futures::{
    channel::oneshot,
    stream::{self, Stream, StreamExt, TryStreamExt},
    try_join,
};
use indicatif::{ProgressBar, ProgressStyle};
use oci_client::{
    client::{BlobResponse, ClientConfig},
    manifest::OciDescriptor,
    secrets::RegistryAuth,
    Client, Reference,
};
use oci_spec::image::ImageConfiguration;
use rustix::{
    buffer::spare_capacity,
    fs::{readlinkat, symlinkat},
    io::{read, Errno},
};
use tokio_util::io::StreamReader;
use zstd_chunked::{
    Chunk, ContentReference, MetadataReference, MetadataReferences, Stream as Metadata,
};

use crate::{sha256_from_digest, tar::split_async, ContentAndVerity};

use composefs::{
    fsverity::FsVerityHashValue, repository::Repository, splitstream::DigestMap, util::Sha256Digest,
};

// The Chameleon keeps track of how well the download is going.  Each byte successfully downloaded
// increases the karma by 1 and each network failure decreases it by 1.  The passage of time also
// decreases karma, with exponential decay.  This means that as long as progress is steady,
// even with really slow download speeds (think 10bytes/sec), we can tolerate a large number of
// network errors, but once we stop making forward progress and exponential decay sets in, our
// patience for errors decreases rapidly.  It also means that a single error at the start is
// immediately fatal, which feels correct.
struct Chameleon {
    // 🌈🦎📊
    karma: f64,
    updated: Instant,
}

impl Chameleon {
    fn get(&self, now: &Instant) -> f64 {
        // first order exponential decay, time constant = 1s (ie: drops to 36.79% after 1 sec)
        self.karma / now.duration_since(self.updated).as_secs_f64().exp()
    }

    fn update(&mut self, delta: impl Into<f64>) -> f64 {
        let now = Instant::now();
        self.karma = self.get(&now) + delta.into();
        self.updated = now;
        self.karma
    }
}

impl fmt::Debug for Chameleon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Chameleon {{ value: {}, updated: {:?} }} -> {}",
            self.karma,
            self.updated,
            self.get(&Instant::now())
        )
    }
}

impl Default for Chameleon {
    fn default() -> Self {
        Self {
            karma: 0.,
            updated: Instant::now(),
        }
    }
}

pub(super) struct PullOp<ObjectId: FsVerityHashValue> {
    repository: Arc<Repository<ObjectId>>,
    client: Client,
    image: Reference,
    progress: ProgressBar,
    karma: Mutex<Chameleon>, // could be RefCell but then PullOp isn't Send
}

async fn run_in_thread<T: Send + 'static>(
    f: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let (tx, rx) = oneshot::channel();
    thread::spawn(move || tx.send(f()));
    rx.await.context("Thread panicked or sender dropped")?
}

impl<ObjectId: FsVerityHashValue> PullOp<ObjectId> {
    async fn softfail(&self, err: impl Into<std::io::Error>) -> std::io::Result<()> {
        #[allow(clippy::unwrap_used)]
        if self.karma.lock().unwrap().update(-1.) < 0. {
            // Karma went negative: let the error bubble out.
            Err(err.into())
        } else {
            // Give it a second...
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        }
    }

    // To simplify progress tracking, if this function fails, the entire operation needs to be
    // aborted, so it tries really hard not to fail... it will also never download any byte that it
    // has already successfully received (ie: it will make the range request smaller before trying
    // again).
    fn stream_range<'a>(
        &self,
        desc: &'a OciDescriptor,
        range: &Range<u64>,
    ) -> impl Stream<Item = std::io::Result<Bytes>> + use<'_, 'a, ObjectId> {
        let (mut start, end) = (range.start, range.end);

        // https://github.com/rust-lang/rust/issues/43122
        stream! {
            'send_request: while start < end {
                let resp = match self
                    .client
                    .pull_blob_stream_partial(&self.image, desc, start, Some(end - start))
                    .await
                {
                    Ok(resp) => resp,
                    Err(err) => {
                        self.softfail(std::io::Error::other(err)).await?;
                        continue 'send_request;
                    }
                };

                // Maybe some servers would respond with a full request if we give the complete range
                // but let's wait until someone actually encounters that before we try to handle it...
                let BlobResponse::Partial(mut stream) = resp else {
                    yield Err(std::io::Error::other(anyhow::anyhow!("Server has no range support")));
                    return;
                };

                // Iterate over the stream of bytes...
                while let Some(result) = stream.next().await {
                    match result {
                        Ok(bytes) => {
                            let n_bytes = bytes.len() as u64;

                            #[allow(clippy::cast_precision_loss, clippy::unwrap_used)]
                            self.karma.lock().unwrap().update(n_bytes as f64);
                            self.progress.inc(n_bytes);
                            start += n_bytes;
                            yield Ok(bytes);
                        }
                        Err(err) => {
                            self.softfail(err).await?;
                            continue 'send_request;
                        }
                    }
                }
            }
        }
    }

    async fn download_range(&self, desc: &OciDescriptor, range: &Range<u64>) -> Result<Vec<u8>> {
        let stream = self.stream_range(desc, range);
        // TODO: find a better way...
        let bytes_vec: Vec<Bytes> = stream.try_collect().await?;
        let data: Vec<u8> = bytes_vec.into_iter().flatten().collect();
        Ok(data)
    }

    async fn download_all(&self, desc: &OciDescriptor) -> Result<Vec<u8>> {
        let everything = 0..desc.size.try_into()?;
        self.download_range(desc, &everything).await
    }

    async fn check_and_save(
        &self,
        digest: String,
        decompress: bool,
        mut data: Vec<u8>,
    ) -> Result<ObjectId> {
        let repository = Arc::clone(&self.repository);

        run_in_thread(move || {
            // decompressing here is slightly awkward but we want it in the thread
            if decompress {
                data = zstd::decode_all(&data[..])?;
            }

            // TODO: validate...
            let _ = digest;

            // TODO: put this in a more reasonable place...
            let id = repository.ensure_object(&data)?;
            match symlinkat(id.to_object_pathname(), repository.objects_dir()?, digest) {
                Ok(()) | Err(Errno::EXIST) => Ok(()),
                Err(err) => Err(err),
            }?;

            Ok(id)
        })
        .await
    }

    fn check_cached(&self, digest: &str) -> Result<Option<ObjectId>> {
        let dir = self.repository.objects_dir()?;
        match readlinkat(dir, digest, []) {
            Ok(path) => Ok(Some(ObjectId::from_object_pathname(path.as_bytes())?)),
            Err(Errno::NOENT) => Ok(None),
            Err(other) => Err(other.into()),
        }
    }

    fn read_object(&self, id: &ObjectId, size: u64) -> Result<Vec<u8>> {
        let mut data = Vec::with_capacity(size.try_into()?);
        read(self.repository.open_object(id)?, spare_capacity(&mut data))?;
        ensure!(data.len() as u64 == size, "Short read?");
        Ok(data)
    }

    fn read_cached(&self, digest: &str, size: u64) -> Result<Option<Vec<u8>>> {
        self.check_cached(digest)?
            .map(|id| self.read_object(&id, size))
            .transpose()
    }

    async fn download_metadata(
        &self,
        layer: &OciDescriptor,
        reference: &MetadataReference,
    ) -> Result<Vec<u8>> {
        if let Some(digest) = &reference.digest {
            if let Some(data) =
                self.read_cached(digest, reference.range.end - reference.range.start)?
            {
                self.progress.dec_length(data.len() as u64);
                return Ok(data);
            }
        }

        let result = self.download_range(layer, &reference.range).await?;

        if let Some(digest) = &reference.digest {
            // Caching metadata might not make sense for the "incremental updates" case (since it's
            // definitely going to be different next time) but it definitely makes sense from the
            // "bad network connection and my download got interrupted" case.
            self.check_and_save(digest.clone(), false, result.clone())
                .await?;
        }

        Ok(result)
    }

    async fn ensure_content(
        &self,
        layer: &OciDescriptor,
        reference: &ContentReference,
    ) -> Result<ObjectId> {
        if let Some(id) = self.check_cached(&reference.digest)? {
            self.progress
                .dec_length(reference.range.end - reference.range.start);
            Ok(id)
        } else {
            let result = self.download_range(layer, &reference.range).await?;
            self.check_and_save(reference.digest.clone(), true, result)
                .await
        }
    }

    async fn download_zstd_chunked_layer(
        &self,
        layer: &OciDescriptor,
        metadata: &MetadataReferences,
        diff_id: &str,
    ) -> Result<ObjectId> {
        let (manifest, tarsplit) = try_join!(
            self.download_metadata(layer, &metadata.manifest),
            self.download_metadata(layer, &metadata.tarsplit)
        )?;

        let stream = Metadata::new_from_frames(&manifest[..], &tarsplit[..])?;

        // Remove the parts of the file that we know we won't need (tar headers, etc.)
        // We get that by summing up the parts we do need and subtracting it from the total size.
        let already_accounted = (manifest.len() + tarsplit.len()) as u64;
        let needed: u64 = stream
            .references()
            .map(|r| r.range.end - r.range.start)
            .sum();
        let unneeded = TryInto::<u64>::try_into(layer.size)? - needed - already_accounted;
        self.progress.dec_length(unneeded);

        // Ensure all external references are in the repository and build an ObjectId map
        // Doing this pass first simplifies the async bookkeeping: we can use .buffer_unordered()
        // and collect the results as they come in instead of letting large jobs block the queue.
        let map: HashMap<String, ObjectId> = stream::iter(stream.references())
            .map(async move |reference| {
                let id = self.ensure_content(layer, reference).await?;
                Ok::<_, anyhow::Error>((reference.digest.clone(), id))
            })
            .buffer_unordered(100)
            .try_collect()
            .await?;

        let digest = sha256_from_digest(diff_id)?;
        let mut writer = self.repository.create_stream(Some(digest), None);
        for chunk in stream.chunks {
            match chunk {
                Chunk::Inline(data) => {
                    writer.write_inline(&data);
                }
                Chunk::External(reference) => {
                    // SAFETY: We downloaded and mapped all of the references above...
                    // We could actually avoid building the map if we relied on the sha256
                    // symlinks...
                    let id = &map[&reference.digest];

                    // Unfortunately we have to read the data here: we could build the splitstream
                    // using only our knowledge of the 'id' but we also need to take a body content
                    // sha256 of the entire .tar stream to ensure it matches the diff_id...
                    let data = self.read_object(id, reference.size)?;
                    writer.write_external(&data, vec![])?;
                }
            }
        }

        self.repository.write_stream(writer, None)
    }

    #[allow(clippy::unused_async)]
    async fn download_tar_layer(
        &self,
        layer: &OciDescriptor,
        diff_id: &Sha256Digest,
    ) -> Result<ObjectId> {
        // We need to use the layer descriptor to download the compressed layer but it gets
        // stored in the repository via the diff_id.  Our return value is the
        // fsverity digest for the corresponding splitstream.
        if let Some(layer_id) = self.repository.check_stream(diff_id)? {
            self.progress.dec_length(layer.size.try_into()?);
            Ok(layer_id)
        } else {
            // Otherwise, we need to fetch it...
            let stream = self.stream_range(layer, &(0..layer.size as u64));
            let reader = pin!(StreamReader::new(stream));

            let mut splitstream = self.repository.create_stream(Some(*diff_id), None);
            match layer.media_type.as_ref() {
                "application/vnd.oci.image.layer.v1.tar" => {
                    split_async(reader, &mut splitstream).await?;
                }
                "application/vnd.oci.image.layer.v1.tar+gzip" => {
                    split_async(GzipDecoder::new(reader), &mut splitstream).await?;
                }
                "application/vnd.oci.image.layer.v1.tar+zstd" => {
                    split_async(ZstdDecoder::new(reader), &mut splitstream).await?;
                }
                other => bail!("Unsupported layer media type {:?}", other),
            };

            self.repository.write_stream(splitstream, None)
        }
    }

    async fn download_layer(&self, layer: &OciDescriptor, diff_id: &str) -> Result<ObjectId> {
        let tar_digest = sha256_from_digest(diff_id)?;

        if let Some(metadata) = layer
            .annotations
            .as_ref()
            .and_then(|annotations| MetadataReferences::from_oci(|key| annotations.get(key)))
        {
            self.download_zstd_chunked_layer(layer, &metadata, diff_id)
                .await
        } else {
            self.download_tar_layer(layer, &tar_digest).await
        }
    }

    pub async fn ensure_config(
        &self,
        manifest_layers: &[OciDescriptor],
        descriptor: &OciDescriptor,
    ) -> Result<ContentAndVerity<ObjectId>> {
        let config_sha256 = sha256_from_digest(&descriptor.digest)?;
        if let Some(config_id) = self.repository.check_stream(&config_sha256)? {
            // We already got this config?  Nice.
            self.progress.println(format!(
                "Already have container config {}",
                hex::encode(config_sha256)
            ));
            self.progress.dec_length(descriptor.size as u64);
            for layer in manifest_layers {
                self.progress.dec_length(layer.size as u64);
            }
            Ok((config_sha256, config_id))
        } else {
            // We need to add the config to the repo.  We need to parse the config and make sure we
            // have all of the layers first.
            //
            self.progress
                .println(format!("Fetching config {}", hex::encode(config_sha256)));

            let raw_config = self.download_all(descriptor).await?;
            let config = ImageConfiguration::from_reader(&raw_config[..])?;

            let mut config_maps = DigestMap::new();
            let layers = zip(manifest_layers, config.rootfs().diff_ids());
            for (descriptor, diff_id) in layers {
                let layer_sha256 = sha256_from_digest(diff_id)?;
                let id = self.download_layer(descriptor, diff_id).await?;
                config_maps.insert(&layer_sha256, &id);
            }

            let mut splitstream = self
                .repository
                .create_stream(Some(config_sha256), Some(config_maps));
            splitstream.write_inline(&raw_config);
            let config_id = self.repository.write_stream(splitstream, None)?;

            Ok((config_sha256, config_id))
        }
    }

    pub(super) async fn pull(
        image: Reference,
        repository: Arc<Repository<ObjectId>>,
    ) -> Result<ContentAndVerity<ObjectId>> {
        let client = Client::new(ClientConfig {
            connect_timeout: Some(Duration::from_secs(1)),
            read_timeout: Some(Duration::from_secs(1)),
            ..Default::default()
        });

        // We don't bother accounting for this in our progress bar
        let (manifest, _) = client
            .pull_image_manifest(&image, &RegistryAuth::Anonymous)
            .await?;

        // But we do include the config
        let mut total: i64 = manifest.config.size;
        for layer in &manifest.layers {
            total += layer.size;
        }

        let progress = ProgressBar::new(total.try_into()?);
        progress.set_style(ProgressStyle::with_template(
            "[eta {eta}] {bar:40.cyan/blue} {decimal_bytes:>7}/{decimal_total_bytes:7} {decimal_bytes_per_sec} {msg}",
        )?);
        progress.enable_steady_tick(Duration::from_millis(100));

        let this = Self {
            repository,
            client,
            image,
            progress,
            karma: Chameleon::default().into(),
        };

        let id = this
            .ensure_config(&manifest.layers, &manifest.config)
            .await?;

        this.progress.finish();

        Ok(id)
    }
}
