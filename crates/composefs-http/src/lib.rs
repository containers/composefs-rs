//! HTTP-based download functionality for composefs splitstreams and objects.
//!
//! This crate provides an asynchronous downloader that can fetch splitstreams and their
//! referenced objects from HTTP servers. It handles recursive fetching of nested splitstream
//! references and verifies content integrity using fsverity checksums.

#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    sync::Arc,
};

use anyhow::{bail, Result};
use bytes::Bytes;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::{Client, Response, Url};
use sha2::{Digest, Sha256};
use tokio::task::JoinSet;

use composefs::{
    fsverity::FsVerityHashValue, repository::Repository, splitstream::SplitStreamReader,
};

struct Downloader<ObjectID: FsVerityHashValue> {
    client: Client,
    repo: Arc<Repository<ObjectID>>,
    url: Url,
}

impl<ObjectID: FsVerityHashValue> Downloader<ObjectID> {
    fn is_symlink(response: &Response) -> bool {
        let Some(content_type_header) = response.headers().get("Content-Type") else {
            return false;
        };

        let Ok(content_type) = content_type_header.to_str() else {
            return false;
        };

        ["text/x-symlink-target"].contains(&content_type)
    }

    async fn fetch(&self, dir: &str, name: &str) -> Result<(Bytes, bool)> {
        let object_url = self.url.join(dir)?.join(name)?;
        let request = self.client.get(object_url.clone()).build()?;
        let response = self.client.execute(request).await?;
        response.error_for_status_ref()?;
        let is_symlink = Self::is_symlink(&response);
        Ok((response.bytes().await?, is_symlink))
    }

    async fn ensure_object(&self, id: &ObjectID) -> Result<bool> {
        if self.repo.open_object(id).is_err() {
            let (data, _is_symlink) = self.fetch("objects/", &id.to_object_pathname()).await?;
            let actual_id = self.repo.ensure_object_async(data.into()).await?;
            if actual_id != *id {
                bail!("Downloaded {id:?} but it has fs-verity {actual_id:?}");
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn open_splitstream(&self, id: &ObjectID) -> Result<SplitStreamReader<ObjectID>> {
        SplitStreamReader::new(File::from(self.repo.open_object(id)?), None)
    }

    async fn ensure_stream(self: &Arc<Self>, name: &str) -> Result<(String, ObjectID)> {
        let progress = ProgressBar::new(2); // the first object gets "ensured" twice
        progress.set_style(
            ProgressStyle::with_template(
                "[eta {eta}] {bar:40.cyan/blue} Fetching {pos} / {len} splitstreams",
            )
            .unwrap()
            .progress_chars("##-"),
        );

        // Ideally we'll get a symlink, but we might get the data directly
        let (data, is_symlink) = self.fetch("streams/", name).await?;
        let my_id = if is_symlink {
            ObjectID::from_object_pathname(&data)?
        } else {
            self.repo.ensure_object(&data)?
        };
        progress.inc(1);

        let mut objects_todo = HashSet::new();

        // TODO: if 'name' looks sha256ish then we ought to use it instead of None?
        let mut splitstreams = HashMap::from([(my_id.clone(), None)]);
        let mut splitstreams_todo = vec![my_id.clone()];

        // Recursively fetch all splitstreams
        // TODO: make this parallel, at least the ensure_object() part...
        while let Some(id) = splitstreams_todo.pop() {
            // this is the slow part (downloads, writing to disk, etc.)
            if self.ensure_object(&id).await? {
                progress.inc(1);
            } else {
                progress.dec_length(1);
            }

            // this part is fast: it only touches the header
            let mut reader = self.open_splitstream(&id)?;
            for (body, verity) in reader.iter_named_refs() {
                match splitstreams.insert(verity.clone(), Some(body.to_string())) {
                    // This is the (normal) case if we encounter a splitstream we didn't see yet...
                    None => {
                        splitstreams_todo.push(verity.clone());
                        progress.inc_length(1);
                    }

                    // This is the case where we've already been asked to fetch this stream.  We'll
                    // verify the SHA-256 content hashes later (after we get all the objects) so we
                    // need to make sure that all referents of this stream agree on what that is.
                    Some(Some(previous)) => {
                        if previous != body {
                            bail!(
                                "Splitstream with verity {verity:?} has different body hashes {} and {}",
                                hex::encode(previous),
                                hex::encode(body)
                            );
                        }
                    }

                    // This case should really be absolutely impossible: the only None value we
                    // record is for the original stream, and if we somehow managed to get back
                    // there via object IDs (which we check on download) then it means someone
                    // managed to construct two self-referential content-addressed objects...
                    Some(None) => bail!("Splitstream attempts to include itself recursively"),
                }
            }

            // This part is medium-fast: it needs to iterate the entire stream
            reader.get_object_refs(|id| {
                if !splitstreams.contains_key(id) {
                    objects_todo.insert(id.clone());
                }
            })?;
        }

        progress.finish();

        let progress = ProgressBar::new(objects_todo.len() as u64);
        progress.set_style(
            ProgressStyle::with_template(
                "[eta {eta}] {bar:40.cyan/blue} Fetching {pos} / {len} objects",
            )
            .unwrap()
            .progress_chars("##-"),
        );

        // Fetch all the objects
        let mut set = JoinSet::<Result<bool>>::new();
        let mut iter = objects_todo.into_iter();

        // Queue up 100 initial requests
        // See SETTINGS_MAX_CONCURRENT_STREAMS in RFC 7540
        // We might actually want to increase this...
        for id in iter.by_ref().take(100) {
            let self_ = Arc::clone(self);
            set.spawn(async move { self_.ensure_object(&id).await });
        }

        // Collect results for tasks that finish.  For each finished task, add another (if there
        // are any).
        while let Some(result) = set.join_next().await {
            if result?? {
                // a download
                progress.inc(1);
            } else {
                // a not-download
                progress.dec_length(1);
            }

            if let Some(id) = iter.next() {
                let self_ = Arc::clone(self);
                set.spawn(async move { self_.ensure_object(&id).await });
            }
        }

        progress.finish();

        // Now that we have all of the objects, we can verify that the merged-content of each
        // splitstream corresponds to its claimed body content checksum, if any...
        let progress = ProgressBar::new(splitstreams.len() as u64);
        progress.set_style(
            ProgressStyle::with_template(
                "[eta {eta}] {bar:40.cyan/blue} Verifying {pos} / {len} splitstreams",
            )
            .unwrap()
            .progress_chars("##-"),
        );

        let mut my_sha256 = None;
        // TODO: This can definitely happen in parallel...
        for (id, expected_checksum) in splitstreams {
            let mut reader = self.open_splitstream(&id)?;
            let mut context = Sha256::new();
            reader.cat(&self.repo, &mut context)?;
            let measured_checksum = format!("sha256:{}", hex::encode(context.finalize()));

            if let Some(expected) = expected_checksum {
                if measured_checksum != expected {
                    bail!(
                        "Splitstream id {id:?} should have checksum {} but is actually {}",
                        hex::encode(expected),
                        hex::encode(measured_checksum)
                    );
                }
            }

            if id == my_id {
                my_sha256 = Some(measured_checksum);
            }

            progress.inc(1);
        }

        progress.finish();

        // We've definitely set this by now: `my_id` is in `splitstreams`.
        let my_sha256 = my_sha256.unwrap();

        Ok((my_sha256, my_id))
    }
}

/// Downloads a composefs splitstream and all its dependencies from an HTTP server.
///
/// This function fetches a named splitstream from the specified HTTP URL, recursively
/// downloads all referenced splitstreams and objects, and verifies their integrity using
/// fsverity checksums. Downloaded objects are stored in the provided repository.
///
/// # Parameters
///
/// * `url` - The base HTTP URL where the splitstream repository is hosted
/// * `name` - The name of the splitstream to download (located under `streams/` on the server)
/// * `repo` - The repository where downloaded objects will be stored
///
/// # Returns
///
/// Returns a tuple containing the SHA-256 digest of the splitstream's content and its
/// fsverity object ID.
///
/// # Errors
///
/// Returns an error if:
/// - The HTTP request fails or returns a non-success status
/// - Downloaded objects have mismatched fsverity checksums
/// - Splitstream references contain inconsistent content hashes
/// - Any I/O operation fails during object storage
pub async fn download<ObjectID: FsVerityHashValue>(
    url: &str,
    name: &str,
    repo: Arc<Repository<ObjectID>>,
) -> Result<(String, ObjectID)> {
    let downloader = Arc::new(Downloader {
        client: Client::new(),
        repo,
        url: Url::parse(url)?,
    });

    downloader.ensure_stream(name).await
}
