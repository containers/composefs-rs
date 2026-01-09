//! OCI container image support for composefs.
//!
//! This crate provides functionality for working with OCI (Open Container Initiative) container images
//! in the context of composefs. It enables importing, extracting, and mounting container images as
//! composefs filesystems with fs-verity integrity protection.
//!
//! Key functionality includes:
//! - Pulling container images from registries using skopeo
//! - Converting OCI image layers from tar format to composefs split streams
//! - Creating mountable filesystems from OCI image configurations
//! - Sealing containers with fs-verity hashes for integrity verification

pub mod image;
pub mod skopeo;
pub mod tar;

use std::{collections::HashMap, io::Read, sync::Arc};

use anyhow::{bail, ensure, Context, Result};
use containers_image_proxy::ImageProxyConfig;
use oci_spec::image::ImageConfiguration;
use sha2::{Digest, Sha256};

use composefs::{fsverity::FsVerityHashValue, repository::Repository};

use crate::skopeo::{OCI_CONFIG_CONTENT_TYPE, TAR_LAYER_CONTENT_TYPE};
use crate::tar::get_entry;

type ContentAndVerity<ObjectID> = (String, ObjectID);

fn layer_identifier(diff_id: &str) -> String {
    format!("oci-layer-{diff_id}")
}

fn config_identifier(config: &str) -> String {
    format!("oci-config-{config}")
}

/// Imports a container layer from a tar stream into the repository.
///
/// Converts the tar stream into a composefs split stream format and stores it in the repository.
/// If a name is provided, creates a reference to the imported layer for easier access.
///
/// Returns the fs-verity hash value of the stored split stream.
pub fn import_layer<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    diff_id: &str,
    name: Option<&str>,
    tar_stream: &mut impl Read,
) -> Result<ObjectID> {
    repo.ensure_stream(
        &layer_identifier(diff_id),
        TAR_LAYER_CONTENT_TYPE,
        |writer| tar::split(tar_stream, writer),
        name,
    )
}

/// Lists the contents of a container layer stored in the repository.
///
/// Reads the split stream for the named layer and prints each tar entry to stdout
/// in composefs dumpfile format.
pub fn ls_layer<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    diff_id: &str,
) -> Result<()> {
    let mut split_stream = repo.open_stream(
        &layer_identifier(diff_id),
        None,
        Some(TAR_LAYER_CONTENT_TYPE),
    )?;

    while let Some(entry) = get_entry(&mut split_stream)? {
        println!("{entry}");
    }

    Ok(())
}

/// Pull the target image, and add the provided tag. If this is a mountable
/// image (i.e. not an artifact), it is *not* unpacked by default.
pub async fn pull<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    imgref: &str,
    reference: Option<&str>,
    img_proxy_config: Option<ImageProxyConfig>,
) -> Result<(String, ObjectID)> {
    skopeo::pull(repo, imgref, reference, img_proxy_config).await
}

fn hash(bytes: &[u8]) -> String {
    let mut context = Sha256::new();
    context.update(bytes);
    format!("sha256:{}", hex::encode(context.finalize()))
}

/// Opens and parses a container configuration.
///
/// Reads the OCI image configuration from the repository and returns both the parsed
/// configuration and a digest map containing fs-verity hashes for all referenced layers.
///
/// If verity is provided, it's used directly. Otherwise, the name must be a sha256 digest
/// and the corresponding verity hash will be looked up (which is more expensive) and the content
/// will be hashed and compared to the provided digest.
///
/// Returns the parsed image configuration and the map of layer references.
///
/// Note: if the verity value is known and trusted then the layer fs-verity values can also be
/// trusted.  If not, then you can use the layer map to find objects that are ostensibly the layers
/// in question, but you'll have to verity their content hashes yourself.
pub fn open_config<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    config_digest: &str,
    verity: Option<&ObjectID>,
) -> Result<(ImageConfiguration, HashMap<Box<str>, ObjectID>)> {
    let mut stream = repo.open_stream(
        &config_identifier(config_digest),
        verity,
        Some(OCI_CONFIG_CONTENT_TYPE),
    )?;

    let config = if verity.is_none() {
        // No verity means we need to verify the content hash
        let mut data = vec![];
        stream.read_to_end(&mut data)?;
        ensure!(config_digest == hash(&data), "Data integrity issue");
        ImageConfiguration::from_reader(&data[..])?
    } else {
        ImageConfiguration::from_reader(&mut stream)?
    };

    Ok((config, stream.into_named_refs()))
}

/// Writes a container configuration to the repository.
///
/// Serializes the image configuration to JSON and stores it as a split stream with the
/// provided layer reference map. The configuration is stored inline since it's typically small.
///
/// Returns a tuple of (sha256 content hash, fs-verity hash value).
pub fn write_config<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    config: &ImageConfiguration,
    refs: HashMap<Box<str>, ObjectID>,
) -> Result<ContentAndVerity<ObjectID>> {
    let json = config.to_string()?;
    let json_bytes = json.as_bytes();
    let config_digest = hash(json_bytes);
    let mut stream = repo.create_stream(OCI_CONFIG_CONTENT_TYPE);
    for (name, value) in &refs {
        stream.add_named_stream_ref(name, value)
    }
    stream.write_inline(json_bytes);
    let id = repo.write_stream(stream, &config_identifier(&config_digest), None)?;
    Ok((config_digest, id))
}

/// Seals a container by computing its filesystem fs-verity hash and adding it to the config.
///
/// Creates the complete filesystem from all layers, computes its fs-verity hash, and stores
/// this hash in the container config labels under "containers.composefs.fsverity". This allows
/// the container to be mounted with integrity protection.
///
/// Returns a tuple of (sha256 content hash, fs-verity hash value) for the updated configuration.
pub fn seal<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    config_name: &str,
    config_verity: Option<&ObjectID>,
) -> Result<ContentAndVerity<ObjectID>> {
    let (mut config, refs) = open_config(repo, config_name, config_verity)?;
    let mut myconfig = config.config().clone().context("no config!")?;
    let labels = myconfig.labels_mut().get_or_insert_with(HashMap::new);
    let fs = crate::image::create_filesystem(repo, config_name, config_verity)?;
    let id = fs.compute_image_id();
    labels.insert("containers.composefs.fsverity".to_string(), id.to_hex());
    config.set_config(Some(myconfig));
    write_config(repo, &config, refs)
}

/// Mounts a sealed container filesystem at the specified mountpoint.
///
/// Reads the container configuration to extract the fs-verity hash from the
/// "containers.composefs.fsverity" label, then mounts the corresponding filesystem.
/// The container must have been previously sealed using `seal()`.
///
/// Returns an error if the container is not sealed or if mounting fails.
pub fn mount<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    name: &str,
    mountpoint: &str,
    verity: Option<&ObjectID>,
) -> Result<()> {
    let (config, _map) = open_config(repo, name, verity)?;
    let Some(id) = config.get_config_annotation("containers.composefs.fsverity") else {
        bail!("Can only mount sealed containers");
    };
    repo.mount_at(id, mountpoint)
}

#[cfg(test)]
mod test {
    use std::{fmt::Write, io::Read};

    use rustix::fs::CWD;
    use sha2::{Digest, Sha256};

    use composefs::{fsverity::Sha256HashValue, repository::Repository, test::tempdir};

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
        let layer_id = format!("sha256:{}", hex::encode(context.finalize()));

        let repo_dir = tempdir();
        let repo = Arc::new(Repository::<Sha256HashValue>::open_path(CWD, &repo_dir).unwrap());
        let id = import_layer(&repo, &layer_id, Some("name"), &mut layer.as_slice()).unwrap();

        let mut dump = String::new();
        let mut split_stream = repo.open_stream("refs/name", Some(&id), None).unwrap();
        while let Some(entry) = tar::get_entry(&mut split_stream).unwrap() {
            writeln!(dump, "{entry}").unwrap();
        }
        similar_asserts::assert_eq!(dump, "\
/file0 0 100700 1 0 0 0 0.0 - - -
/file4095 4095 100700 1 0 0 0 0.0 53/72beb83c78537c8970c8361e3254119fafdf1763854ecd57d3f0fe2da7c719 - 5372beb83c78537c8970c8361e3254119fafdf1763854ecd57d3f0fe2da7c719
/file4096 4096 100700 1 0 0 0 0.0 ba/bc284ee4ffe7f449377fbf6692715b43aec7bc39c094a95878904d34bac97e - babc284ee4ffe7f449377fbf6692715b43aec7bc39c094a95878904d34bac97e
/file4097 4097 100700 1 0 0 0 0.0 09/3756e4ea9683329106d4a16982682ed182c14bf076463a9e7f97305cbac743 - 093756e4ea9683329106d4a16982682ed182c14bf076463a9e7f97305cbac743
");
    }
}
