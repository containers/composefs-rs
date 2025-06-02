pub mod image;
pub mod skopeo;
pub mod tar;

use std::{collections::HashMap, io::Read, sync::Arc};

use anyhow::{bail, ensure, Context, Result};
use oci_spec::image::{Descriptor, ImageConfiguration};
use sha2::{Digest, Sha256};

use composefs::{
    fsverity::FsVerityHashValue,
    repository::Repository,
    splitstream::DigestMap,
    util::{parse_sha256, Sha256Digest},
};

use crate::tar::get_entry;

type ContentAndVerity<ObjectID> = (Sha256Digest, ObjectID);

pub(crate) fn sha256_from_descriptor(descriptor: &Descriptor) -> Result<Sha256Digest> {
    let Some(digest) = descriptor.as_digest_sha256() else {
        bail!("Descriptor in oci config is not sha256");
    };
    Ok(parse_sha256(digest)?)
}

pub(crate) fn sha256_from_digest(digest: &str) -> Result<Sha256Digest> {
    match digest.strip_prefix("sha256:") {
        Some(rest) => Ok(parse_sha256(rest)?),
        None => bail!("Manifest has non-sha256 digest"),
    }
}

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
) -> Result<(Sha256Digest, ObjectID)> {
    skopeo::pull(repo, imgref, reference).await
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
    let mut fs = crate::image::create_filesystem(repo, config_name, config_verity)?;
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
        let layer_id: [u8; 32] = context.finalize().into();

        let repo_dir = tempdir();
        let repo = Arc::new(Repository::<Sha256HashValue>::open_path(CWD, &repo_dir).unwrap());
        let id = import_layer(&repo, &layer_id, Some("name"), &mut layer.as_slice()).unwrap();

        let mut dump = String::new();
        let mut split_stream = repo.open_stream("refs/name", Some(&id)).unwrap();
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
