use anyhow::{bail, Context, Error, Result};
use configparser::ini::Ini;
use flate2::read::DeflateDecoder;
use gvariant::aligned_bytes::{AlignedBuf, AlignedSlice, A8};
use gvariant::{gv, Marker, Structure};
use reqwest::{Client, Url};
use rustix::fs::{openat, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    future::Future,
    io::Read,
    os::fd::{AsFd, OwnedFd},
    path::Path,
    sync::Arc,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use composefs::{
    fsverity::FsVerityHashValue,
    repository::Repository,
    util::{parse_sha256, Sha256Digest},
    INLINE_CONTENT_MAX,
};

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum RepoMode {
    Bare,
    Archive,
    BareUser,
    BareUserOnly,
    BareSplitXAttrs,
}

#[derive(Debug, PartialEq)]
pub enum ObjectType {
    File,
    DirTree,
    DirMeta,
    Commit,
    TombstoneCommit,
    PayloadLink,
    FileXAttrs,
    FileXAttrsLink,
}

impl ObjectType {
    pub fn extension(&self, repo_mode: RepoMode) -> &'static str {
        match self {
            ObjectType::File => {
                if repo_mode == RepoMode::Archive {
                    ".filez"
                } else {
                    ".file"
                }
            }
            ObjectType::DirTree => ".dirtree",
            ObjectType::DirMeta => ".dirmeta",
            ObjectType::Commit => ".commit",
            ObjectType::TombstoneCommit => ".commit-tombstone",
            ObjectType::PayloadLink => ".payload-link",
            ObjectType::FileXAttrs => ".file-xattrs",
            ObjectType::FileXAttrsLink => ".file-xattrs-link",
        }
    }
}

impl RepoMode {
    pub fn parse(s: &str) -> Result<RepoMode> {
        match s {
            "bare" => Ok(RepoMode::Bare),
            "archive" => Ok(RepoMode::Archive),
            "archive-z2" => Ok(RepoMode::Archive),
            "bare-user" => Ok(RepoMode::BareUser),
            "bare-user-only" => Ok(RepoMode::BareUserOnly),
            "bare-split-xattrs" => Ok(RepoMode::BareSplitXAttrs),
            _ => Err(Error::msg(format!("Unsupported repo mode {}", s))),
        }
    }
}

/* Source for locally available data about ostree objects, typically
 * in-memory caches */
pub trait ObjectStore<ObjectID: FsVerityHashValue> {
    fn lookup_dirmeta(&self, _id: &Sha256Digest) -> Option<&AlignedSlice<A8>>;
    fn lookup_dirtree(&self, _id: &Sha256Digest) -> Option<&AlignedSlice<A8>>;
    fn lookup_file(&self, _id: &Sha256Digest) -> Option<(&AlignedSlice<A8>, &ObjectID)>;
}

fn get_object_pathname(mode: RepoMode, checksum: &Sha256Digest, object_type: ObjectType) -> String {
    format!(
        "{:02x}/{}{}",
        checksum[0],
        hex::encode(&checksum[1..]),
        object_type.extension(mode)
    )
}

fn size_prefix(data: &[u8]) -> AlignedBuf {
    let mut buf = AlignedBuf::new();
    let svh = SizedVariantHeader {
        size: u32::to_be(data.len() as u32),
        padding: 0,
    };
    buf.with_vec(|v| v.extend_from_slice(svh.as_bytes()));
    buf.with_vec(|v| v.extend_from_slice(data));
    buf
}

pub(crate) fn get_sized_variant_size(data: &[u8]) -> Result<usize> {
    let variant_header_size = size_of::<SizedVariantHeader>();
    if data.len() < variant_header_size {
        bail!("Sized variant too small");
    }

    let aligned: AlignedBuf = data[0..variant_header_size].to_vec().into();
    let h = SizedVariantHeader::ref_from_bytes(&aligned)
        .map_err(|e| Error::msg(format!("Sized variant header: {:?}", e)))?;
    Ok(u32::from_be(h.size) as usize)
}

pub(crate) fn split_sized_variant(data: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    let variant_size = get_sized_variant_size(data)?;
    let header_size = size_of::<SizedVariantHeader>();
    if data.len() < header_size + variant_size {
        bail!("Sized variant too small");
    }

    let sized_data = &data[0..header_size + variant_size];
    let variant_data = &data[header_size..header_size + variant_size];
    let remaining_data = &data[header_size + variant_size..];

    Ok((sized_data, variant_data, remaining_data))
}

pub(crate) fn ostree_zlib_file_header_to_regular(zlib_header_data: &AlignedSlice<A8>) -> Vec<u8> {
    let data = gv!("(tuuuusa(ayay))").cast(zlib_header_data);
    let (_size, uid, gid, mode, zero, symlink_target, xattrs_data) = data.to_tuple();
    let mut s = Vec::<(&[u8], &[u8])>::new();
    for x in xattrs_data.iter() {
        let (key, value) = x.to_tuple();
        s.push((key, value))
    }

    gv!("(uuuusa(ayay))").serialize_to_vec(&(*uid, *gid, *mode, *zero, symlink_target.to_str(), &s))
}

/* This is how ostree stores gvariants on disk when used as a header for filez objects */
#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub(crate) struct SizedVariantHeader {
    size: u32,
    padding: u32,
}

pub trait OstreeRepo<ObjectID: FsVerityHashValue> {
    fn fetch_object(
        &self,
        checksum: &Sha256Digest,
        object_type: ObjectType,
    ) -> impl Future<Output = Result<AlignedBuf>>;
    fn fetch_file(
        &self,
        checksum: &Sha256Digest,
    ) -> impl Future<Output = Result<(AlignedBuf, Option<ObjectID>)>>;
}

#[derive(Debug)]
pub struct RemoteRepo<ObjectID: FsVerityHashValue> {
    repo: Arc<Repository<ObjectID>>,
    client: Client,
    url: Url,
}

impl<ObjectID: FsVerityHashValue> RemoteRepo<ObjectID> {
    pub fn new(repo: &Arc<Repository<ObjectID>>, url: &str) -> Result<Self> {
        Ok(RemoteRepo {
            repo: repo.clone(),
            client: Client::new(),
            url: Url::parse(url)?,
        })
    }

    pub async fn resolve_ref(&self, ref_name: &str) -> Result<Sha256Digest> {
        // TODO: Support summary format
        let path = format!("refs/heads/{}", ref_name);
        let url = self.url.join(&path)?;

        let t = self
            .client
            .get(url.clone())
            .send()
            .await?
            .text()
            .await
            .with_context(|| format!("Cannot get ostree ref at {}", url))?;

        Ok(parse_sha256(&t.trim())?)
    }
}

impl<ObjectID: FsVerityHashValue> OstreeRepo<ObjectID> for RemoteRepo<ObjectID> {
    async fn fetch_object(
        &self,
        checksum: &Sha256Digest,
        object_type: ObjectType,
    ) -> Result<AlignedBuf> {
        let path = format!(
            "objects/{}",
            get_object_pathname(RepoMode::Archive, checksum, object_type)
        );
        let url = self.url.join(&path)?;

        let response = self.client.get(url.clone()).send().await?;
        response.error_for_status_ref()?;
        let b = response
            .bytes()
            .await
            .with_context(|| format!("Cannot get ostree object at {}", url))?;

        Ok(b.to_vec().into())
    }

    async fn fetch_file(&self, checksum: &Sha256Digest) -> Result<(AlignedBuf, Option<ObjectID>)> {
        let path = format!(
            "objects/{}",
            get_object_pathname(RepoMode::Archive, checksum, ObjectType::File)
        );
        let url = self.url.join(&path)?;

        let response = self.client.get(url.clone()).send().await?;
        response.error_for_status_ref()?;

        let data = response
            .bytes()
            .await
            .with_context(|| format!("Cannot get ostree file at {}", url))?;

        let (file_header, variant_data, compressed_data) = split_sized_variant(&data)?;

        // Force align the data as there is a gvariant-rs bug (https://github.com/ostreedev/gvariant-rs/pull/9)
        let mut aligned_variant_data = AlignedBuf::new();
        aligned_variant_data.with_vec(|v| v.extend_from_slice(variant_data));

        // Compute the checksum of (regular) header + data
        let mut hasher = Sha256::new();
        let regular_header = ostree_zlib_file_header_to_regular(&aligned_variant_data);
        let sized_regular_header = size_prefix(&regular_header);
        hasher.update(&*sized_regular_header);

        // Decompress rest
        let mut uncompressed = DeflateDecoder::new(compressed_data);

        // TODO: Stream files into repo instead of reading it all

        let mut file_content = Vec::new();
        uncompressed.read_to_end(&mut file_content)?;

        hasher.update(&file_content);
        let actual_checksum = hasher.finalize();
        if *actual_checksum != *checksum {
            bail!(
                "Unexpected file checksum {:?}, expected {:?}",
                actual_checksum,
                checksum
            );
        }

        let mut file_data = file_header.to_vec();
        let obj_id = if file_content.len() <= INLINE_CONTENT_MAX {
            file_data.extend_from_slice(&file_content);
            None
        } else {
            Some(self.repo.ensure_object(&file_content)?)
        };

        Ok((file_data.into(), obj_id))
    }
}

#[derive(Debug)]
pub struct LocalRepo<ObjectID: FsVerityHashValue> {
    repo: Arc<Repository<ObjectID>>,
    mode: RepoMode,
    dir: OwnedFd,
    objects: OwnedFd,
}

impl<ObjectID: FsVerityHashValue> LocalRepo<ObjectID> {
    pub fn open_path(
        repo: &Arc<Repository<ObjectID>>,
        dirfd: impl AsFd,
        path: impl AsRef<Path>,
    ) -> Result<Self> {
        let path = path.as_ref();
        let repofd = openat(
            &dirfd,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("Cannot open ostree repository at {}", path.display()))?;

        let configfd = openat(
            &repofd,
            "config",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("Cannot open ostree repo config file at {}", path.display()))?;

        let mut config_data = String::new();

        File::from(configfd)
            .read_to_string(&mut config_data)
            .with_context(|| format!("Can't read config file"))?;

        let mut config = Ini::new();
        let map = config
            .read(config_data)
            .map_err(Error::msg)
            .with_context(|| format!("Can't read config file"))?;

        let core = if let Some(core_map) = map.get("core") {
            core_map
        } else {
            return Err(Error::msg(format!("No [core] section in config")));
        };

        let mode = if let Some(Some(mode)) = core.get("mode") {
            RepoMode::parse(mode)?
        } else {
            return Err(Error::msg(format!("No mode in [core] section in config")));
        };

        if mode != RepoMode::Archive {
            return Err(Error::msg(format!("Unsupported repo mode {mode:?}")));
        }

        let objectsfd = openat(
            &repofd,
            "objects",
            OFlags::PATH | OFlags::CLOEXEC | OFlags::DIRECTORY,
            0o666.into(),
        )
        .with_context(|| {
            format!(
                "Cannot open ostree repository objects directory at {}",
                path.display()
            )
        })?;

        Ok(Self {
            repo: repo.clone(),
            mode: mode,
            dir: repofd,
            objects: objectsfd,
        })
    }

    pub fn open_object(&self, checksum: &Sha256Digest, object_type: ObjectType) -> Result<OwnedFd> {
        let cs = checksum.into();
        let path = get_object_pathname(self.mode, cs, object_type);

        openat(
            &self.objects,
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("Cannot open ostree objects object at {}", path))
    }

    pub fn read_ref(&self, ref_name: &str) -> Result<Sha256Digest> {
        let path = format!("refs/heads/{}", ref_name);

        let fd = openat(
            &self.dir,
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("Cannot open ostree ref at {}", path))?;

        let mut buffer = String::new();
        File::from(fd)
            .read_to_string(&mut buffer)
            .with_context(|| format!("Can't read ref file"))?;

        Ok(parse_sha256(&buffer.trim())?)
    }
}

impl<ObjectID: FsVerityHashValue> OstreeRepo<ObjectID> for LocalRepo<ObjectID> {
    async fn fetch_object(
        &self,
        checksum: &Sha256Digest,
        object_type: ObjectType,
    ) -> Result<AlignedBuf> {
        let fd = self.open_object(checksum.into(), object_type)?;

        let mut buffer = Vec::new();
        File::from(fd).read_to_end(&mut buffer)?;
        Ok(buffer.into())
    }

    async fn fetch_file(&self, checksum: &Sha256Digest) -> Result<(AlignedBuf, Option<ObjectID>)> {
        let fd = self.open_object(checksum.into(), ObjectType::File)?;
        let mut file = File::from(fd);

        let mut header_buf = Vec::<u8>::new();

        // Read variant size header
        let header_size = size_of::<SizedVariantHeader>();
        header_buf.resize(header_size, 0u8);
        file.read_exact(&mut header_buf)?;

        // Read variant
        let variant_size = get_sized_variant_size(&header_buf)?;
        header_buf.resize(header_size + variant_size, 0u8);
        file.read_exact(&mut header_buf[header_size..])?;

        // Force align the data as there is a gvariant-rs bug (https://github.com/ostreedev/gvariant-rs/pull/9)
        let mut aligned_variant_data = AlignedBuf::new();
        aligned_variant_data.with_vec(|v| v.extend_from_slice(&header_buf[header_size..]));

        // Compute the checksum of (regular) header + data
        let mut hasher = Sha256::new();
        let regular_header = ostree_zlib_file_header_to_regular(&aligned_variant_data);
        let sized_regular_header = size_prefix(&regular_header);
        hasher.update(&*sized_regular_header);

        // Decompress rest
        let mut rest = DeflateDecoder::new(file);

        // TODO: Stream files into repo instead of reading it all
        let mut file_content = Vec::new();
        rest.read_to_end(&mut file_content)?;
        hasher.update(&file_content);

        // Ensure matching checksum
        let actual_checksum = hasher.finalize();
        if *actual_checksum != *checksum {
            bail!(
                "Unexpected file checksum {}, expected {}",
                hex::encode(actual_checksum),
                hex::encode(checksum)
            );
        }

        let obj_id = if file_content.len() <= INLINE_CONTENT_MAX {
            header_buf.extend_from_slice(&file_content);
            None
        } else {
            Some(self.repo.ensure_object(&file_content)?)
        };

        Ok((header_buf.into(), obj_id))
    }
}
