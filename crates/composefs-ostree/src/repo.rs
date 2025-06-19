use anyhow::{Context, Error, Result};
use configparser::ini::Ini;
use flate2::read::DeflateDecoder;
use gvariant::aligned_bytes::{AlignedBuf, AlignedSlice, A8};
use reqwest::{Client, Url};
use rustix::fs::{openat, Mode, OFlags};
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
};

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum RepoMode {
    Bare,
    Archive,
    BareUser,
    BareUserOnly,
    BareSplitXAttrs,
}

#[derive(Debug)]
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

/* This is how ostree stores gvariants on disk when used as a header for filez objects */
#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
struct SizedVariantHeader {
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
    ) -> impl Future<Output = Result<(AlignedBuf, ObjectID)>>;
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

    async fn fetch_file(&self, checksum: &Sha256Digest) -> Result<(AlignedBuf, ObjectID)> {
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

        let variant_header_size = size_of::<SizedVariantHeader>();
        let aligned: AlignedBuf = data[0..variant_header_size].to_vec().into();

        // Read variant size header
        let h = SizedVariantHeader::ref_from_bytes(&aligned)
            .map_err(|e| Error::msg(format!("Sized variant header: {:?}", e)))?;
        let file_header_size = u32::from_be(h.size) as usize;

        // Get file header
        let file_header = &data[variant_header_size..variant_header_size + file_header_size];
        let compressed_data = &data[variant_header_size + file_header_size..];

        // Decompress rest
        let mut uncompressed = DeflateDecoder::new(compressed_data);

        // TODO: Stream files into repo instead of reading it all

        let mut buffer = Vec::new();
        uncompressed.read_to_end(&mut buffer)?;

        let obj_id = self.repo.ensure_object(&buffer)?;

        Ok((file_header.to_vec().into(), obj_id))
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

    async fn fetch_file(&self, checksum: &Sha256Digest) -> Result<(AlignedBuf, ObjectID)> {
        let fd = self.open_object(checksum.into(), ObjectType::File)?;

        let mut file = File::from(fd);

        // Read variant size header
        let h = SizedVariantHeader::read_from_io(&mut file)?;
        let size = u32::from_be(h.size);

        // Read variant
        let mut v = vec![0u8; size as usize];
        file.read_exact(&mut v)?;

        // Decompress rest
        let mut rest = DeflateDecoder::new(file);

        // TODO: Stream files into repo instead of reading it all

        let mut buffer = Vec::new();
        rest.read_to_end(&mut buffer)?;

        let obj_id = self.repo.ensure_object(&buffer)?;

        Ok((v.into(), obj_id))
    }
}
