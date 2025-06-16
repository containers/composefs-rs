/* Implementation of the ostree commit splitstream file format.
 *
 */
use anyhow::{Error, Result};
use gvariant::aligned_bytes::{AlignedBuf, AlignedSlice, AsAligned, TryAsAligned, A8};
use gvariant::{gv, Marker, Structure};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, collections::HashSet, ffi::OsStr, os::unix::ffi::OsStrExt};
use std::{
    fmt,
    io::Read,
    sync::Arc,
};
use composefs::{
    fsverity::FsVerityHashValue,
    repository::Repository,
    tree::{Directory, FileSystem, Inode, Leaf, LeafContent, RegularFile, Stat},
    util::Sha256Digest,
};

use crate::objmap::{ObjectMapBuilder, ObjectMapImage};
use crate::repo::{ObjectType, OstreeRepo};

pub const COMMIT_CONTENT_TYPE : u64 = 0xc72d30f121a31936;

const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000;

#[derive(Debug)]
pub struct OstreeCommit<ObjectID: FsVerityHashValue> {
    data: AlignedBuf,
    objmap: ObjectMapImage<ObjectID>,
}

impl<ObjectID: FsVerityHashValue> OstreeCommit<ObjectID> {
    pub fn load(repo: &Repository<ObjectID>, commit_name: &str) -> Result<Self> {
        let mut commit_stream = repo.open_stream(commit_name, None, Some(COMMIT_CONTENT_TYPE))?;
        let mut buffer = Vec::new();
        commit_stream.read_to_end(&mut buffer)?;

        // TODO: Currently we first store the reference to the objmap
        // with the remaining data. This is not great as it causes the
        // sha256 of the commit splitstream to not match the ostree
        // commit id

        let (objmap_id, rest) = ObjectID::read_from_prefix(&buffer)
            .map_err(|_e| Error::msg(format!("Invalid  objects")))?;


        let objmap = ObjectMapImage::<ObjectID>::load(repo, &objmap_id)?;

        Ok(OstreeCommit {
            data: rest.to_vec().into(),
            objmap: objmap,
        })
    }

    fn get_commit(&self) -> &AlignedSlice<A8> {
        &self.data
    }

    fn create_filesystem_file(&self, id: &Sha256Digest) -> Result<Leaf<ObjectID>> {
        let (maybe_obj_id, file_header) = self.objmap.lookup(id.into()).ok_or(Error::msg(format!(
            "Unexpectedly missing id {}",
            hex::encode(id)
        )))?;

        let data = gv!("(tuuuusa(ayay))").cast(file_header.try_as_aligned()?);
        let (size, uid, gid, mode, _zero, symlink_target, xattrs_data) = data.to_tuple();
        let mut xattrs = BTreeMap::<Box<OsStr>, Box<[u8]>>::new();
        for x in xattrs_data.iter() {
            let (key, value) = x.to_tuple();
            xattrs.insert(OsStr::from_bytes(key).into(), Box::from(value));
        }

        let stat = Stat {
            st_mode: u32::from_be(*mode),
            st_uid: u32::from_be(*uid),
            st_gid: u32::from_be(*gid),
            st_mtim_sec: 0,
            xattrs: xattrs.into(),
        };

        let content = if (stat.st_mode & S_IFMT) == S_IFLNK {
            LeafContent::Symlink(OsStr::new(symlink_target.to_str()).into())
        } else {
            let obj_id = maybe_obj_id.ok_or(
                Error::msg(format!("No object id reference for file object")))?;
            let file = RegularFile::External(obj_id.clone(), u64::from_be(*size));
            LeafContent::Regular(file)
        };

        Ok(Leaf { stat, content })
    }

    fn create_filesystem_dir(
        &self,
        dirtree_id: &Sha256Digest,
        dirmeta_id: &Sha256Digest,
    ) -> Result<Directory<ObjectID>> {
        let (_obj_id, dirmeta) = self.objmap.lookup(dirmeta_id.into()).ok_or(Error::msg(format!(
            "Unexpectedly missing dirmeta {}",
            hex::encode(dirmeta_id)
        )))?;
        let (_obj_id, dirtree) = self.objmap.lookup(dirtree_id.into()).ok_or(Error::msg(format!(
            "Unexpectedly missing dirtree {}",
            hex::encode(dirtree_id)
        )))?;

        let data = gv!("(uuua(ayay))").cast(dirmeta.try_as_aligned().unwrap());
        let (uid, gid, mode, xattrs_data) = data.to_tuple();
        let mut xattrs = BTreeMap::<Box<OsStr>, Box<[u8]>>::new();
        for x in xattrs_data.iter() {
            let (key, value) = x.to_tuple();
            xattrs.insert(OsStr::from_bytes(key).into(), Box::from(value));
        }

        let stat = Stat {
            st_mode: u32::from_be(*mode),
            st_uid: u32::from_be(*uid),
            st_gid: u32::from_be(*gid),
            st_mtim_sec: 0,
            xattrs: xattrs.into(),
        };

        let mut directory = Directory::new(stat);

        let tree_data = gv!("(a(say)a(sayay))").cast(dirtree.as_aligned());
        let (files_data, dirs_data) = tree_data.to_tuple();

        for f in files_data.iter() {
            let (name, checksum) = f.to_tuple();

            let file = self.create_filesystem_file(checksum.try_into()?)?;
            directory.insert(OsStr::new(name.to_str()), Inode::Leaf(file.into()));
        }

        for d in dirs_data.iter() {
            let (name, tree_checksum, meta_checksum) = d.to_tuple();

            let subdir =
                self.create_filesystem_dir(tree_checksum.try_into()?, meta_checksum.try_into()?)?;

            directory.insert(
                OsStr::new(name.to_str()),
                Inode::Directory(Box::new(subdir)),
            );
        }

        Ok(directory)
    }

    pub fn create_filesystem(&self) -> Result<FileSystem<ObjectID>> {
        let commit = self.get_commit();

        let data = gv!("(a{sv}aya(say)sstayay)").cast(&commit);
        let (
            _metadata_data,
            _parent_checksum,
            _related_objects,
            _subject,
            _body,
            _timestamp,
            root_tree,
            root_metadata,
        ) = data.to_tuple();

        let root = self.create_filesystem_dir(root_tree.try_into()?, root_metadata.try_into()?)?;

        Ok(FileSystem::<ObjectID> {
            root: root,
            have_root_stat: true,
        })
    }

    fn lookup_dirmeta(&self, id: &Sha256Digest) -> Option<&AlignedSlice<A8>> {
        if let Some((None, data)) = self.objmap.lookup(id) {
            Some(data.try_as_aligned().unwrap())
        } else {
            None
        }
    }

    fn lookup_dirtree(&self, id: &Sha256Digest) -> Option<&AlignedSlice<A8>> {
        if let Some((None, data)) = self.objmap.lookup(id) {
            Some(data.try_as_aligned().unwrap())
        } else {
            None
        }
    }

    fn lookup_file(&self, id: &Sha256Digest) -> Option<(&AlignedSlice<A8>, &ObjectID)> {
        if let Some((Some(objectid), data)) = self.objmap.lookup(id) {
            Some((data.try_as_aligned().unwrap(), objectid))
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct OstreeCommitBuilder<ObjectID: FsVerityHashValue> {
    repo: Arc<Repository<ObjectID>>,
    objmap: ObjectMapBuilder<ObjectID>,
    _commit_id: Option<Sha256Digest>,
    commit: Option<AlignedBuf>,
}

impl<ObjectID: FsVerityHashValue> OstreeCommitBuilder<ObjectID> {
    pub fn new(repo: &Arc<Repository<ObjectID>>) -> Self {
        OstreeCommitBuilder {
            repo: repo.clone(),
            commit: None,
            _commit_id: None,
            objmap: ObjectMapBuilder::<ObjectID>::new(),
        }
    }

    fn serialize_objmap(&self) -> Result<ObjectID> {
        let objmap_data = self.objmap.serialize()?;

        self.repo.ensure_object(&objmap_data)
    }

    fn serialize_commit(&self, commit: &AlignedBuf, objmap_id: &ObjectID) -> Result<Vec<u8>> {
        // TODO: We don't want to store objmap_id here, as it makes the sha256 not match the commit data
        let mut buf = Vec::new();
        buf.extend_from_slice(objmap_id.as_bytes());
        buf.extend_from_slice(&commit);
        Ok(buf)
    }

    pub fn ensure_commit(&self) -> Result<(Sha256Digest, ObjectID)> {
        let commit = self
            .commit
            .as_ref()
            .ok_or(Error::msg("No commit was pulled"))?;

        let objmap_id = self.serialize_objmap()?;

        let serialized_commit = self.serialize_commit(commit, &objmap_id)?;

        // TODO: Due to the objmap id we can't use self._commit_id here
        let sha256 : Sha256Digest = Sha256::digest(&serialized_commit).into();

        let mut stream = self.repo.create_stream(COMMIT_CONTENT_TYPE, Some(sha256));

        stream.add_external_reference(&objmap_id);
        for (_mapped_id, maybe_obj_id, _) in self.objmap.iter() {
            if let Some(obj_id) = maybe_obj_id {
                stream.add_external_reference(obj_id);
            }
        }

        stream.write_inline(&serialized_commit);
        let object_id = self.repo.write_stream(stream, None)?;

        Ok((sha256, object_id))
    }

    fn insert_dirmeta(&mut self, id: &Sha256Digest, data: Vec<u8>) {
        self.objmap.insert(id, None, data.to_vec());
    }

    fn insert_dirtree(&mut self, id: &Sha256Digest, data: Vec<u8>) {
        self.objmap.insert(id, None, data.to_vec());
    }

    fn insert_file(&mut self, id: &Sha256Digest, obj_id: &ObjectID, file_header: AlignedBuf) {
        self.objmap.insert(id, Some(obj_id), file_header.to_vec());
    }
}

struct Outstanding {
    id: Sha256Digest,
    obj_type: ObjectType,
}

impl fmt::Debug for Outstanding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Outstanding")
            .field("id", &hex::encode(self.id))
            .field("obj_type", &self.obj_type)
            .finish()
    }
}

#[derive(Debug)]
pub struct PullOperation<ObjectID: FsVerityHashValue, RepoType: OstreeRepo<ObjectID>> {
    repo: Arc<Repository<ObjectID>>,
    builder: OstreeCommitBuilder<ObjectID>,
    ostree_repo: RepoType,
    base_commits: Vec<OstreeCommit<ObjectID>>,
    outstanding: Vec<Outstanding>,
    // All ids that were ever enqueued (including already fetched and currently being fetched)
    fetched: HashSet<Sha256Digest>,
}

impl<ObjectID: FsVerityHashValue, RepoType: OstreeRepo<ObjectID>>
    PullOperation<ObjectID, RepoType>
{
    pub fn new(repo: &Arc<Repository<ObjectID>>, ostree_repo: RepoType) -> Self {
        PullOperation {
            repo: repo.clone(),
            builder: OstreeCommitBuilder::<ObjectID>::new(repo),
            ostree_repo: ostree_repo,
            outstanding: Vec::new(),
            base_commits: vec![],
            fetched: HashSet::new(),
        }
    }

    pub fn add_base(&mut self, base_name: &str) -> Result<()> {
        let base = OstreeCommit::<ObjectID>::load(&self.repo, base_name)?;
        self.base_commits.push(base);
        Ok(())
    }

    fn enqueue_fetch(&mut self, id: &Sha256Digest, obj_type: ObjectType) {
        // To avoid fetching twice, even if the id is not in the outstanding list
        // (for example we may be currenly downloading it) we keep all ids we ever
        // fetch in a map
        if self.fetched.contains(id) {
            return;
        }
        self.fetched.insert(*id);
        self.outstanding.push(Outstanding {
            id: *id,
            obj_type: obj_type,
        });
    }

    fn maybe_fetch_file(&mut self, id: &Sha256Digest) {
        if self.builder.objmap.contains(id) {
            return;
        }

        for base in self.base_commits.iter() {
            if let Some((file_header, obj_id)) = base.lookup_file(id) {
                let o = obj_id.clone();
                self.add_file(id, &o, file_header.to_owned());
                return;
            }
        }

        self.enqueue_fetch(id, ObjectType::File);
    }

    fn add_file(&mut self, id: &Sha256Digest, obj_id: &ObjectID, file_header: AlignedBuf) {
        self.builder.insert_file(id, obj_id, file_header);
    }

    fn maybe_fetch_dirmeta(&mut self, id: &Sha256Digest) {
        if self.builder.objmap.contains(id) {
            return;
        }

        for base in self.base_commits.iter() {
            if let Some(dirmeta) = base.lookup_dirmeta(id) {
                self.add_dirmeta(id, dirmeta.to_owned());
                return;
            }
        }

        self.enqueue_fetch(id, ObjectType::DirMeta);
    }

    fn add_dirmeta(&mut self, id: &Sha256Digest, data: AlignedBuf) {
        self.builder.insert_dirmeta(id, data.to_vec());
    }

    fn maybe_fetch_dirtree(&mut self, id: &Sha256Digest) {
        if self.builder.objmap.contains(id) {
            return;
        }

        for base in self.base_commits.iter() {
            if let Some(dirtree) = base.lookup_dirtree(id) {
                self.add_dirtree(id, dirtree.to_owned());
                return;
            }
        }

        self.enqueue_fetch(id, ObjectType::DirTree);
    }

    fn add_dirtree(&mut self, id: &Sha256Digest, buf: AlignedBuf) {
        let data = gv!("(a(say)a(sayay))").cast(buf.as_aligned());
        let (files_data, dirs_data) = data.to_tuple();

        for f in files_data.iter() {
            let (_name, checksum) = f.to_tuple();

            self.maybe_fetch_file(checksum.try_into().unwrap());
        }

        for d in dirs_data.iter() {
            let (_name, tree_checksum, meta_checksum) = d.to_tuple();

            self.maybe_fetch_dirmeta(meta_checksum.try_into().unwrap());
            self.maybe_fetch_dirtree(tree_checksum.try_into().unwrap());
        }

        self.builder.insert_dirtree(id, buf.to_vec());
    }

    fn add_commit(&mut self, id: &Sha256Digest, commit: AlignedBuf) {
        let data = gv!("(a{sv}aya(say)sstayay)").cast(&commit);
        let (
            _metadata_data,
            _parent_checksum,
            _related_objects,
            _subject,
            _body,
            _timestamp,
            root_tree,
            root_metadata,
        ) = data.to_tuple();

        self.maybe_fetch_dirmeta(root_metadata.try_into().unwrap());
        self.maybe_fetch_dirtree(root_tree.try_into().unwrap());

        self.builder._commit_id = Some(*id);
        self.builder.commit = Some(commit);
    }

    pub async fn pull_commit(&mut self, commit_id: &Sha256Digest) -> Result<(Sha256Digest, ObjectID)> {
        self.enqueue_fetch(commit_id, ObjectType::Commit);

        // TODO: Support deltas

        // TODO: At least for http we should make parallel fetches
        while self.outstanding.len() > 0 {
            let fetch = self.outstanding.pop().unwrap();
            println!(
                "Fetching ostree {:?} object {} ",
                fetch.obj_type,
                hex::encode(fetch.id)
            );

            match fetch.obj_type {
                ObjectType::Commit => {
                    let data = self
                        .ostree_repo
                        .fetch_object(&fetch.id, fetch.obj_type)
                        .await?;
                    self.add_commit(&fetch.id, data);
                }
                ObjectType::DirMeta => {
                    let data = self
                        .ostree_repo
                        .fetch_object(&fetch.id, fetch.obj_type)
                        .await?;
                    self.add_dirmeta(&fetch.id, data);
                }
                ObjectType::DirTree => {
                    let data = self
                        .ostree_repo
                        .fetch_object(&fetch.id, fetch.obj_type)
                        .await?;
                    self.add_dirtree(&fetch.id, data);
                }
                ObjectType::File => {
                    let (file_header, obj_id) = self.ostree_repo.fetch_file(&fetch.id).await?;

                    // TODO: Should we special case header.size == 0, like for symlinks?
                    // TODO: Also, should we inline small files (and symlinks) anyways?

                    self.add_file(&fetch.id, &obj_id, file_header);
                }
                _ => {}
            }
        }

        self.builder.ensure_commit()
    }
}
