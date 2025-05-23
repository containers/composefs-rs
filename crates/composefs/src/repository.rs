use std::{
    collections::HashSet,
    ffi::CStr,
    fs::File,
    io::{Read, Write},
    os::fd::{AsFd, OwnedFd},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, ensure, Context, Result};
use once_cell::sync::OnceCell;
use rustix::{
    fs::{
        fdatasync, flock, linkat, mkdirat, open, openat, readlinkat, symlinkat, AtFlags, Dir,
        FileType, FlockOperation, Mode, OFlags, CWD,
    },
    io::{Errno, Result as ErrnoResult},
};
use sha2::{Digest, Sha256};

use crate::{
    fsverity::{
        compute_verity, enable_verity, ensure_verity_equal, measure_verity, FsVerityHashValue,
    },
    mount::mount_composefs_at,
    splitstream::{DigestMap, SplitStreamReader, SplitStreamWriter},
    util::{proc_self_fd, Sha256Digest},
};

/// Call openat() on the named subdirectory of "dirfd", possibly creating it first.
///
/// We assume that the directory will probably exist (ie: we try the open first), and on ENOENT, we
/// mkdirat() and retry.
fn ensure_dir_and_openat(dirfd: impl AsFd, filename: &str, flags: OFlags) -> ErrnoResult<OwnedFd> {
    match openat(
        &dirfd,
        filename,
        flags | OFlags::CLOEXEC | OFlags::DIRECTORY,
        0o666.into(),
    ) {
        Ok(file) => Ok(file),
        Err(Errno::NOENT) => match mkdirat(&dirfd, filename, 0o777.into()) {
            Ok(()) | Err(Errno::EXIST) => openat(
                dirfd,
                filename,
                flags | OFlags::CLOEXEC | OFlags::DIRECTORY,
                0o666.into(),
            ),
            Err(other) => Err(other),
        },
        Err(other) => Err(other),
    }
}

#[derive(Debug)]
pub struct Repository<ObjectID: FsVerityHashValue> {
    repository: OwnedFd,
    objects: OnceCell<OwnedFd>,
    _data: std::marker::PhantomData<ObjectID>,
}

impl<ObjectID: FsVerityHashValue> Drop for Repository<ObjectID> {
    fn drop(&mut self) {
        flock(&self.repository, FlockOperation::Unlock).expect("repository unlock failed");
    }
}

impl<ObjectID: FsVerityHashValue> Repository<ObjectID> {
    pub fn objects_dir(&self) -> ErrnoResult<&OwnedFd> {
        self.objects
            .get_or_try_init(|| ensure_dir_and_openat(&self.repository, "objects", OFlags::PATH))
    }

    pub fn open_path(dirfd: impl AsFd, path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();

        // O_PATH isn't enough because flock()
        let repository = openat(dirfd, path, OFlags::RDONLY | OFlags::CLOEXEC , Mode::empty())
            .with_context(|| format!("Cannot open composefs repository at {}", path.display()))?;

        flock(&repository, FlockOperation::LockShared)
            .context("Cannot lock composefs repository")?;

        Ok(Self {
            repository,
            objects: OnceCell::new(),
            _data: std::marker::PhantomData,
        })
    }

    pub fn open_user() -> Result<Self> {
        let home = std::env::var("HOME").with_context(|| "$HOME must be set when in user mode")?;

        Self::open_path(CWD, PathBuf::from(home).join(".var/lib/composefs"))
    }

    pub fn open_system() -> Result<Self> {
        Self::open_path(CWD, PathBuf::from("/sysroot/composefs".to_string()))
    }

    fn ensure_dir(&self, dir: impl AsRef<Path>) -> ErrnoResult<()> {
        mkdirat(&self.repository, dir.as_ref(), 0o755.into()).or_else(|e| match e {
            Errno::EXIST => Ok(()),
            _ => Err(e),
        })
    }

    pub async fn ensure_object_async(self: &Arc<Self>, data: Vec<u8>) -> Result<ObjectID> {
        let self_ = Arc::clone(self);
        tokio::task::spawn_blocking(move || self_.ensure_object(&data)).await?
    }

    pub fn ensure_object(&self, data: &[u8]) -> Result<ObjectID> {
        let dirfd = self.objects_dir()?;
        let id: ObjectID = compute_verity(data);

        let path = id.to_object_pathname();

        // the usual case is that the file will already exist
        match openat(
            dirfd,
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => {
                // measure the existing file to ensure that it's correct
                // TODO: try to replace file if it's broken?
                ensure_verity_equal(fd, &id)?;
                return Ok(id);
            }
            Err(Errno::NOENT) => {
                // in this case we'll create the file
            }
            Err(other) => {
                return Err(other).context("Checking for existing object in repository")?;
            }
        }

        let fd = ensure_dir_and_openat(dirfd, &id.to_object_dir(), OFlags::RDWR | OFlags::TMPFILE)?;
        let mut file = File::from(fd);
        file.write_all(data)?;
        fdatasync(&file)?;

        // We can't enable verity with an open writable fd, so re-open and close the old one.
        let ro_fd = open(proc_self_fd(&file), OFlags::RDONLY, Mode::empty())?;
        drop(file);

        enable_verity::<ObjectID>(&ro_fd).context("Enabling verity digest")?;
        ensure_verity_equal(&ro_fd, &id).context("Double-checking verity digest")?;

        match linkat(
            CWD,
            proc_self_fd(&ro_fd),
            dirfd,
            path,
            AtFlags::SYMLINK_FOLLOW,
        ) {
            Ok(()) => {}
            Err(Errno::EXIST) => {
                // TODO: strictly, we should measure the newly-appeared file
            }
            Err(other) => {
                return Err(other).context("Linking created object file");
            }
        }

        Ok(id)
    }

    fn open_with_verity(&self, filename: &str, expected_verity: &ObjectID) -> Result<OwnedFd> {
        let fd = self.openat(filename, OFlags::RDONLY)?;
        ensure_verity_equal(&fd, expected_verity)?;
        Ok(fd)
    }

    /// Creates a SplitStreamWriter for writing a split stream.
    /// You should write the data to the returned object and then pass it to .store_stream() to
    /// store the result.
    pub fn create_stream(
        self: &Arc<Self>,
        sha256: Option<Sha256Digest>,
        maps: Option<DigestMap<ObjectID>>,
    ) -> SplitStreamWriter<ObjectID> {
        SplitStreamWriter::new(self, maps, sha256)
    }

    fn format_object_path(id: &ObjectID) -> String {
        format!("objects/{}", id.to_object_pathname())
    }

    pub fn has_stream(&self, sha256: &Sha256Digest) -> Result<Option<ObjectID>> {
        let stream_path = format!("streams/{}", hex::encode(sha256));

        match readlinkat(&self.repository, &stream_path, []) {
            Ok(target) => {
                // NB: This is kinda unsafe: we depend that the symlink didn't get corrupted
                // we could also measure the verity of the destination object, but it doesn't
                // improve anything, since we don't know if it was the original one.
                //
                // One thing we *could* do here is to iterate the entire file and verify the sha256
                // content hash.  That would allow us to reestablish a solid link between
                // content-sha256 and verity digest.
                let bytes = target.as_bytes();
                ensure!(
                    bytes.starts_with(b"../"),
                    "stream symlink has incorrect prefix"
                );
                Ok(Some(ObjectID::from_object_pathname(bytes)?))
            }
            Err(Errno::NOENT) => Ok(None),
            Err(err) => Err(err)?,
        }
    }

    /// Basically the same as has_stream() except that it performs expensive verification
    pub fn check_stream(&self, sha256: &Sha256Digest) -> Result<Option<ObjectID>> {
        match self.openat(&format!("streams/{}", hex::encode(sha256)), OFlags::RDONLY) {
            Ok(stream) => {
                let measured_verity: ObjectID = measure_verity(&stream)?;
                let mut context = Sha256::new();
                let mut split_stream = SplitStreamReader::new(File::from(stream))?;

                // check the verity of all linked streams
                for entry in &split_stream.refs.map {
                    if self.check_stream(&entry.body)?.as_ref() != Some(&entry.verity) {
                        bail!("reference mismatch");
                    }
                }

                // check this stream
                split_stream.cat(&mut context, |id| -> Result<Vec<u8>> {
                    let mut data = vec![];
                    File::from(self.open_object(id)?).read_to_end(&mut data)?;
                    Ok(data)
                })?;
                if *sha256 != Into::<[u8; 32]>::into(context.finalize()) {
                    bail!("Content didn't match!");
                }

                Ok(Some(measured_verity))
            }
            Err(Errno::NOENT) => Ok(None),
            Err(err) => Err(err)?,
        }
    }

    pub fn write_stream(
        &self,
        writer: SplitStreamWriter<ObjectID>,
        reference: Option<&str>,
    ) -> Result<ObjectID> {
        let Some((.., ref sha256)) = writer.sha256 else {
            bail!("Writer doesn't have sha256 enabled");
        };
        let stream_path = format!("streams/{}", hex::encode(sha256));
        let object_id = writer.done()?;
        let object_path = Self::format_object_path(&object_id);
        self.ensure_symlink(&stream_path, &object_path)?;

        if let Some(name) = reference {
            let reference_path = format!("streams/refs/{name}");
            self.symlink(&reference_path, &stream_path)?;
        }

        Ok(object_id)
    }

    /// Assign the given name to a stream.  The stream must already exist.  After this operation it
    /// will be possible to refer to the stream by its new name 'refs/{name}'.
    pub fn name_stream(&self, sha256: Sha256Digest, name: &str) -> Result<()> {
        let stream_path = format!("streams/{}", hex::encode(sha256));
        let reference_path = format!("streams/refs/{name}");
        self.symlink(&reference_path, &stream_path)?;
        Ok(())
    }

    /// Ensures that the stream with a given SHA256 digest exists in the repository.
    ///
    /// This tries to find the stream by the `sha256` digest of its contents.  If the stream is
    /// already in the repository, the object ID (fs-verity digest) is read from the symlink.  If
    /// the stream is not already in the repository, a `SplitStreamWriter` is created and passed to
    /// `callback`.  On return, the object ID of the stream will be calculated and it will be
    /// written to disk (if it wasn't already created by someone else in the meantime).
    ///
    /// In both cases, if `reference` is provided, it is used to provide a fixed name for the
    /// object.  Any object that doesn't have a fixed reference to it is subject to garbage
    /// collection.  It is an error if this reference already exists.
    ///
    /// On success, the object ID of the new object is returned.  It is expected that this object
    /// ID will be used when referring to the stream from other linked streams.
    pub fn ensure_stream(
        self: &Arc<Self>,
        sha256: &Sha256Digest,
        callback: impl FnOnce(&mut SplitStreamWriter<ObjectID>) -> Result<()>,
        reference: Option<&str>,
    ) -> Result<ObjectID> {
        let stream_path = format!("streams/{}", hex::encode(sha256));

        let object_id = match self.has_stream(sha256)? {
            Some(id) => id,
            None => {
                let mut writer = self.create_stream(Some(*sha256), None);
                callback(&mut writer)?;
                let object_id = writer.done()?;

                let object_path = Self::format_object_path(&object_id);
                self.ensure_symlink(&stream_path, &object_path)?;
                object_id
            }
        };

        if let Some(name) = reference {
            let reference_path = format!("streams/refs/{name}");
            self.symlink(&reference_path, &stream_path)?;
        }

        Ok(object_id)
    }

    pub fn open_stream(
        &self,
        name: &str,
        verity: Option<&ObjectID>,
    ) -> Result<SplitStreamReader<File, ObjectID>> {
        let filename = format!("streams/{name}");

        let file = File::from(if let Some(verity_hash) = verity {
            self.open_with_verity(&filename, verity_hash)?
        } else {
            self.openat(&filename, OFlags::RDONLY)?
        });

        SplitStreamReader::new(file)
    }

    pub fn open_object(&self, id: &ObjectID) -> Result<OwnedFd> {
        self.open_with_verity(&Self::format_object_path(id), id)
    }

    pub fn merge_splitstream(
        &self,
        name: &str,
        verity: Option<&ObjectID>,
        stream: &mut impl Write,
    ) -> Result<()> {
        let mut split_stream = self.open_stream(name, verity)?;
        split_stream.cat(stream, |id| -> Result<Vec<u8>> {
            let mut data = vec![];
            File::from(self.open_object(id)?).read_to_end(&mut data)?;
            Ok(data)
        })?;

        Ok(())
    }

    /// this function is not safe for untrusted users
    pub fn write_image(&self, name: Option<&str>, data: &[u8]) -> Result<ObjectID> {
        let object_id = self.ensure_object(data)?;

        let object_path = Self::format_object_path(&object_id);
        let image_path = format!("images/{}", object_id.to_hex());

        self.ensure_symlink(&image_path, &object_path)?;

        if let Some(reference) = name {
            let ref_path = format!("images/refs/{reference}");
            self.symlink(&ref_path, &image_path)?;
        }

        Ok(object_id)
    }

    /// this function is not safe for untrusted users
    pub fn import_image<R: Read>(&self, name: &str, image: &mut R) -> Result<ObjectID> {
        let mut data = vec![];
        image.read_to_end(&mut data)?;
        self.write_image(Some(name), &data)
    }

    pub fn open_image(&self, name: &str) -> Result<OwnedFd> {
        let image = self.openat(&format!("images/{name}"), OFlags::RDONLY)?;

        if !name.contains("/") {
            // A name with no slashes in it is taken to be a sha256 fs-verity digest
            ensure_verity_equal(&image, &ObjectID::from_hex(name)?)?;
        }

        Ok(image)
    }

    pub fn mount(&self, name: &str, mountpoint: &str) -> Result<()> {
        let image = self.open_image(name)?;
        Ok(mount_composefs_at(
            image,
            name,
            self.objects_dir()?,
            mountpoint,
        )?)
    }

    pub fn symlink(&self, name: impl AsRef<Path>, target: impl AsRef<Path>) -> ErrnoResult<()> {
        let name = name.as_ref();

        let mut symlink_components = name.parent().unwrap().components().peekable();
        let mut target_components = target.as_ref().components().peekable();

        let mut symlink_ancestor = PathBuf::new();

        // remove common leading components
        while symlink_components.peek() == target_components.peek() {
            symlink_ancestor.push(symlink_components.next().unwrap());
            target_components.next().unwrap();
        }

        let mut relative = PathBuf::new();
        // prepend a "../" for each ancestor of the symlink
        // and create those ancestors as we do so
        for symlink_component in symlink_components {
            symlink_ancestor.push(symlink_component);
            self.ensure_dir(&symlink_ancestor)?;
            relative.push("..");
        }

        // now build the relative path from the remaining components of the target
        for target_component in target_components {
            relative.push(target_component);
        }

        symlinkat(relative, &self.repository, name)
    }

    pub fn ensure_symlink<P: AsRef<Path>>(&self, name: P, target: &str) -> ErrnoResult<()> {
        self.symlink(name, target).or_else(|e| match e {
            Errno::EXIST => Ok(()),
            _ => Err(e),
        })
    }

    fn read_symlink_hashvalue(dirfd: &OwnedFd, name: &CStr) -> Result<ObjectID> {
        let link_content = readlinkat(dirfd, name, [])?;
        Ok(ObjectID::from_object_pathname(link_content.to_bytes())?)
    }

    fn walk_symlinkdir(fd: OwnedFd, objects: &mut HashSet<ObjectID>) -> Result<()> {
        for item in Dir::read_from(&fd)? {
            let entry = item?;
            // NB: the underlying filesystem must support returning filetype via direntry
            // that's a reasonable assumption, since it must also support fsverity...
            match entry.file_type() {
                FileType::Directory => {
                    let filename = entry.file_name();
                    if filename != c"." && filename != c".." {
                        let dirfd = openat(&fd, filename, OFlags::RDONLY, Mode::empty())?;
                        Self::walk_symlinkdir(dirfd, objects)?;
                    }
                }
                FileType::Symlink => {
                    objects.insert(Self::read_symlink_hashvalue(&fd, entry.file_name())?);
                }
                _ => {
                    bail!("Unexpected file type encountered");
                }
            }
        }

        Ok(())
    }

    fn openat(&self, name: &str, flags: OFlags) -> ErrnoResult<OwnedFd> {
        // Unconditionally add CLOEXEC as we always want it.
        openat(
            &self.repository,
            name,
            flags | OFlags::CLOEXEC,
            Mode::empty(),
        )
    }

    fn gc_category(&self, category: &str) -> Result<HashSet<ObjectID>> {
        let mut objects = HashSet::new();

        let category_fd = self.openat(category, OFlags::RDONLY | OFlags::DIRECTORY)?;

        let refs = openat(
            &category_fd,
            "refs",
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )?;
        Self::walk_symlinkdir(refs, &mut objects)?;

        for item in Dir::read_from(&category_fd)? {
            let entry = item?;
            let filename = entry.file_name();
            if filename != c"refs" && filename != c"." && filename != c".." {
                if entry.file_type() != FileType::Symlink {
                    bail!("category directory contains non-symlink");
                }

                // TODO: we need to sort this out.  the symlink itself might be a sha256 content ID
                // (as for splitstreams), not an object/ to be preserved.
                continue;

                /*
                let mut value = Sha256HashValue::EMPTY;
                hex::decode_to_slice(filename.to_bytes(), &mut value)?;

                if !objects.contains(&value) {
                    println!("rm {}/{:?}", category, filename);
                }
                */
            }
        }

        Ok(objects)
    }

    pub fn objects_for_image(&self, name: &str) -> Result<HashSet<ObjectID>> {
        let image = self.open_image(name)?;
        let mut data = vec![];
        std::fs::File::from(image).read_to_end(&mut data)?;
        Ok(crate::erofs::reader::collect_objects(&data)?)
    }

    pub fn gc(&self) -> Result<()> {
        flock(&self.repository, FlockOperation::LockExclusive)?;

        let mut objects = HashSet::new();

        for ref object in self.gc_category("images")? {
            println!("{object:?} lives as an image");
            objects.insert(object.clone());
            objects.extend(self.objects_for_image(&object.to_hex())?);
        }

        for object in self.gc_category("streams")? {
            println!("{object:?} lives as a stream");
            objects.insert(object.clone());

            let mut split_stream = self.open_stream(&object.to_hex(), None)?;
            split_stream.get_object_refs(|id| {
                println!("   with {id:?}");
                objects.insert(id.clone());
            })?;
        }

        for first_byte in 0x0..=0xff {
            let dirfd = match self.openat(
                &format!("objects/{first_byte:02x}"),
                OFlags::RDONLY | OFlags::DIRECTORY,
            ) {
                Ok(fd) => fd,
                Err(Errno::NOENT) => continue,
                Err(e) => Err(e)?,
            };
            for item in Dir::new(dirfd)? {
                let entry = item?;
                let filename = entry.file_name();
                if filename != c"." && filename != c".." {
                    let id =
                        ObjectID::from_object_dir_and_basename(first_byte, filename.to_bytes())?;
                    if !objects.contains(&id) {
                        println!("rm objects/{first_byte:02x}/{filename:?}");
                    } else {
                        println!("# objects/{first_byte:02x}/{filename:?} lives");
                    }
                }
            }
        }

        Ok(flock(&self.repository, FlockOperation::LockShared)?) // XXX: finally { } ?
    }

    pub fn fsck(&self) -> Result<()> {
        Ok(())
    }
}
