//! Content-addressable repository for composefs objects.
//!
//! This module provides a repository abstraction for storing and retrieving
//! content-addressed objects, splitstreams, and images with fs-verity
//! verification and garbage collection support.

use std::{
    collections::HashSet,
    ffi::CStr,
    fs::{canonicalize, File},
    io::{Read, Write},
    os::fd::{AsFd, OwnedFd},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, ensure, Context, Result};
use once_cell::sync::OnceCell;
use rustix::{
    fs::{
        flock, linkat, mkdirat, open, openat, readlinkat, statat, syncfs, AtFlags, Dir, FileType,
        FlockOperation, Mode, OFlags, CWD,
    },
    io::{Errno, Result as ErrnoResult},
};

use crate::{
    fsverity::{
        compute_verity, enable_verity_maybe_copy, ensure_verity_equal, measure_verity,
        CompareVerityError, EnableVerityError, FsVerityHashValue, MeasureVerityError,
    },
    mount::{composefs_fsmount, mount_at},
    splitstream::{SplitStreamReader, SplitStreamWriter},
    util::{proc_self_fd, replace_symlinkat, ErrnoFilter},
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

/// A content-addressable repository for composefs objects.
///
/// Stores content-addressed objects, splitstreams, and images with fsverity
/// verification. Objects are stored by their fsverity digest, streams by SHA256
/// content hash, and both support named references for persistence across
/// garbage collection.
#[derive(Debug)]
pub struct Repository<ObjectID: FsVerityHashValue> {
    repository: OwnedFd,
    objects: OnceCell<OwnedFd>,
    insecure: bool,
    _data: std::marker::PhantomData<ObjectID>,
}

impl<ObjectID: FsVerityHashValue> Drop for Repository<ObjectID> {
    fn drop(&mut self) {
        flock(&self.repository, FlockOperation::Unlock).expect("repository unlock failed");
    }
}

impl<ObjectID: FsVerityHashValue> Repository<ObjectID> {
    /// Return the objects directory.
    pub fn objects_dir(&self) -> ErrnoResult<&OwnedFd> {
        self.objects
            .get_or_try_init(|| ensure_dir_and_openat(&self.repository, "objects", OFlags::PATH))
    }

    /// Open a repository at the target directory and path.
    pub fn open_path(dirfd: impl AsFd, path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();

        // O_PATH isn't enough because flock()
        let repository = openat(dirfd, path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .with_context(|| format!("Cannot open composefs repository at {}", path.display()))?;

        flock(&repository, FlockOperation::LockShared)
            .context("Cannot lock composefs repository")?;

        Ok(Self {
            repository,
            objects: OnceCell::new(),
            insecure: false,
            _data: std::marker::PhantomData,
        })
    }

    /// Open the default user-owned composefs repository.
    pub fn open_user() -> Result<Self> {
        let home = std::env::var("HOME").with_context(|| "$HOME must be set when in user mode")?;

        Self::open_path(CWD, PathBuf::from(home).join(".var/lib/composefs"))
    }

    /// Open the default system-global composefs repository.
    pub fn open_system() -> Result<Self> {
        Self::open_path(CWD, PathBuf::from("/sysroot/composefs".to_string()))
    }

    fn ensure_dir(&self, dir: impl AsRef<Path>) -> ErrnoResult<()> {
        mkdirat(&self.repository, dir.as_ref(), 0o755.into()).or_else(|e| match e {
            Errno::EXIST => Ok(()),
            _ => Err(e),
        })
    }

    /// Asynchronously ensures an object exists in the repository.
    ///
    /// Same as `ensure_object` but runs the operation on a blocking thread pool
    /// to avoid blocking async tasks. Returns the fsverity digest of the object.
    ///
    /// For performance reasons, this function does *not* call fsync() or similar.  After you're
    /// done with everything, call `Repository::sync_async()`.
    pub async fn ensure_object_async(self: &Arc<Self>, data: Vec<u8>) -> Result<ObjectID> {
        let self_ = Arc::clone(self);
        tokio::task::spawn_blocking(move || self_.ensure_object(&data)).await?
    }

    /// Given a blob of data, store it in the repository.
    ///
    /// For performance reasons, this function does *not* call fsync() or similar.  After you're
    /// done with everything, call `Repository::sync()`.
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
                match ensure_verity_equal(&fd, &id) {
                    Ok(()) => {}
                    Err(CompareVerityError::Measure(MeasureVerityError::VerityMissing))
                        if self.insecure =>
                    {
                        match enable_verity_maybe_copy::<ObjectID>(dirfd, fd.as_fd()) {
                            Ok(Some(fd)) => ensure_verity_equal(&fd, &id)?,
                            Ok(None) => ensure_verity_equal(&fd, &id)?,
                            Err(other) => Err(other)?,
                        }
                    }
                    Err(CompareVerityError::Measure(
                        MeasureVerityError::FilesystemNotSupported,
                    )) if self.insecure => {}
                    Err(other) => Err(other)?,
                }
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
        // We can't enable verity with an open writable fd, so re-open and close the old one.
        let ro_fd = open(
            proc_self_fd(&file),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        // NB: We should do fdatasync() or fsync() here, but doing this for each file forces the
        // creation of a massive number of journal commits and is a performance disaster.  We need
        // to coordinate this at a higher level.  See .write_stream().
        drop(file);

        let ro_fd = match enable_verity_maybe_copy::<ObjectID>(dirfd, ro_fd.as_fd()) {
            Ok(maybe_fd) => {
                let ro_fd = maybe_fd.unwrap_or(ro_fd);
                match ensure_verity_equal(&ro_fd, &id) {
                    Ok(()) => ro_fd,
                    Err(CompareVerityError::Measure(
                        MeasureVerityError::VerityMissing
                        | MeasureVerityError::FilesystemNotSupported,
                    )) if self.insecure => ro_fd,
                    Err(other) => Err(other).context("Double-checking verity digest")?,
                }
            }
            Err(EnableVerityError::FilesystemNotSupported) if self.insecure => ro_fd,
            Err(other) => Err(other).context("Enabling verity digest")?,
        };

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
        match ensure_verity_equal(&fd, expected_verity) {
            Ok(()) => {}
            Err(CompareVerityError::Measure(
                MeasureVerityError::VerityMissing | MeasureVerityError::FilesystemNotSupported,
            )) if self.insecure => {}
            Err(other) => Err(other)?,
        }
        Ok(fd)
    }

    /// By default fsverity is required to be enabled on the target
    /// filesystem. Setting this disables verification of digests
    /// and an instance of [`Self`] can be used on a filesystem
    /// without fsverity support.
    pub fn set_insecure(&mut self, insecure: bool) -> &mut Self {
        self.insecure = insecure;
        self
    }

    /// Creates a SplitStreamWriter for writing a split stream.
    /// You should write the data to the returned object and then pass it to .store_stream() to
    /// store the result.
    pub fn create_stream(self: &Arc<Self>, content_type: u64) -> SplitStreamWriter<ObjectID> {
        SplitStreamWriter::new(self, content_type)
    }

    fn format_object_path(id: &ObjectID) -> String {
        format!("objects/{}", id.to_object_pathname())
    }

    fn format_stream_path(content_identifier: &str) -> String {
        format!("streams/{content_identifier}")
    }

    /// Check if the provided splitstream is present in the repository;
    /// if so, return its fsverity digest.
    pub fn has_stream(&self, content_identifier: &str) -> Result<Option<ObjectID>> {
        let stream_path = Self::format_stream_path(content_identifier);

        match readlinkat(&self.repository, &stream_path, []) {
            Ok(target) => {
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

    /// Write the given splitstream to the repository with the provided content identifier and
    /// optional reference name.
    ///
    /// This call contains an internal barrier that guarantees that, in event of a crash, either:
    ///  - the named stream (by `content_identifier`) will not be available; or
    ///  - the stream and all of its linked data will be available
    ///
    /// In other words: it will not be possible to boot a system which contained a stream named
    /// `content_identifier` but is missing linked streams or objects from that stream.
    pub fn write_stream(
        &self,
        writer: SplitStreamWriter<ObjectID>,
        content_identifier: &str,
        reference: Option<&str>,
    ) -> Result<ObjectID> {
        let object_id = writer.done()?;

        // Right now we have:
        //   - all of the linked external objects and streams; and
        //   - the binary data of this splitstream itself
        //
        // in the filesystem but but not yet guaranteed to be synced to disk.  This is OK because
        // nobody knows that the binary data of the splitstream is a splitstream yet: it could just
        // as well be a random data file contained in an OS image or something.
        //
        // We need to make sure that all of that makes it to the disk before the splitstream is
        // visible as a splitstream.
        self.sync()?;

        let stream_path = Self::format_stream_path(content_identifier);
        let object_path = Self::format_object_path(&object_id);
        self.symlink(&stream_path, &object_path)?;

        if let Some(name) = reference {
            let reference_path = format!("streams/refs/{name}");
            self.symlink(&reference_path, &stream_path)?;
        }

        Ok(object_id)
    }

    /// Check if a splitstream with a given name exists in the "refs" in the repository.
    pub fn has_named_stream(&self, name: &str) -> Result<bool> {
        let stream_path = format!("streams/refs/{name}");

        Ok(statat(&self.repository, &stream_path, AtFlags::empty())
            .filter_errno(Errno::NOENT)
            .context("Looking for stream {name} in repository")?
            .map(|s| FileType::from_raw_mode(s.st_mode).is_symlink())
            .unwrap_or(false))
    }

    /// Assign the given name to a stream.  The stream must already exist.  After this operation it
    /// will be possible to refer to the stream by its new name 'refs/{name}'.
    pub fn name_stream(&self, content_identifier: &str, name: &str) -> Result<()> {
        let stream_path = Self::format_stream_path(content_identifier);
        let reference_path = format!("streams/refs/{name}");
        self.symlink(&reference_path, &stream_path)?;
        Ok(())
    }

    /// Ensures that the stream with a given content identifier digest exists in the repository.
    ///
    /// This tries to find the stream by the content identifier.  If the stream is already in the
    /// repository, the object ID (fs-verity digest) is read from the symlink.  If the stream is
    /// not already in the repository, a `SplitStreamWriter` is created and passed to `callback`.
    /// On return, the object ID of the stream will be calculated and it will be written to disk
    /// (if it wasn't already created by someone else in the meantime).
    ///
    /// In both cases, if `reference` is provided, it is used to provide a fixed name for the
    /// object.  Any object that doesn't have a fixed reference to it is subject to garbage
    /// collection.  It is an error if this reference already exists.
    ///
    /// On success, the object ID of the new object is returned.  It is expected that this object
    /// ID will be used when referring to the stream from other linked streams.
    pub fn ensure_stream(
        self: &Arc<Self>,
        content_identifier: &str,
        content_type: u64,
        callback: impl FnOnce(&mut SplitStreamWriter<ObjectID>) -> Result<()>,
        reference: Option<&str>,
    ) -> Result<ObjectID> {
        let stream_path = Self::format_stream_path(content_identifier);

        let object_id = match self.has_stream(content_identifier)? {
            Some(id) => id,
            None => {
                let mut writer = self.create_stream(content_type);
                callback(&mut writer)?;
                self.write_stream(writer, content_identifier, reference)?
            }
        };

        if let Some(name) = reference {
            let reference_path = format!("streams/refs/{name}");
            self.symlink(&reference_path, &stream_path)?;
        }

        Ok(object_id)
    }

    /// Open a splitstream with the given name.
    pub fn open_stream(
        &self,
        content_identifier: &str,
        verity: Option<&ObjectID>,
        expected_content_type: Option<u64>,
    ) -> Result<SplitStreamReader<ObjectID>> {
        let file = File::from(if let Some(verity_hash) = verity {
            self.open_object(verity_hash)
                .with_context(|| format!("Opening object '{verity_hash:?}'"))?
        } else {
            let filename = Self::format_stream_path(content_identifier);
            self.openat(&filename, OFlags::RDONLY)
                .with_context(|| format!("Opening ref '{filename}'"))?
        });

        SplitStreamReader::new(file, expected_content_type)
    }

    /// Given an object identifier (a digest), return a read-only file descriptor
    /// for its contents. The fsverity digest is verified (if the repository is not in `insecure` mode).
    pub fn open_object(&self, id: &ObjectID) -> Result<OwnedFd> {
        self.open_with_verity(&Self::format_object_path(id), id)
    }

    /// Read the contents of an object into a Vec
    pub fn read_object(&self, id: &ObjectID) -> Result<Vec<u8>> {
        let mut data = vec![];
        File::from(self.open_object(id)?).read_to_end(&mut data)?;
        Ok(data)
    }

    /// Merges a splitstream into a single continuous stream.
    ///
    /// Opens the named splitstream, resolves all object references, and writes
    /// the complete merged content to the provided writer. Optionally verifies
    /// the splitstream's fsverity digest matches the expected value.
    pub fn merge_splitstream(
        &self,
        content_identifier: &str,
        verity: Option<&ObjectID>,
        expected_content_type: Option<u64>,
        output: &mut impl Write,
    ) -> Result<()> {
        let mut split_stream =
            self.open_stream(content_identifier, verity, expected_content_type)?;
        split_stream.cat(self, output)
    }

    /// Write `data into the repository as an image with the given `name`.
    ///
    /// The fsverity digest is returned.
    ///
    /// # Integrity
    ///
    /// This function is not safe for untrusted users.
    pub fn write_image(&self, name: Option<&str>, data: &[u8]) -> Result<ObjectID> {
        let object_id = self.ensure_object(data)?;

        let object_path = Self::format_object_path(&object_id);
        let image_path = format!("images/{}", object_id.to_hex());

        self.symlink(&image_path, &object_path)?;

        if let Some(reference) = name {
            let ref_path = format!("images/refs/{reference}");
            self.symlink(&ref_path, &image_path)?;
        }

        Ok(object_id)
    }

    /// Import the data from the provided read into the repository as an image.
    ///
    /// The fsverity digest is returned.
    ///
    /// # Integrity
    ///
    /// This function is not safe for untrusted users.
    pub fn import_image<R: Read>(&self, name: &str, image: &mut R) -> Result<ObjectID> {
        let mut data = vec![];
        image.read_to_end(&mut data)?;
        self.write_image(Some(name), &data)
    }

    /// Returns the fd of the image and whether or not verity should be
    /// enabled when mounting it.
    fn open_image(&self, name: &str) -> Result<(OwnedFd, bool)> {
        let image = self
            .openat(&format!("images/{name}"), OFlags::RDONLY)
            .with_context(|| format!("Opening ref 'images/{name}'"))?;

        if name.contains("/") {
            return Ok((image, true));
        }

        // A name with no slashes in it is taken to be a sha256 fs-verity digest
        match measure_verity::<ObjectID>(&image) {
            Ok(found) if found == FsVerityHashValue::from_hex(name)? => Ok((image, true)),
            Ok(_) => bail!("fs-verity content mismatch"),
            Err(MeasureVerityError::VerityMissing | MeasureVerityError::FilesystemNotSupported)
                if self.insecure =>
            {
                Ok((image, false))
            }
            Err(other) => Err(other)?,
        }
    }

    /// Create a detached mount of an image. This file descriptor can then
    /// be attached via e.g. `move_mount`.
    pub fn mount(&self, name: &str) -> Result<OwnedFd> {
        let (image, enable_verity) = self.open_image(name)?;
        Ok(composefs_fsmount(
            image,
            name,
            self.objects_dir()?,
            enable_verity,
        )?)
    }

    /// Mount the image with the provided digest at the target path.
    pub fn mount_at(&self, name: &str, mountpoint: impl AsRef<Path>) -> Result<()> {
        Ok(mount_at(
            self.mount(name)?,
            CWD,
            &canonicalize(mountpoint)?,
        )?)
    }

    /// Creates a relative symlink within the repository.
    ///
    /// Computes the correct relative path from the symlink location to the target,
    /// creating any necessary intermediate directories. Atomically replaces any
    /// existing symlink at the specified name.
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

        // Atomically replace existing symlink
        replace_symlinkat(&relative, &self.repository, name)
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

    /// Open the provided path in the repository.
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

        let Some(category_fd) = self
            .openat(category, OFlags::RDONLY | OFlags::DIRECTORY)
            .filter_errno(Errno::NOENT)
            .context("Opening {category} dir in repository")?
        else {
            return Ok(objects);
        };

        if let Some(refs) = openat(
            &category_fd,
            "refs",
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .filter_errno(Errno::NOENT)
        .context("Opening {category}/refs dir in repository")?
        {
            Self::walk_symlinkdir(refs, &mut objects)?;
        }

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

    /// Given an image, return the set of all objects referenced by it.
    pub fn objects_for_image(&self, name: &str) -> Result<HashSet<ObjectID>> {
        let (image, _) = self.open_image(name)?;
        let mut data = vec![];
        std::fs::File::from(image).read_to_end(&mut data)?;
        Ok(crate::erofs::reader::collect_objects(&data)?)
    }

    /// Makes sure all content is written to the repository.
    ///
    /// This is currently just syncfs() on the repository's root directory because we don't have
    /// any better options at present.  This blocks until the data is written out.
    pub fn sync(&self) -> Result<()> {
        syncfs(&self.repository)?;
        Ok(())
    }

    /// Makes sure all content is written to the repository.
    ///
    /// This is currently just syncfs() on the repository's root directory because we don't have
    /// any better options at present.  This won't return until the data is written out.
    pub async fn sync_async(self: &Arc<Self>) -> Result<()> {
        let self_ = Arc::clone(self);
        tokio::task::spawn_blocking(move || self_.sync()).await?
    }

    /// Perform a garbage collection operation.
    ///
    /// # Locking
    ///
    /// An exclusive lock is held for the duration of this operation.
    pub fn gc(&self) -> Result<()> {
        flock(&self.repository, FlockOperation::LockExclusive)?;

        let mut objects = HashSet::new();

        for ref object in self.gc_category("images")? {
            println!("{object:?} lives as an image");
            objects.insert(object.clone());
            objects.extend(self.objects_for_image(&object.to_hex())?);
        }

        /* TODO
        for object in self.gc_category("streams")? {
            println!("{object:?} lives as a stream");
            objects.insert(object.clone());

            let mut split_stream = self.open_stream(&object.to_hex(), None, None)?;
            split_stream.get_object_refs(|id| {
                println!("   with {id:?}");
                objects.insert(id.clone());
            })?;
        }
        */

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

    // fn fsck(&self) -> Result<()> {
    //     unimplemented!()
    // }
}
