use std::{
    collections::HashSet,
    ffi::CStr,
    fs::File,
    io::{ErrorKind, Read, Write},
    os::fd::OwnedFd,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, ensure, Context, Result};
use rustix::{
    fs::{
        accessat, fdatasync, flock, linkat, mkdirat, open, openat, readlinkat, symlinkat, Access,
        AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, CWD,
    },
    io::{Errno, Result as ErrnoResult},
};
use sha2::{Digest, Sha256};

use crate::{
    fsverity::{
        digest::FsVerityHasher,
        ioctl::{fs_ioc_enable_verity, fs_ioc_measure_verity},
        FsVerityHashValue, Sha256HashValue,
    },
    mount::{mount_fd, pivot_sysroot},
    splitstream::{DigestMap, SplitStreamReader, SplitStreamWriter},
    util::{parse_sha256, proc_self_fd},
};

pub struct Repository {
    repository: OwnedFd,
    path: PathBuf,
}

impl Drop for Repository {
    fn drop(&mut self) {
        flock(&self.repository, FlockOperation::Unlock).expect("repository unlock failed");
    }
}

impl Repository {
    pub fn open_path(path: PathBuf) -> Result<Repository> {
        // O_PATH isn't enough because flock()
        let repository = open(&path, OFlags::RDONLY, Mode::empty())
            .with_context(|| format!("Cannot open composefs repository {path:?}"))?;

        flock(&repository, FlockOperation::LockShared)
            .with_context(|| format!("Cannot lock repository {path:?}"))?;

        Ok(Repository { repository, path })
    }

    pub fn open_user() -> Result<Repository> {
        let home = std::env::var("HOME").with_context(|| "$HOME must be set when in user mode")?;

        Repository::open_path(PathBuf::from(home).join(".var/lib/composefs"))
    }

    pub fn open_system() -> Result<Repository> {
        Repository::open_path(PathBuf::from("/sysroot/composefs".to_string()))
    }

    fn ensure_dir(&self, dir: impl AsRef<Path>) -> ErrnoResult<()> {
        mkdirat(&self.repository, dir.as_ref(), 0o755.into()).or_else(|e| match e {
            Errno::EXIST => Ok(()),
            _ => Err(e),
        })
    }

    pub fn ensure_object(&self, data: &[u8]) -> Result<Sha256HashValue> {
        let digest = FsVerityHasher::hash(data);
        let dir = PathBuf::from(format!("objects/{:02x}", digest[0]));
        let file = dir.join(hex::encode(&digest[1..]));

        // fairly common...
        if accessat(&self.repository, &file, Access::READ_OK, AtFlags::empty()) == Ok(()) {
            return Ok(digest);
        }

        self.ensure_dir("objects")?;
        self.ensure_dir(&dir)?;

        let fd = openat(
            &self.repository,
            &dir,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::TMPFILE,
            0o666.into(),
        )?;
        rustix::io::write(&fd, data)?; // TODO: no write_all() here...
        fdatasync(&fd)?;

        // We can't enable verity with an open writable fd, so re-open and close the old one.
        let ro_fd = open(proc_self_fd(&fd), OFlags::RDONLY, Mode::empty())?;
        drop(fd);

        fs_ioc_enable_verity::<&OwnedFd, Sha256HashValue>(&ro_fd)?;

        // double-check
        let measured_digest: Sha256HashValue = fs_ioc_measure_verity(&ro_fd)?;
        assert!(measured_digest == digest);

        if let Err(err) = linkat(
            CWD,
            proc_self_fd(&ro_fd),
            &self.repository,
            file,
            AtFlags::SYMLINK_FOLLOW,
        ) {
            if err.kind() != ErrorKind::AlreadyExists {
                return Err(err.into());
            }
        }

        drop(ro_fd);
        Ok(digest)
    }

    fn open_with_verity(
        &self,
        filename: &str,
        expected_verity: &Sha256HashValue,
    ) -> Result<OwnedFd> {
        let fd = self.openat(filename, OFlags::RDONLY)?;
        let measured_verity: Sha256HashValue = fs_ioc_measure_verity(&fd)?;
        if measured_verity != *expected_verity {
            bail!("bad verity!")
        } else {
            Ok(fd)
        }
    }

    /// Creates a SplitStreamWriter for writing a split stream.
    /// You should write the data to the returned object and then pass it to .store_stream() to
    /// store the result.
    pub fn create_stream(
        &self,
        sha256: Option<Sha256HashValue>,
        maps: Option<DigestMap>,
    ) -> SplitStreamWriter {
        SplitStreamWriter::new(self, maps, sha256)
    }

    fn parse_object_path(path: impl AsRef<[u8]>) -> Result<Sha256HashValue> {
        // "objects/0c/9513d99b120ee9a709c4d6554d938f6b2b7e213cf5b26f2e255c0b77e40379"
        let bytes = path.as_ref();
        ensure!(bytes.len() == 73, "stream symlink has incorrect length");
        ensure!(
            bytes.starts_with(b"objects/"),
            "stream symlink has incorrect prefix"
        );
        ensure!(
            bytes[10] == b'/',
            "stream symlink has incorrect path separator"
        );
        let mut result = Sha256HashValue::EMPTY;
        hex::decode_to_slice(&bytes[8..10], &mut result[..1])
            .context("stream symlink has incorrect format")?;
        hex::decode_to_slice(&bytes[11..], &mut result[1..])
            .context("stream symlink has incorrect format")?;
        Ok(result)
    }

    fn format_object_path(id: &Sha256HashValue) -> String {
        format!("objects/{:02x}/{}", id[0], hex::encode(&id[1..]))
    }

    pub fn has_stream(&self, sha256: &Sha256HashValue) -> Result<Option<Sha256HashValue>> {
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
                Ok(Some(Repository::parse_object_path(&bytes[3..])?))
            }
            Err(Errno::NOENT) => Ok(None),
            Err(err) => Err(err)?,
        }
    }

    /// Basically the same as has_stream() except that it performs expensive verification
    pub fn check_stream(&self, sha256: &Sha256HashValue) -> Result<Option<Sha256HashValue>> {
        match self.openat(&format!("streams/{}", hex::encode(sha256)), OFlags::RDONLY) {
            Ok(stream) => {
                let measured_verity: Sha256HashValue = fs_ioc_measure_verity(&stream)?;
                let mut context = Sha256::new();
                let mut split_stream = SplitStreamReader::new(File::from(stream))?;

                // check the verity of all linked streams
                for entry in &split_stream.refs.map {
                    if self.check_stream(&entry.body)? != Some(entry.verity) {
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
        writer: SplitStreamWriter,
        reference: Option<&str>,
    ) -> Result<Sha256HashValue> {
        let Some((.., ref sha256)) = writer.sha256 else {
            bail!("Writer doesn't have sha256 enabled");
        };
        let stream_path = format!("streams/{}", hex::encode(sha256));
        let object_id = writer.done()?;
        let object_path = Repository::format_object_path(&object_id);
        self.ensure_symlink(&stream_path, &object_path)?;

        if let Some(name) = reference {
            let reference_path = format!("streams/refs/{name}");
            self.symlink(&reference_path, &stream_path)?;
        }

        Ok(object_id)
    }

    /// Assign the given name to a stream.  The stream must already exist.  After this operation it
    /// will be possible to refer to the stream by its new name 'refs/{name}'.
    pub fn name_stream(&self, sha256: Sha256HashValue, name: &str) -> Result<()> {
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
        &self,
        sha256: &Sha256HashValue,
        callback: impl FnOnce(&mut SplitStreamWriter) -> Result<()>,
        reference: Option<&str>,
    ) -> Result<Sha256HashValue> {
        let stream_path = format!("streams/{}", hex::encode(sha256));

        let object_id = match self.has_stream(sha256)? {
            Some(id) => id,
            None => {
                let mut writer = self.create_stream(Some(*sha256), None);
                callback(&mut writer)?;
                let object_id = writer.done()?;

                let object_path = Repository::format_object_path(&object_id);
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
        verity: Option<&Sha256HashValue>,
    ) -> Result<SplitStreamReader<File>> {
        let filename = format!("streams/{}", name);

        let file = File::from(if let Some(verity_hash) = verity {
            self.open_with_verity(&filename, verity_hash)?
        } else {
            self.openat(&filename, OFlags::RDONLY)?
        });

        SplitStreamReader::new(file)
    }

    fn open_object(&self, id: &Sha256HashValue) -> Result<OwnedFd> {
        self.open_with_verity(
            &format!("objects/{:02x}/{}", id[0], hex::encode(&id[1..])),
            id,
        )
    }

    pub fn merge_splitstream(
        &self,
        name: &str,
        verity: Option<&Sha256HashValue>,
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
    pub fn write_image(&self, name: Option<&str>, data: &[u8]) -> Result<Sha256HashValue> {
        let object_id = self.ensure_object(data)?;

        let object_path = format!(
            "objects/{:02x}/{}",
            object_id[0],
            hex::encode(&object_id[1..])
        );
        let image_path = format!("images/{}", hex::encode(object_id));

        self.ensure_symlink(&image_path, &object_path)?;

        if let Some(reference) = name {
            let ref_path = format!("images/refs/{}", reference);
            self.symlink(&ref_path, &image_path)?;
        }

        Ok(object_id)
    }

    /// this function is not safe for untrusted users
    pub fn import_image<R: Read>(&self, name: &str, image: &mut R) -> Result<Sha256HashValue> {
        let mut data = vec![];
        image.read_to_end(&mut data)?;
        self.write_image(Some(name), &data)
    }

    pub fn mount(&self, name: &str, mountpoint: &str) -> Result<()> {
        let filename = format!("images/{}", name);

        let image = if name.contains("/") {
            // no fsverity checking on this path
            Ok(self.openat(&filename, OFlags::RDONLY)?)
        } else {
            self.open_with_verity(&filename, &parse_sha256(name)?)
        }?;

        let object_path = self.path.join("objects");
        mount_fd(image, &object_path, mountpoint)
    }

    pub fn pivot_sysroot(&self, name: &str, mountpoint: &Path) -> Result<()> {
        let filename = format!("images/{}", name);
        let object_path = self.path.join("objects");
        let image = self.open_with_verity(&filename, &parse_sha256(name)?)?;
        pivot_sysroot(image, &object_path, mountpoint)
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

    fn read_symlink_hashvalue(dirfd: &OwnedFd, name: &CStr) -> Result<Sha256HashValue> {
        let link_content = readlinkat(dirfd, name, [])?;
        let link_bytes = link_content.to_bytes();
        let link_size = link_bytes.len();
        // XXX: check correctness of leading ../?
        // XXX: or is that something for fsck?
        if link_size > 64 {
            let mut value = Sha256HashValue::EMPTY;
            hex::decode_to_slice(&link_bytes[link_size - 64..link_size], &mut value)?;
            Ok(value)
        } else {
            bail!("symlink has wrong format")
        }
    }

    fn walk_symlinkdir(fd: OwnedFd, objects: &mut HashSet<Sha256HashValue>) -> Result<()> {
        for item in Dir::read_from(&fd)? {
            let entry = item?;
            // NB: the underlying filesystem must support returning filetype via direntry
            // that's a reasonable assumption, since it must also support fsverity...
            match entry.file_type() {
                FileType::Directory => {
                    let filename = entry.file_name();
                    if filename != c"." && filename != c".." {
                        let dirfd = openat(&fd, filename, OFlags::RDONLY, Mode::empty())?;
                        Repository::walk_symlinkdir(dirfd, objects)?;
                    }
                }
                FileType::Symlink => {
                    objects.insert(Repository::read_symlink_hashvalue(&fd, entry.file_name())?);
                }
                _ => {
                    bail!("Unexpected file type encountered");
                }
            }
        }

        Ok(())
    }

    fn openat(&self, name: &str, flags: OFlags) -> ErrnoResult<OwnedFd> {
        openat(&self.repository, name, flags, Mode::empty())
    }

    fn gc_category(&self, category: &str) -> Result<HashSet<Sha256HashValue>> {
        let mut objects = HashSet::<Sha256HashValue>::new();

        let category_fd = self.openat(category, OFlags::RDONLY | OFlags::DIRECTORY)?;

        let refs = openat(
            &category_fd,
            "refs",
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )?;
        Repository::walk_symlinkdir(refs, &mut objects)?;

        for item in Dir::read_from(&category_fd)? {
            let entry = item?;
            let filename = entry.file_name();
            if filename != c"refs" && filename != c"." && filename != c".." {
                if entry.file_type() != FileType::Symlink {
                    bail!("category directory contains non-symlink");
                }
                let mut value = Sha256HashValue::EMPTY;
                hex::decode_to_slice(filename.to_bytes(), &mut value)?;

                if !objects.contains(&value) {
                    println!("rm {}/{:?}", category, filename);
                }
            }
        }

        Ok(objects)
    }

    pub fn gc(&self) -> Result<()> {
        flock(&self.repository, FlockOperation::LockExclusive)?;

        let mut objects = HashSet::new();

        for ref object in self.gc_category("images")? {
            println!("{} lives as an image", hex::encode(object));
            objects.insert(*object);

            // composefs-info mmaps the file, so pipes aren't normally OK but we pass the
            // underlying file directly, which works.
            let output = Command::new("composefs-info")
                .stdin(File::from(self.open_object(object)?))
                .args(["objects", "/proc/self/fd/0"])
                .output()?
                .stdout;

            if output.len() % 66 != 0 {
                bail!("composefs-info gave invalid output (wrong size)");
            }

            for line in output.chunks_exact(66) {
                if line[2] != b'/' || line[65] != b'\n' {
                    bail!("composefs-info gave invalid output");
                }
                let mut value = Sha256HashValue::EMPTY;
                hex::decode_to_slice(&line[0..2], &mut value[0..1])?;
                hex::decode_to_slice(&line[3..65], &mut value[1..32])?;
                println!("    with {}", hex::encode(value));
                objects.insert(value);
            }
        }

        for object in self.gc_category("streams")? {
            println!("{} lives as a stream", hex::encode(object));
            objects.insert(object);

            let mut split_stream = self.open_stream(&hex::encode(object), None)?;
            split_stream.get_object_refs(|id| {
                println!("   with {}", hex::encode(*id));
                objects.insert(*id);
            })?;
        }

        for first_byte in 0x0..=0xff {
            let dirfd = self.openat(
                &format!("objects/{first_byte:02x}"),
                OFlags::RDONLY | OFlags::DIRECTORY,
            )?;
            for item in Dir::new(dirfd)? {
                match item {
                    Err(e) => Err(e)?,
                    Ok(entry) => {
                        let filename = entry.file_name();
                        if filename != c"." && filename != c".." {
                            let mut value = Sha256HashValue::EMPTY;
                            value[0] = first_byte;
                            hex::decode_to_slice(filename.to_bytes(), &mut value[1..])?;
                            if !objects.contains(&value) {
                                println!("rm objects/{first_byte:02x}/{filename:?}");
                            } else {
                                println!("# objects/{first_byte:02x}/{filename:?} lives");
                            }
                        }
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
