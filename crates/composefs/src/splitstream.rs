//! Split Stream file format implementation.
//!
//! This module implements the Split Stream format for efficiently storing
//! and transferring data with inline content and external object references,
//! supporting compression and content deduplication.

/* Implementation of the Split Stream file format
 *
 * See doc/splitstream.md
 */

use std::{
    io::{BufReader, Read, Write},
    sync::Arc,
};

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
use zstd::stream::{read::Decoder, write::Encoder};

use crate::{
    fsverity::FsVerityHashValue,
    repository::Repository,
    util::{read_exactish, Sha256Digest},
};

/// A single entry in the digest map, mapping content SHA256 hash to fs-verity object ID.
#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct DigestMapEntry<ObjectID: FsVerityHashValue> {
    /// SHA256 hash of the content body
    pub body: Sha256Digest,
    /// fs-verity object identifier
    pub verity: ObjectID,
}

/// A map of content digests to object IDs, maintained in sorted order for binary search.
#[derive(Debug)]
pub struct DigestMap<ObjectID: FsVerityHashValue> {
    /// Vector of digest map entries, kept sorted by body hash
    pub map: Vec<DigestMapEntry<ObjectID>>,
}

impl<ObjectID: FsVerityHashValue> Default for DigestMap<ObjectID> {
    fn default() -> Self {
        Self::new()
    }
}

impl<ObjectID: FsVerityHashValue> DigestMap<ObjectID> {
    /// Creates a new empty digest map.
    pub fn new() -> Self {
        DigestMap { map: vec![] }
    }

    /// Looks up an object ID by its content SHA256 hash.
    ///
    /// Returns the object ID if found, or None if not present in the map.
    pub fn lookup(&self, body: &Sha256Digest) -> Option<&ObjectID> {
        match self.map.binary_search_by_key(body, |e| e.body) {
            Ok(idx) => Some(&self.map[idx].verity),
            Err(..) => None,
        }
    }

    /// Inserts a new digest mapping, maintaining sorted order.
    ///
    /// If the body hash already exists, asserts that the verity ID matches.
    pub fn insert(&mut self, body: &Sha256Digest, verity: &ObjectID) {
        match self.map.binary_search_by_key(body, |e| e.body) {
            Ok(idx) => assert_eq!(self.map[idx].verity, *verity), // or else, bad things...
            Err(idx) => self.map.insert(
                idx,
                DigestMapEntry {
                    body: *body,
                    verity: verity.clone(),
                },
            ),
        }
    }
}

/// Writer for creating split stream format files with inline content and external object references.
pub struct SplitStreamWriter<ObjectID: FsVerityHashValue> {
    repo: Arc<Repository<ObjectID>>,
    inline_content: Vec<u8>,
    writer: Encoder<'static, Vec<u8>>,
    /// Optional SHA256 hasher and expected digest for validation
    pub sha256: Option<(Sha256, Sha256Digest)>,
}

impl<ObjectID: FsVerityHashValue> std::fmt::Debug for SplitStreamWriter<ObjectID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // writer doesn't impl Debug
        f.debug_struct("SplitStreamWriter")
            .field("repo", &self.repo)
            .field("inline_content", &self.inline_content)
            .field("sha256", &self.sha256)
            .finish()
    }
}

impl<ObjectID: FsVerityHashValue> SplitStreamWriter<ObjectID> {
    /// Creates a new split stream writer.
    ///
    /// The writer is initialized with optional digest map references and an optional
    /// expected SHA256 hash for validation when the stream is finalized.
    pub fn new(
        repo: &Arc<Repository<ObjectID>>,
        refs: Option<DigestMap<ObjectID>>,
        sha256: Option<Sha256Digest>,
    ) -> Self {
        // SAFETY: we surely can't get an error writing the header to a Vec<u8>
        let mut writer = Encoder::new(vec![], 0).unwrap();

        match refs {
            Some(DigestMap { map }) => {
                writer.write_all(&(map.len() as u64).to_le_bytes()).unwrap();
                writer.write_all(map.as_bytes()).unwrap();
            }
            None => {
                writer.write_all(&0u64.to_le_bytes()).unwrap();
            }
        }

        Self {
            repo: Arc::clone(repo),
            inline_content: vec![],
            writer,
            sha256: sha256.map(|x| (Sha256::new(), x)),
        }
    }

    fn write_fragment(writer: &mut impl Write, size: usize, data: &[u8]) -> Result<()> {
        writer.write_all(&(size as u64).to_le_bytes())?;
        Ok(writer.write_all(data)?)
    }

    fn flush_inline(&mut self) -> Result<()> {
        if !self.inline_content.is_empty() {
            Self::write_fragment(
                &mut self.writer,
                self.inline_content.len(),
                &self.inline_content,
            )?;
            self.inline_content.clear();
        }
        Ok(())
    }

    /// Write inline data to the stream.
    pub fn write_inline(&mut self, data: &[u8]) {
        if let Some((ref mut sha256, ..)) = self.sha256 {
            sha256.update(data);
        }
        self.inline_content.extend(data);
    }

    // common part of .write_external() and .write_external_async()
    fn write_reference(&mut self, id: ObjectID) -> Result<()> {
        // Flush any buffered inline data before we store the external reference.
        self.flush_inline()?;

        Self::write_fragment(&mut self.writer, 0, id.as_bytes())
    }

    /// Write externally-split data to the stream.
    ///
    /// The data is stored in the repository and a reference is written to the stream.
    pub fn write_external(&mut self, data: &[u8]) -> Result<()> {
        if let Some((ref mut sha256, ..)) = self.sha256 {
            sha256.update(data);
        }
        let id = self.repo.ensure_object(data)?;
        self.write_reference(id)
    }

    /// Asynchronously write externally-split data to the stream.
    ///
    /// The data is stored in the repository asynchronously and a reference is written to the stream.
    pub async fn write_external_async(&mut self, data: Vec<u8>) -> Result<()> {
        if let Some((ref mut sha256, ..)) = self.sha256 {
            sha256.update(&data);
        }
        let id = self.repo.ensure_object_async(data).await?;
        self.write_reference(id)
    }

    /// Finalizes the split stream and returns its object ID.
    ///
    /// Flushes any remaining inline content, validates the SHA256 hash if provided,
    /// and stores the compressed stream in the repository.
    pub fn done(mut self) -> Result<ObjectID> {
        self.flush_inline()?;

        if let Some((context, expected)) = self.sha256 {
            if Into::<Sha256Digest>::into(context.finalize()) != expected {
                bail!("Content doesn't have expected SHA256 hash value!");
            }
        }

        self.repo.ensure_object(&self.writer.finish()?)
    }
}

/// Data fragment from a split stream, either inline content or an external object reference.
#[derive(Debug)]
pub enum SplitStreamData<ObjectID: FsVerityHashValue> {
    /// Inline content stored directly in the stream
    Inline(Box<[u8]>),
    /// Reference to an external object
    External(ObjectID),
}

/// Reader for parsing split stream format files with inline content and external object references.
pub struct SplitStreamReader<R: Read, ObjectID: FsVerityHashValue> {
    decoder: Decoder<'static, BufReader<R>>,
    /// Digest map containing content hash to object ID mappings
    pub refs: DigestMap<ObjectID>,
    inline_bytes: usize,
}

impl<R: Read, ObjectID: FsVerityHashValue> std::fmt::Debug for SplitStreamReader<R, ObjectID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // decoder doesn't impl Debug
        f.debug_struct("SplitStreamReader")
            .field("refs", &self.refs)
            .field("inline_bytes", &self.inline_bytes)
            .finish()
    }
}

fn read_u64_le<R: Read>(reader: &mut R) -> Result<Option<usize>> {
    let mut buf = [0u8; 8];
    if read_exactish(reader, &mut buf)? {
        Ok(Some(u64::from_le_bytes(buf) as usize))
    } else {
        Ok(None)
    }
}

/// Using the provided [`vec`] as a buffer, read exactly [`size`]
/// bytes of content from [`reader`] into it. Any existing content
/// in [`vec`] will be discarded; however its capacity will be reused,
/// making this function suitable for use in loops.
fn read_into_vec(reader: &mut impl Read, vec: &mut Vec<u8>, size: usize) -> Result<()> {
    vec.resize(size, 0u8);
    reader.read_exact(vec.as_mut_slice())?;
    Ok(())
}

enum ChunkType<ObjectID: FsVerityHashValue> {
    Eof,
    Inline,
    External(ObjectID),
}

impl<R: Read, ObjectID: FsVerityHashValue> SplitStreamReader<R, ObjectID> {
    /// Creates a new split stream reader from the provided reader.
    ///
    /// Reads the digest map header from the stream during initialization.
    pub fn new(reader: R) -> Result<Self> {
        let mut decoder = Decoder::new(reader)?;

        let n_map_entries = {
            let mut buf = [0u8; 8];
            decoder.read_exact(&mut buf)?;
            u64::from_le_bytes(buf)
        } as usize;

        let mut refs = DigestMap::<ObjectID> {
            map: Vec::with_capacity(n_map_entries),
        };
        for _ in 0..n_map_entries {
            refs.map.push(DigestMapEntry::read_from_io(&mut decoder)?);
        }

        Ok(Self {
            decoder,
            refs,
            inline_bytes: 0,
        })
    }

    fn ensure_chunk(
        &mut self,
        eof_ok: bool,
        ext_ok: bool,
        expected_bytes: usize,
    ) -> Result<ChunkType<ObjectID>> {
        if self.inline_bytes == 0 {
            match read_u64_le(&mut self.decoder)? {
                None => {
                    if !eof_ok {
                        bail!("Unexpected EOF when parsing splitstream");
                    }
                    return Ok(ChunkType::Eof);
                }
                Some(0) => {
                    if !ext_ok {
                        bail!("Unexpected external reference when parsing splitstream");
                    }
                    let id = ObjectID::read_from_io(&mut self.decoder)?;
                    return Ok(ChunkType::External(id));
                }
                Some(size) => {
                    self.inline_bytes = size;
                }
            }
        }

        if self.inline_bytes < expected_bytes {
            bail!("Unexpectedly small inline content when parsing splitstream");
        }

        Ok(ChunkType::Inline)
    }

    /// Reads the exact number of inline bytes
    /// Assumes that the data cannot be split across chunks
    pub fn read_inline_exact(&mut self, buffer: &mut [u8]) -> Result<bool> {
        if let ChunkType::Inline = self.ensure_chunk(true, false, buffer.len())? {
            self.decoder.read_exact(buffer)?;
            self.inline_bytes -= buffer.len();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn discard_padding(&mut self, size: usize) -> Result<()> {
        let mut buf = [0u8; 512];
        assert!(size <= 512);
        self.ensure_chunk(false, false, size)?;
        self.decoder.read_exact(&mut buf[0..size])?;
        self.inline_bytes -= size;
        Ok(())
    }

    /// Reads an exact amount of data, which may be inline or external.
    ///
    /// The stored_size is the size as recorded in the stream (including any padding),
    /// while actual_size is the actual content size without padding.
    /// Returns either inline content or an external object reference.
    pub fn read_exact(
        &mut self,
        actual_size: usize,
        stored_size: usize,
    ) -> Result<SplitStreamData<ObjectID>> {
        if let ChunkType::External(id) = self.ensure_chunk(false, true, stored_size)? {
            // ...and the padding
            if actual_size < stored_size {
                self.discard_padding(stored_size - actual_size)?;
            }
            Ok(SplitStreamData::External(id))
        } else {
            let mut content = vec![];
            read_into_vec(&mut self.decoder, &mut content, stored_size)?;
            content.truncate(actual_size);
            self.inline_bytes -= stored_size;
            Ok(SplitStreamData::Inline(content.into()))
        }
    }

    /// Concatenates the entire split stream content to the output writer.
    ///
    /// Inline content is written directly, while external references are resolved
    /// using the provided load_data callback function.
    pub fn cat(
        &mut self,
        output: &mut impl Write,
        mut load_data: impl FnMut(&ObjectID) -> Result<Vec<u8>>,
    ) -> Result<()> {
        let mut buffer = vec![];

        loop {
            match self.ensure_chunk(true, true, 0)? {
                ChunkType::Eof => break Ok(()),
                ChunkType::Inline => {
                    read_into_vec(&mut self.decoder, &mut buffer, self.inline_bytes)?;
                    self.inline_bytes = 0;
                    output.write_all(&buffer)?;
                }
                ChunkType::External(ref id) => {
                    output.write_all(&load_data(id)?)?;
                }
            }
        }
    }

    /// Traverses the split stream and calls the callback for each object reference.
    ///
    /// This includes both references from the digest map and external references in the stream.
    pub fn get_object_refs(&mut self, mut callback: impl FnMut(&ObjectID)) -> Result<()> {
        let mut buffer = vec![];

        for entry in &self.refs.map {
            callback(&entry.verity);
        }

        loop {
            match self.ensure_chunk(true, true, 0)? {
                ChunkType::Eof => break Ok(()),
                ChunkType::Inline => {
                    read_into_vec(&mut self.decoder, &mut buffer, self.inline_bytes)?;
                    self.inline_bytes = 0;
                }
                ChunkType::External(ref id) => {
                    callback(id);
                }
            }
        }
    }

    /// Calls the callback for each content hash in the digest map.
    pub fn get_stream_refs(&mut self, mut callback: impl FnMut(&Sha256Digest)) {
        for entry in &self.refs.map {
            callback(&entry.body);
        }
    }

    /// Looks up an object ID by content hash in the digest map.
    ///
    /// Returns an error if the reference is not found.
    pub fn lookup(&self, body: &Sha256Digest) -> Result<&ObjectID> {
        match self.refs.lookup(body) {
            Some(id) => Ok(id),
            None => bail!("Reference is not found in splitstream"),
        }
    }
}

impl<F: Read, ObjectID: FsVerityHashValue> Read for SplitStreamReader<F, ObjectID> {
    fn read(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        match self.ensure_chunk(true, false, 1) {
            Ok(ChunkType::Eof) => Ok(0),
            Ok(ChunkType::Inline) => {
                let n_bytes = std::cmp::min(data.len(), self.inline_bytes);
                self.decoder.read_exact(&mut data[0..n_bytes])?;
                self.inline_bytes -= n_bytes;
                Ok(n_bytes)
            }
            Ok(ChunkType::External(..)) => unreachable!(),
            Err(e) => Err(std::io::Error::other(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_into_vec() -> Result<()> {
        // Test with an empty reader
        let mut reader = Cursor::new(vec![]);
        let mut vec = Vec::new();
        let result = read_into_vec(&mut reader, &mut vec, 0);
        assert!(result.is_ok());
        assert_eq!(vec.len(), 0);

        // Test with a reader that has some data
        let mut reader = Cursor::new(vec![1, 2, 3, 4, 5]);
        let mut vec = Vec::new();
        let result = read_into_vec(&mut reader, &mut vec, 3);
        assert!(result.is_ok());
        assert_eq!(vec.len(), 3);
        assert_eq!(vec, vec![1, 2, 3]);

        // Test reading more than the reader has
        let mut reader = Cursor::new(vec![1, 2, 3]);
        let mut vec = Vec::new();
        let result = read_into_vec(&mut reader, &mut vec, 5);
        assert!(result.is_err());

        // Test reading exactly what the reader has
        let mut reader = Cursor::new(vec![1, 2, 3]);
        let mut vec = Vec::new();
        let result = read_into_vec(&mut reader, &mut vec, 3);
        assert!(result.is_ok());
        assert_eq!(vec.len(), 3);
        assert_eq!(vec, vec![1, 2, 3]);

        // Test reading into a vector with existing capacity
        let mut reader = Cursor::new(vec![1, 2, 3, 4, 5]);
        let mut vec = Vec::with_capacity(10);
        let result = read_into_vec(&mut reader, &mut vec, 4);
        assert!(result.is_ok());
        assert_eq!(vec.len(), 4);
        assert_eq!(vec, vec![1, 2, 3, 4]);
        assert_eq!(vec.capacity(), 10);

        // Test reading into a vector with existing data
        let mut reader = Cursor::new(vec![1, 2, 3]);
        let mut vec = vec![9, 9, 9];
        let result = read_into_vec(&mut reader, &mut vec, 2);
        assert!(result.is_ok());
        assert_eq!(vec.len(), 2);
        assert_eq!(vec, vec![1, 2]);

        Ok(())
    }
}
