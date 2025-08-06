/* Implementation of the Split Stream file format
 *
 * See doc/splitstream.md
 */

use std::{
    io::{BufReader, Read, Write},
    sync::Arc,
};

use anyhow::{bail, Error, Result};
use sha2::{Digest, Sha256};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
use zstd::stream::{read::Decoder, write::Encoder};

use crate::{
    fsverity::FsVerityHashValue,
    repository::Repository,
    util::{read_exactish, Sha256Digest},
};

pub const SPLITSTREAM_MAGIC: [u8; 7] = [b'S', b'p', b'l', b't', b'S', b't', b'r'];

#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct SplitstreamHeader {
    pub magic: [u8; 7], // Contains SPLITSTREAM_MAGIC
    pub algorithm: u8,
    pub content_type: u64, // User can put whatever magic identifier they want there
    pub total_size: u64,   // total size of inline chunks and external chunks
    pub n_refs: u64,
    pub n_mappings: u64,
    // Followed by n_refs ObjectIDs, sorted
    // Followed by n_mappings MappingEntry, sorted by body
    // Followed by zstd compressed chunks
}

#[derive(Clone, Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct MappingEntry {
    pub body: Sha256Digest,
    pub reference_idx: u64,
}

// These are used during construction before we know the final reference indexes
#[derive(Debug)]
pub struct DigestMapEntry<ObjectID: FsVerityHashValue> {
    pub body: Sha256Digest,
    pub verity: ObjectID,
}

#[derive(Debug)]
pub struct DigestMap<ObjectID: FsVerityHashValue> {
    pub map: Vec<DigestMapEntry<ObjectID>>,
}

impl<ObjectID: FsVerityHashValue> Default for DigestMap<ObjectID> {
    fn default() -> Self {
        Self::new()
    }
}

impl<ObjectID: FsVerityHashValue> DigestMap<ObjectID> {
    pub fn new() -> Self {
        DigestMap { map: vec![] }
    }

    pub fn lookup(&self, body: &Sha256Digest) -> Option<&ObjectID> {
        match self.map.binary_search_by_key(body, |e| e.body) {
            Ok(idx) => Some(&self.map[idx].verity),
            Err(..) => None,
        }
    }

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

pub struct SplitStreamWriter<ObjectID: FsVerityHashValue> {
    repo: Arc<Repository<ObjectID>>,
    refs: Vec<ObjectID>,
    mappings: DigestMap<ObjectID>,
    inline_content: Vec<u8>,
    total_size: u64,
    writer: Encoder<'static, Vec<u8>>,
    pub content_type: u64,
    pub sha256: Option<Sha256>,
    pub expected_sha256: Option<Sha256Digest>,
}

impl<ObjectID: FsVerityHashValue> std::fmt::Debug for SplitStreamWriter<ObjectID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // writer doesn't impl Debug
        f.debug_struct("SplitStreamWriter")
            .field("repo", &self.repo)
            .field("inline_content", &self.inline_content)
            .field("expected_sha256", &self.expected_sha256)
            .field("sha256", &self.sha256)
            .finish()
    }
}

impl<ObjectID: FsVerityHashValue> SplitStreamWriter<ObjectID> {
    pub fn new(
        repo: &Arc<Repository<ObjectID>>,
        content_type: u64,
        compute_sha256: bool,
        expected_sha256: Option<Sha256Digest>,
    ) -> Self {
        // SAFETY: we surely can't get an error writing the header to a Vec<u8>
        let writer = Encoder::new(vec![], 0).unwrap();

        Self {
            repo: Arc::clone(repo),
            content_type,
            inline_content: vec![],
            refs: vec![],
            total_size: 0,
            mappings: DigestMap::new(),
            writer,
            sha256: if compute_sha256 || expected_sha256.is_some() {
                Some(Sha256::new())
            } else {
                None
            },
            expected_sha256,
        }
    }

    pub fn add_external_reference(&mut self, verity: &ObjectID) {
        match self.refs.binary_search(verity) {
            Ok(_) => {} // Already added
            Err(idx) => self.refs.insert(idx, verity.clone()),
        }
    }

    // Note: These are only stable if no more references are added
    pub fn lookup_external_reference(&self, verity: &ObjectID) -> Option<usize> {
        self.refs.binary_search(verity).ok()
    }

    pub fn add_sha256_mappings(&mut self, maps: DigestMap<ObjectID>) {
        for m in maps.map {
            self.add_sha256_mapping(&m.body, &m.verity);
        }
    }

    pub fn add_sha256_mapping(&mut self, digest: &Sha256Digest, verity: &ObjectID) {
        self.add_external_reference(verity);
        self.mappings.insert(digest, verity)
    }

    fn write_fragment(writer: &mut impl Write, size: usize, data: &[u8]) -> Result<()> {
        writer.write_all(&(size as u64).to_le_bytes())?;
        Ok(writer.write_all(data)?)
    }

    /// flush any buffered inline data, taking new_value as the new value of the buffer
    fn flush_inline(&mut self, new_value: Vec<u8>) -> Result<()> {
        if !self.inline_content.is_empty() {
            Self::write_fragment(
                &mut self.writer,
                self.inline_content.len(),
                &self.inline_content,
            )?;
            self.total_size += self.inline_content.len() as u64;
            self.inline_content = new_value;
        }
        Ok(())
    }

    /// really, "add inline content to the buffer"
    /// you need to call .flush_inline() later
    pub fn write_inline(&mut self, data: &[u8]) {
        if let Some(ref mut sha256) = self.sha256 {
            sha256.update(data);
        }
        self.inline_content.extend(data);
    }

    /// write a reference to external data to the stream.  If the external data had padding in the
    /// stream which is not stored in the object then pass it here as well and it will be stored
    /// inline after the reference.
    fn write_reference(&mut self, reference: &ObjectID, padding: Vec<u8>) -> Result<()> {
        // Flush the inline data before we store the external reference.  Any padding from the
        // external data becomes the start of a new inline block.
        self.flush_inline(padding)?;

        Self::write_fragment(&mut self.writer, 0, reference.as_bytes())
    }

    pub fn write_external(&mut self, data: &[u8], padding: Vec<u8>) -> Result<()> {
        if let Some(ref mut sha256, ..) = self.sha256 {
            sha256.update(data);
            sha256.update(&padding);
        }
        let id = self.repo.ensure_object(data)?;

        self.add_external_reference(&id);
        self.total_size += data.len() as u64;
        self.write_reference(&id, padding)
    }

    pub async fn write_external_async(&mut self, data: Vec<u8>, padding: Vec<u8>) -> Result<()> {
        if let Some(ref mut sha256, ..) = self.sha256 {
            sha256.update(&data);
            sha256.update(&padding);
        }
        self.total_size += data.len() as u64;
        let id = self.repo.ensure_object_async(data).await?;
        self.add_external_reference(&id);
        self.write_reference(&id, padding)
    }

    pub fn done(mut self) -> Result<(ObjectID, Option<Sha256Digest>)> {
        self.flush_inline(vec![])?;

        let sha256_digest = if let Some(sha256) = self.sha256 {
            let actual = Into::<Sha256Digest>::into(sha256.finalize());
            if let Some(expected) = self.expected_sha256 {
                if actual != expected {
                    bail!("Content doesn't have expected SHA256 hash value!");
                }
            }
            Some(actual)
        } else {
            None
        };

        let mut buf = vec![];
        let header = SplitstreamHeader {
            magic: SPLITSTREAM_MAGIC,
            algorithm: ObjectID::ALGORITHM,
            content_type: self.content_type,
            total_size: u64::to_le(self.total_size),
            n_refs: u64::to_le(self.refs.len() as u64),
            n_mappings: u64::to_le(self.mappings.map.len() as u64),
        };
        buf.extend_from_slice(header.as_bytes());

        for ref_id in self.refs.iter() {
            buf.extend_from_slice(ref_id.as_bytes());
        }

        for mapping in self.mappings.map {
            let entry = MappingEntry {
                body: mapping.body,
                reference_idx: u64::to_le(self.refs.binary_search(&mapping.verity).unwrap() as u64),
            };
            buf.extend_from_slice(entry.as_bytes());
        }

        buf.extend_from_slice(&self.writer.finish()?);

        Ok((self.repo.ensure_object(&buf)?, sha256_digest))
    }
}

#[derive(Debug)]
pub enum SplitStreamData<ObjectID: FsVerityHashValue> {
    Inline(Box<[u8]>),
    External(ObjectID),
}

// utility class to help read splitstreams
pub struct SplitStreamReader<R: Read, ObjectID: FsVerityHashValue> {
    decoder: Decoder<'static, BufReader<R>>,
    inline_bytes: usize,
    pub content_type: u64,
    pub total_size: u64,
    pub refs: Vec<ObjectID>,
    mappings: Vec<MappingEntry>,
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
    pub fn new(mut reader: R, expected_content_type: Option<u64>) -> Result<Self> {
        let header = SplitstreamHeader::read_from_io(&mut reader)
            .map_err(|e| Error::msg(format!("Error reading splitstream header: {:?}", e)))?;

        if header.magic != SPLITSTREAM_MAGIC {
            bail!("Invalid splitstream header magic value");
        }

        if header.algorithm != ObjectID::ALGORITHM {
            bail!("Invalid splitstream algorithm type");
        }

        let content_type = u64::from_le(header.content_type);
        if let Some(expected) = expected_content_type {
            if content_type != expected {
                bail!("Invalid splitstream content type");
            }
        }

        let total_size = u64::from_le(header.total_size);
        let n_refs = usize::try_from(u64::from_le(header.n_refs))?;
        let n_mappings = usize::try_from(u64::from_le(header.n_mappings))?;

        let mut refs = Vec::<ObjectID>::new();
        for _ in 0..n_refs {
            let objid = ObjectID::read_from_io(&mut reader)
                .map_err(|e| Error::msg(format!("Invalid refs array {:?}", e)))?;
            refs.push(objid.clone());
        }

        let mut mappings = Vec::<MappingEntry>::new();
        for _ in 0..n_mappings {
            let mut m = MappingEntry::read_from_io(&mut reader)
                .map_err(|e| Error::msg(format!("Invalid mappings array {:?}", e)))?;
            m.reference_idx = u64::from_le(m.reference_idx);
            if m.reference_idx >= n_refs as u64 {
                bail!("Invalid mapping reference")
            }
            mappings.push(m.clone());
        }

        let decoder = Decoder::new(reader)?;

        Ok(Self {
            decoder,
            inline_bytes: 0,
            content_type,
            total_size,
            refs,
            mappings,
        })
    }

    pub fn iter_mappings(&self) -> impl Iterator<Item = (&Sha256Digest, &ObjectID)> {
        self.mappings
            .iter()
            .map(|m| (&m.body, &self.refs[m.reference_idx as usize]))
    }

    pub fn get_mappings(&self) -> DigestMap<ObjectID> {
        let mut m = DigestMap::new();

        for (body, verity) in self.iter_mappings() {
            m.insert(body, verity);
        }
        m
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

    pub fn get_object_refs(&mut self, mut callback: impl FnMut(&ObjectID)) -> Result<()> {
        for entry in &self.refs {
            callback(entry);
        }
        Ok(())
    }

    pub fn get_stream_refs(&mut self, mut callback: impl FnMut(&Sha256Digest)) {
        for entry in &self.mappings {
            callback(&entry.body);
        }
    }

    pub fn lookup(&self, body: &Sha256Digest) -> Result<&ObjectID> {
        match self.mappings.binary_search_by_key(body, |e| e.body) {
            Ok(idx) => Ok(&self.refs[self.mappings[idx].reference_idx as usize]),
            Err(..) => bail!("Reference is not found in splitstream"),
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
