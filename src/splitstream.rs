/* Implementation of the Split Stream file format
 *
 * See doc/splitstream.md
 */

use std::io::{BufReader, Read, Write};

use anyhow::{bail, Result};
use sha2::Sha256;
use zstd::stream::read::Decoder;

use crate::{
    fsverity::{FsVerityHashValue, Sha256HashValue},
    repository::Repository,
    util::read_exactish,
    zstd_encoder::ZstdWriter,
};

#[derive(Debug)]
pub struct DigestMapEntry {
    pub body: Sha256HashValue,
    pub verity: Sha256HashValue,
}

#[derive(Debug)]
pub struct DigestMap {
    pub map: Vec<DigestMapEntry>,
}

impl Default for DigestMap {
    fn default() -> Self {
        Self::new()
    }
}

impl DigestMap {
    pub fn new() -> Self {
        DigestMap { map: vec![] }
    }

    pub fn lookup(&self, body: &Sha256HashValue) -> Option<&Sha256HashValue> {
        match self.map.binary_search_by_key(body, |e| e.body) {
            Ok(idx) => Some(&self.map[idx].verity),
            Err(..) => None,
        }
    }

    pub fn insert(&mut self, body: &Sha256HashValue, verity: &Sha256HashValue) {
        match self.map.binary_search_by_key(body, |e| e.body) {
            Ok(idx) => assert_eq!(self.map[idx].verity, *verity), // or else, bad things...
            Err(idx) => self.map.insert(
                idx,
                DigestMapEntry {
                    body: *body,
                    verity: *verity,
                },
            ),
        }
    }
}

pub struct SplitStreamWriter<'a> {
    repo: &'a Repository,
    pub(crate) inline_content: Vec<u8>,
    writer: ZstdWriter,
}

impl std::fmt::Debug for SplitStreamWriter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // writer doesn't impl Debug
        f.debug_struct("SplitStreamWriter")
            .field("repo", &self.repo)
            .field("inline_content", &self.inline_content)
            .finish()
    }
}

impl SplitStreamWriter<'_> {
    pub fn new(
        repo: &Repository,
        refs: Option<DigestMap>,
        sha256: Option<Sha256HashValue>,
    ) -> SplitStreamWriter {
        SplitStreamWriter {
            repo,
            inline_content: vec![],
            writer: ZstdWriter::new(sha256, refs),
        }
    }

    pub fn get_sha_builder(&self) -> &Option<(Sha256, Sha256HashValue)> {
        &self.writer.sha256_builder
    }

    /// flush any buffered inline data, taking new_value as the new value of the buffer
    fn flush_inline(&mut self, new_value: Vec<u8>) -> Result<()> {
        self.writer.flush_inline(&self.inline_content)?;
        self.inline_content = new_value;
        Ok(())
    }

    /// really, "add inline content to the buffer"
    /// you need to call .flush_inline() later
    pub fn write_inline(&mut self, data: &[u8]) {
        self.writer.update_sha(data);
        self.inline_content.extend(data);
    }

    pub fn write_external(&mut self, data: &[u8], padding: Vec<u8>) -> Result<()> {
        let id = self.repo.ensure_object(&data)?;

        self.writer.update_sha(data);
        self.writer.update_sha(&padding);
        self.writer.flush_inline(&padding)?;

        self.writer.write_fragment(0, &id)?;
        Ok(())
    }

    pub fn done(mut self) -> Result<Sha256HashValue> {
        self.flush_inline(vec![])?;

        self.writer.finalize_sha256_builder()?;

        self.repo.ensure_object(&self.writer.finish()?)
    }
}

#[derive(Debug)]
pub enum SplitStreamData {
    Inline(Box<[u8]>),
    External(Sha256HashValue),
}

// utility class to help read splitstreams
pub struct SplitStreamReader<R: Read> {
    decoder: Decoder<'static, BufReader<R>>,
    pub refs: DigestMap,
    inline_bytes: usize,
}

impl<R: Read> std::fmt::Debug for SplitStreamReader<R> {
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

enum ChunkType {
    Eof,
    Inline,
    External(Sha256HashValue),
}

impl<R: Read> SplitStreamReader<R> {
    pub fn new(reader: R) -> Result<SplitStreamReader<R>> {
        let mut decoder = Decoder::new(reader)?;

        let n_map_entries = {
            let mut buf = [0u8; 8];
            decoder.read_exact(&mut buf)?;
            u64::from_le_bytes(buf)
        } as usize;

        let mut refs = DigestMap {
            map: Vec::with_capacity(n_map_entries),
        };
        for _ in 0..n_map_entries {
            let mut body = [0u8; 32];
            let mut verity = [0u8; 32];

            decoder.read_exact(&mut body)?;
            decoder.read_exact(&mut verity)?;
            refs.map.push(DigestMapEntry { body, verity });
        }

        Ok(SplitStreamReader {
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
    ) -> Result<ChunkType> {
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
                    let mut id = Sha256HashValue::EMPTY;
                    self.decoder.read_exact(&mut id)?;
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
    ) -> Result<SplitStreamData> {
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
        mut load_data: impl FnMut(&Sha256HashValue) -> Result<Vec<u8>>,
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

    pub fn get_object_refs(&mut self, mut callback: impl FnMut(&Sha256HashValue)) -> Result<()> {
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

    pub fn get_stream_refs(&mut self, mut callback: impl FnMut(&Sha256HashValue)) {
        for entry in &self.refs.map {
            callback(&entry.body);
        }
    }

    pub fn lookup(&self, body: &Sha256HashValue) -> Result<&Sha256HashValue> {
        match self.refs.lookup(body) {
            Some(id) => Ok(id),
            None => bail!("Reference is not found in splitstream"),
        }
    }
}

impl<F: Read> Read for SplitStreamReader<F> {
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
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
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
