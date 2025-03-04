/* Implementation of the Split Stream file format
 *
 * See doc/splitstream.md
 */

use std::{
    fmt::Debug,
    io::{BufReader, Read, Write},
};

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use zstd::stream::{read::Decoder, write::Encoder};

use crate::{
    fsverity::{FsVerityHashValue, Sha256HashValue},
    repository::Repository,
    util::read_exactish,
};

pub struct DigestMapEntry {
    pub body: Sha256HashValue,
    pub verity: Sha256HashValue,
}

impl Debug for DigestMapEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "< Body: {}, Verity: {} >",
            hex::encode(self.body),
            hex::encode(self.verity)
        )
    }
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
    inline_content: Vec<u8>,
    writer: Encoder<'a, Vec<u8>>,
    pub sha256: Option<(Sha256, Sha256HashValue)>,
}

impl std::fmt::Debug for SplitStreamWriter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // writer doesn't impl Debug
        f.debug_struct("SplitStreamWriter")
            .field("repo", &self.repo)
            .field("inline_content", &self.inline_content)
            .field("sha256", &self.sha256)
            .finish()
    }
}

impl SplitStreamWriter<'_> {
    pub fn new(
        repo: &Repository,
        refs: Option<DigestMap>,
        sha256: Option<Sha256HashValue>,
    ) -> SplitStreamWriter {
        // SAFETY: we surely can't get an error writing the header to a Vec<u8>
        let mut writer = Encoder::new(vec![], 0).unwrap();

        match refs {
            Some(DigestMap { map }) => {
                writer.write_all(&(map.len() as u64).to_le_bytes()).unwrap();
                for ref entry in map {
                    writer.write_all(&entry.body).unwrap();
                    writer.write_all(&entry.verity).unwrap();
                }
            }
            None => {
                writer.write_all(&0u64.to_le_bytes()).unwrap();
            }
        }

        SplitStreamWriter {
            repo,
            inline_content: vec![],
            writer,
            sha256: sha256.map(|x| (Sha256::new(), x)),
        }
    }

    fn write_fragment(writer: &mut impl Write, size: usize, data: &[u8]) -> Result<()> {
        writer.write_all(&(size as u64).to_le_bytes())?;
        Ok(writer.write_all(data)?)
    }

    /// flush any buffered inline data, taking new_value as the new value of the buffer
    fn flush_inline(&mut self, new_value: Vec<u8>) -> Result<()> {
        if !self.inline_content.is_empty() {
            SplitStreamWriter::write_fragment(
                &mut self.writer,
                self.inline_content.len(),
                &self.inline_content,
            )?;
            self.inline_content = new_value;
        }
        Ok(())
    }

    /// really, "add inline content to the buffer"
    /// you need to call .flush_inline() later
    pub fn write_inline(&mut self, data: &[u8]) {
        if let Some((ref mut sha256, ..)) = self.sha256 {
            sha256.update(data);
        }
        self.inline_content.extend(data);
    }

    /// write a reference to external data to the stream.  If the external data had padding in the
    /// stream which is not stored in the object then pass it here as well and it will be stored
    /// inline after the reference.
    fn write_reference(&mut self, reference: Sha256HashValue, padding: Vec<u8>) -> Result<()> {
        // Flush the inline data before we store the external reference.  Any padding from the
        // external data becomes the start of a new inline block.
        self.flush_inline(padding)?;

        SplitStreamWriter::write_fragment(&mut self.writer, 0, &reference)
    }

    pub fn write_external(&mut self, data: &[u8], padding: Vec<u8>) -> Result<()> {
        if let Some((ref mut sha256, ..)) = self.sha256 {
            sha256.update(data);
            sha256.update(&padding);
        }

        let id = self.repo.ensure_object(data)?;

        self.write_reference(id, padding)
    }

    pub fn done(mut self) -> Result<Sha256HashValue> {
        self.flush_inline(vec![])?;

        if let Some((context, expected)) = self.sha256 {
            if Into::<Sha256HashValue>::into(context.finalize()) != expected {
                bail!("Content doesn't have expected SHA256 hash value!");
            }
        }

        self.repo.ensure_object(&self.writer.finish()?)
    }
}

#[derive(Debug)]
pub enum SplitStreamData {
    Inline(Vec<u8>),
    External(Sha256HashValue),
}

// utility class to help read splitstreams
pub struct SplitStreamReader<R: Read> {
    decoder: Decoder<'static, BufReader<R>>,
    pub refs: DigestMap,
    /// Is non zero if we're in the process of reading internal chunks
    /// Once we find an internal chunk, `inline_bytes` is set to the size
    /// of the internal chunk
    inline_bytes: usize,
    /// If this is not None, then there is some padding in the next internal
    /// chunk that needs to be skipped
    skip_padding: Option<usize>,
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

fn read_into_vec(reader: &mut impl Read, vec: &mut Vec<u8>, size: usize) -> Result<()> {
    unsafe {
        vec.truncate(0);
        vec.reserve(size);
        reader.read_exact(std::slice::from_raw_parts_mut(vec.as_mut_ptr(), size))?;
        vec.set_len(size);
    }
    Ok(())
}

enum ChunkType {
    Eof,
    Inline,
    External(Sha256HashValue),
}

impl<R: Read> SplitStreamReader<R> {
    /// Creates a new zstd decoder using `reader`
    /// Reads the number of map_entries in the file, puts them in a vec
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
            skip_padding: None,
        })
    }

    fn ensure_chunk(
        &mut self,
        eof_ok: bool,
        ext_ok: bool,
        expected_bytes: usize,
    ) -> Result<ChunkType> {
        // Only try to read if there are no inline bytes left to read
        // Else we're still in the process of reading inline bytes
        if self.inline_bytes == 0 {
            match read_u64_le(&mut self.decoder)? {
                None => {
                    if !eof_ok {
                        bail!("Unexpected EOF when parsing splitstream");
                    }

                    return Ok(ChunkType::Eof);
                }

                Some(0) => {
                    let mut id = Sha256HashValue::EMPTY;
                    self.decoder.read_exact(&mut id)?;

                    if !ext_ok {
                        bail!(
                            "Unexpected external reference {} when parsing splitstream",
                            hex::encode(id)
                        );
                    }

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

    pub fn discard_padding(&mut self, size: usize) -> Result<()> {
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
            Ok(SplitStreamData::Inline(content))
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

    pub fn set_padding_to_skip(&mut self, padding: usize) {
        self.skip_padding = Some(padding);
    }

    pub fn get_tar_archive(&mut self) -> tar::Archive<&mut SplitStreamReader<R>> {
        return tar::Archive::new(self);
    }
}

impl<F: Read> Read for SplitStreamReader<F> {
    fn read(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        // if we're extracting tar, we are okay with an external chunk
        let ret = match self.ensure_chunk(true, true, 1) {
            Ok(ChunkType::Eof) => Ok(0),

            Ok(ChunkType::Inline) => {
                if let Some(padding) = self.skip_padding {
                    if let Err(e) = self.discard_padding(padding) {
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
                    };

                    self.skip_padding = None;
                }

                let n_bytes = std::cmp::min(data.len(), self.inline_bytes);
                self.decoder.read_exact(&mut data[0..n_bytes])?;
                self.inline_bytes -= n_bytes;

                Ok(n_bytes)
            }

            Ok(ChunkType::External(id)) => {
                data[..id.len()].copy_from_slice(&id);
                Ok(id.len())
            }

            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        };

        return ret;
    }
}
