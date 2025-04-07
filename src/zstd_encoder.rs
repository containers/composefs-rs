use std::io::{self, Write};

use sha2::{Digest, Sha256};

use anyhow::{bail, Result};

use crate::{
    fsverity::{FsVerityHashValue, Sha256HashValue},
    splitstream::DigestMap,
};

pub(crate) struct ZstdWriter {
    writer: zstd::Encoder<'static, Vec<u8>>,
    pub(crate) sha256_builder: Option<(Sha256, Sha256HashValue)>,
}

impl ZstdWriter {
    pub fn new(sha256: Option<Sha256HashValue>, refs: Option<DigestMap>) -> Self {
        Self {
            writer: ZstdWriter::instantiate_writer(refs),
            sha256_builder: sha256.map(|x| (Sha256::new(), x)),
        }
    }

    fn instantiate_writer(refs: Option<DigestMap>) -> zstd::Encoder<'static, Vec<u8>> {
        let mut writer = zstd::Encoder::new(vec![], 0).unwrap();

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

        return writer;
    }

    pub(crate) fn write_fragment(&mut self, size: usize, data: &[u8]) -> Result<()> {
        self.writer.write_all(&(size as u64).to_le_bytes())?;
        Ok(self.writer.write_all(data)?)
    }

    pub(crate) fn update_sha(&mut self, data: &[u8]) {
        if let Some((sha256, ..)) = &mut self.sha256_builder {
            sha256.update(&data);
        }
    }

    pub(crate) fn flush_inline(&mut self, inline_content: &Vec<u8>) -> Result<()> {
        if inline_content.is_empty() {
            return Ok(());
        }

        self.write_fragment(inline_content.len(), &inline_content)?;

        Ok(())
    }

    pub(crate) fn finalize_sha256_builder(&mut self) -> Result<Sha256HashValue> {
        let sha256_builder = std::mem::replace(&mut self.sha256_builder, None);

        let mut sha = Sha256HashValue::EMPTY;

        if let Some((context, expected)) = sha256_builder {
            let final_sha = Into::<Sha256HashValue>::into(context.finalize());

            if final_sha != expected {
                bail!(
                    "Content doesn't have expected SHA256 hash value!\nExpected: {}, final: {}",
                    hex::encode(expected),
                    hex::encode(final_sha)
                );
            }

            sha = final_sha;
        }

        return Ok(sha);
    }

    pub(crate) fn finish(self) -> io::Result<Vec<u8>> {
        self.writer.finish()
    }
}
