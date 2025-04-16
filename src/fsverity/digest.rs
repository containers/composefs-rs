use core::{cmp::min, mem::size_of};

use sha2::Digest;

use super::FsVerityHashValue;

#[derive(Debug)]
struct FsVerityLayer<H: FsVerityHashValue, const LG_BLKSZ: u8 = 12> {
    context: H::Digest,
    remaining: usize,
}

impl<H: FsVerityHashValue, const LG_BLKSZ: u8> FsVerityLayer<H, LG_BLKSZ> {
    fn new() -> Self {
        Self {
            context: H::Digest::new(),
            remaining: 1 << LG_BLKSZ,
        }
    }

    fn add_data(&mut self, data: &[u8]) {
        self.context.update(data);
        self.remaining -= data.len();
    }

    fn complete(&mut self) -> H {
        self.context.update([0].repeat(self.remaining));
        self.remaining = 1 << LG_BLKSZ;
        self.context.finalize_reset().into()
    }
}

#[derive(Debug)]
pub(super) struct FsVerityHasher<H: FsVerityHashValue, const LG_BLKSZ: u8 = 12> {
    layers: Vec<FsVerityLayer<H, LG_BLKSZ>>,
    value: Option<H>,
    n_bytes: u64,
}

impl<H: FsVerityHashValue, const LG_BLKSZ: u8> FsVerityHasher<H, LG_BLKSZ> {
    pub(super) fn hash(buffer: &[u8]) -> H {
        let mut hasher = Self::new();

        let mut start = 0;
        while start < buffer.len() {
            let end = min(start + (1 << LG_BLKSZ), buffer.len());
            hasher.add_data(&buffer[start..end]);
            start = end;
        }

        hasher.digest()
    }

    fn new() -> Self {
        Self {
            layers: vec![],
            value: None,
            n_bytes: 0,
        }
    }

    fn add_data(&mut self, data: &[u8]) {
        if let Some(value) = self.value.take() {
            // We had a complete value, but now we're adding new data.
            // This means that we need to add a new hash layer...
            let mut new_layer = FsVerityLayer::new();
            new_layer.add_data(value.as_bytes());
            self.layers.push(new_layer);
        }

        // Get the value of this block
        let mut context = FsVerityLayer::<H, LG_BLKSZ>::new();
        context.add_data(data);
        let mut value = context.complete();
        self.n_bytes += data.len() as u64;

        for layer in self.layers.iter_mut() {
            // We have a layer we need to hash this value into
            layer.add_data(value.as_bytes());
            if layer.remaining != 0 {
                return;
            }
            // ...but now this layer itself is now complete, so get the value of *it*.
            value = layer.complete();
        }

        // If we made it this far, we completed the last layer and have a value.  Store it.
        self.value = Some(value);
    }

    fn root_hash(&mut self) -> H {
        if let Some(value) = &self.value {
            value.clone()
        } else {
            let mut value = H::EMPTY;

            for layer in self.layers.iter_mut() {
                // We have a layer we need to hash this value into
                if value != H::EMPTY {
                    layer.add_data(value.as_bytes());
                }
                if layer.remaining != (1 << LG_BLKSZ) {
                    // ...but now this layer itself is complete, so get the value of *it*.
                    value = layer.complete();
                } else {
                    value = H::EMPTY;
                }
            }

            self.value = Some(value.clone());

            value
        }
    }

    fn digest(&mut self) -> H {
        /*
        let mut root_hash = [0u8; 64];
        let result = self.root_hash();
        root_hash[..result.as_ref().len()].copy_from_slice(result.as_ref());

        let descriptor = FsVerityDescriptor {
            version: 1,
            hash_algorithm: H::ALGORITHM,
            log_blocksize: LG_BLKSZ,
            salt_size: 0,
            reserved_0x04: U32::new(0),
            data_size: U64::new(self.n_bytes),
            root_hash,
            salt: [0; 32],
            reserved: [0; 144],
        };

        let mut context = H::Digest::new();
        context.update(descriptor.as_bytes());
        context.finalize().into()
            */

        let mut context = H::Digest::new();
        context.update(1u8.to_le_bytes()); /* version */
        context.update(H::ALGORITHM.to_le_bytes()); /* hash_algorithm */
        context.update(LG_BLKSZ.to_le_bytes()); /* log_blocksize */
        context.update(0u8.to_le_bytes()); /* salt_size */
        context.update([0; 4]); /* reserved */
        context.update(self.n_bytes.to_le_bytes());
        context.update(self.root_hash().as_bytes());
        context.update([0].repeat(64 - size_of::<H>()));
        context.update([0; 32]); /* salt */
        context.update([0; 144]); /* reserved */
        context.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use crate::fsverity::{Sha256HashValue, Sha512HashValue};

    use super::*;

    #[test]
    fn test_digest() {
        assert_eq!(
            FsVerityHasher::<Sha256HashValue, 12>::hash(b"hello world").to_hex(),
            "1e2eaa4202d750a41174ee454970b92c1bc2f925b1e35076d8c7d5f56362ba64"
        );

        assert_eq!(
            FsVerityHasher::<Sha512HashValue, 12>::hash(b"hello world").to_hex(),
            "18430270729d162d4e469daca123ae61893db4b0583d8f7081e3bf4f92b88ba514e7982f10733fb6aa895195c5ae8fd2eb2c47a8be05513ce5a0c51a6f570409"
        );
    }
}
