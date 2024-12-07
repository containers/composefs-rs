use std::cmp::min;

use sha2::{Digest, Sha256};

use super::Sha256HashValue;

// TODO: support Sha512

#[derive(Debug)]
struct FsVerityLayer {
    context: Sha256,
    remaining: usize,
}

impl FsVerityLayer {
    fn new() -> FsVerityLayer {
        FsVerityLayer {
            context: Sha256::new(),
            remaining: 4096,
        }
    }

    fn add_data(&mut self, data: &[u8]) {
        self.context.update(data);
        self.remaining -= data.len();
    }

    fn complete(&mut self) -> Sha256HashValue {
        self.context.update(&[0u8; 4096][..self.remaining]);
        self.remaining = 4096;
        self.context.finalize_reset().into()
    }
}

#[derive(Debug)]
pub struct FsVerityHasher {
    layers: Vec<FsVerityLayer>,
    value: Option<Sha256HashValue>,
    n_bytes: u64,
}

impl FsVerityHasher {
    pub fn hash(buffer: &[u8]) -> Sha256HashValue {
        let mut hasher = FsVerityHasher::new();

        let mut start = 0;
        while start < buffer.len() {
            let end = min(start + 4096, buffer.len());
            hasher.add_data(&buffer[start..end]);
            start = end;
        }

        hasher.digest()
    }

    pub fn new() -> FsVerityHasher {
        FsVerityHasher {
            layers: vec![],
            value: None,
            n_bytes: 0,
        }
    }

    pub fn add_data(&mut self, data: &[u8]) {
        if let Some(value) = self.value {
            // We had a complete value, but now we're adding new data.
            // This means that we need to add a new hash layer...
            let mut new_layer = FsVerityLayer::new();
            new_layer.add_data(&value);
            self.layers.push(new_layer);
            self.value = None;
        }

        // Get the value of this block
        let mut context = FsVerityLayer::new();
        context.add_data(data);
        let mut value = context.complete();
        self.n_bytes += data.len() as u64;

        for layer in self.layers.iter_mut() {
            // We have a layer we need to hash this value into
            layer.add_data(&value);
            if layer.remaining != 0 {
                return;
            }
            // ...but now this layer itself is now complete, so get the value of *it*.
            value = layer.complete();
        }

        // If we made it this far, we completed the last layer and have a value.  Store it.
        self.value = Some(value);
    }

    pub fn root_hash(&mut self) -> Sha256HashValue {
        if let Some(value) = self.value {
            value
        } else {
            let mut value = [0u8; 32];

            for layer in self.layers.iter_mut() {
                // We have a layer we need to hash this value into
                if value != [0u8; 32] {
                    layer.add_data(&value);
                }
                if layer.remaining != 4096 {
                    // ...but now this layer itself is complete, so get the value of *it*.
                    value = layer.complete();
                } else {
                    value = [0u8; 32];
                }
            }

            self.value = Some(value);

            value
        }
    }

    pub fn digest(&mut self) -> Sha256HashValue {
        /*
        let descriptor = FsVerityDescriptor {
            version: 1,
            hash_algorithm: 1,
            log_blocksize: 12,
            salt_size: 0,
            reserved_0x04: 0,
            data_size: self.n_bytes,
            root_hash: (self.root_hash(), [0; 32]),
            salt: [0; 32],
            reserved: [0; 144],
        };

        let mut context = Sha256::new();
        context.update(descriptor);
        return context.finalize().into();
        */

        let mut context = Sha256::new();
        context.update(1u8.to_le_bytes()); /* version */
        context.update(1u8.to_le_bytes()); /* hash_algorithm */
        context.update(12u8.to_le_bytes()); /* log_blocksize */
        context.update(0u8.to_le_bytes()); /* salt_size */
        context.update([0; 4]); /* reserved */
        context.update(self.n_bytes.to_le_bytes());
        context.update(self.root_hash());
        context.update([0; 32]);
        context.update([0; 32]); /* salt */
        context.update([0; 144]); /* reserved */
        context.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;

    #[test]
    fn test_digest() -> Result<()> {
        let digest = FsVerityHasher::hash(b"hello world");
        assert_eq!(
            digest,
            [
                30, 46, 170, 66, 2, 215, 80, 164, 17, 116, 238, 69, 73, 112, 185, 44, 27, 194, 249,
                37, 177, 227, 80, 118, 216, 199, 213, 245, 99, 98, 186, 100
            ]
        );
        Ok(())
    }
}
