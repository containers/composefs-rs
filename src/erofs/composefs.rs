use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::fsverity::FsVerityHashValue;

/* From linux/fs/overlayfs/overlayfs.h struct ovl_metacopy */
#[derive(Debug, FromBytes, Immutable, KnownLayout, IntoBytes)]
#[repr(C)]
pub(super) struct OverlayMetacopy<H: FsVerityHashValue> {
    version: u8,
    len: u8,
    flags: u8,
    digest_algo: u8,
    pub(super) digest: H,
}

impl<H: FsVerityHashValue> OverlayMetacopy<H> {
    pub(super) fn new(digest: &H) -> Self {
        Self {
            version: 0,
            len: size_of::<Self>() as u8,
            flags: 0,
            digest_algo: H::ALGORITHM,
            digest: digest.clone(),
        }
    }

    pub(super) fn valid(&self) -> bool {
        self.version == 0
            && self.len == size_of::<Self>() as u8
            && self.flags == 0
            && self.digest_algo == H::ALGORITHM
    }
}
