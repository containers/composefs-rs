//! EROFS image reading and parsing functionality.
//!
//! This module provides safe parsing and navigation of EROFS filesystem
//! images, including inode traversal, directory reading, and object
//! reference collection for garbage collection.

use core::mem::size_of;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsStr;
use std::ops::Range;
use std::os::unix::ffi::OsStrExt;
use std::rc::Rc;

use anyhow::Context;
use thiserror::Error;
use zerocopy::{little_endian::U32, FromBytes, Immutable, KnownLayout};

use super::{
    composefs::OverlayMetacopy,
    format::{
        CompactInodeHeader, ComposefsHeader, DataLayout, DirectoryEntryHeader, ExtendedInodeHeader,
        InodeXAttrHeader, ModeField, Superblock, XAttrHeader, S_IFBLK, S_IFCHR, S_IFIFO, S_IFLNK,
        S_IFMT, S_IFREG, S_IFSOCK, XATTR_PREFIXES,
    },
};
use crate::fsverity::FsVerityHashValue;
use crate::tree;

/// Rounds up a value to the nearest multiple of `to`
pub fn round_up(n: usize, to: usize) -> usize {
    (n + to - 1) & !(to - 1)
}

/// Common interface for accessing inode header fields across different layouts
pub trait InodeHeader {
    /// Returns the data layout method used by this inode
    fn data_layout(&self) -> DataLayout;
    /// Returns the extended attribute inode count
    fn xattr_icount(&self) -> u16;
    /// Returns the file mode
    fn mode(&self) -> ModeField;
    /// Returns the file size in bytes
    fn size(&self) -> u64;
    /// Returns the union field value (block address, device number, etc.)
    fn u(&self) -> u32;
    /// Returns the number of hard links
    fn nlink(&self) -> u32;

    /// Calculates the number of additional bytes after the header
    fn additional_bytes(&self, blkszbits: u8) -> Result<usize, ErofsReaderError> {
        let block_size: usize = 1usize
            .checked_shl(blkszbits.into())
            .ok_or_else(|| ErofsReaderError::InvalidImage("blkszbits overflow".into()))?;
        let data_layout = self.data_layout();
        Ok(self.xattr_size()
            + match data_layout {
                DataLayout::FlatPlain => 0,
                DataLayout::FlatInline => {
                    let size = usize::try_from(self.size()).map_err(|_| {
                        ErofsReaderError::InvalidImage("inode size too large for platform".into())
                    })?;
                    size % block_size
                }
                DataLayout::ChunkBased => 4,
            })
    }

    /// Calculates the size of the extended attributes section
    fn xattr_size(&self) -> usize {
        match self.xattr_icount() {
            0 => 0,
            n => (n as usize - 1) * 4 + 12,
        }
    }
}

impl InodeHeader for ExtendedInodeHeader {
    fn data_layout(&self) -> DataLayout {
        self.format.try_into().unwrap()
    }

    fn xattr_icount(&self) -> u16 {
        self.xattr_icount.get()
    }

    fn mode(&self) -> ModeField {
        self.mode
    }

    fn size(&self) -> u64 {
        self.size.get()
    }

    fn u(&self) -> u32 {
        self.u.get()
    }

    fn nlink(&self) -> u32 {
        self.nlink.get()
    }
}

impl InodeHeader for CompactInodeHeader {
    fn data_layout(&self) -> DataLayout {
        self.format.try_into().unwrap()
    }

    fn xattr_icount(&self) -> u16 {
        self.xattr_icount.get()
    }

    fn mode(&self) -> ModeField {
        self.mode
    }

    fn size(&self) -> u64 {
        self.size.get() as u64
    }

    fn u(&self) -> u32 {
        self.u.get()
    }

    fn nlink(&self) -> u32 {
        self.nlink.get().into()
    }
}

/// Extended attribute entry with header and variable-length data
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
pub struct XAttr {
    /// Extended attribute header
    pub header: XAttrHeader,
    /// Variable-length data containing name suffix and value
    pub data: [u8],
}

/// Inode structure with header and variable-length data
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
pub struct Inode<Header: InodeHeader> {
    /// Inode header (compact or extended)
    pub header: Header,
    /// Variable-length data containing xattrs and inline content
    pub data: [u8],
}

/// Extended attributes section of an inode
#[repr(C)]
#[derive(Debug, FromBytes, Immutable, KnownLayout)]
pub struct InodeXAttrs {
    /// Extended attributes header
    pub header: InodeXAttrHeader,
    /// Variable-length data containing shared xattr refs and local xattrs
    pub data: [u8],
}

impl XAttrHeader {
    /// Calculates the total size of this xattr including padding
    pub fn calculate_n_elems(&self) -> usize {
        round_up(self.name_len as usize + self.value_size.get() as usize, 4)
    }
}

impl XAttr {
    /// Parses an xattr from a byte slice, returning the xattr and remaining bytes
    pub fn from_prefix(data: &[u8]) -> (&XAttr, &[u8]) {
        let header = XAttrHeader::ref_from_bytes(&data[..4]).unwrap();
        Self::ref_from_prefix_with_elems(data, header.calculate_n_elems()).unwrap()
    }

    /// Returns the attribute name suffix
    pub fn suffix(&self) -> &[u8] {
        &self.data[..self.header.name_len as usize]
    }

    /// Returns the attribute value
    pub fn value(&self) -> &[u8] {
        &self.data[self.header.name_len as usize..][..self.header.value_size.get() as usize]
    }

    /// Returns the padding bytes after the value
    pub fn padding(&self) -> &[u8] {
        &self.data[self.header.name_len as usize + self.header.value_size.get() as usize..]
    }
}

/// Operations on inode data
pub trait InodeOps {
    /// Returns the extended attributes section if present
    fn xattrs(&self) -> Option<&InodeXAttrs>;
    /// Returns the inline data portion
    fn inline(&self) -> Option<&[u8]>;
    /// Returns the range of block IDs used by this inode
    fn blocks(&self, blkszbits: u8) -> Result<Range<u64>, ErofsReaderError>;
}

impl<Header: InodeHeader> InodeHeader for &Inode<Header> {
    fn data_layout(&self) -> DataLayout {
        self.header.data_layout()
    }

    fn xattr_icount(&self) -> u16 {
        self.header.xattr_icount()
    }

    fn mode(&self) -> ModeField {
        self.header.mode()
    }

    fn size(&self) -> u64 {
        self.header.size()
    }

    fn u(&self) -> u32 {
        self.header.u()
    }

    fn nlink(&self) -> u32 {
        self.header.nlink()
    }
}

impl<Header: InodeHeader> InodeOps for &Inode<Header> {
    fn xattrs(&self) -> Option<&InodeXAttrs> {
        match self.header.xattr_size() {
            0 => None,
            n => Some(InodeXAttrs::ref_from_bytes(&self.data[..n]).unwrap()),
        }
    }

    fn inline(&self) -> Option<&[u8]> {
        let data = &self.data[self.header.xattr_size()..];

        if data.is_empty() {
            return None;
        }

        Some(data)
    }

    fn blocks(&self, blkszbits: u8) -> Result<Range<u64>, ErofsReaderError> {
        let size = self.header.size();
        let block_size: u64 = 1u64
            .checked_shl(blkszbits.into())
            .ok_or_else(|| ErofsReaderError::InvalidImage("blkszbits overflow".into()))?;
        let start = self.header.u() as u64;
        let data_layout = self.header.data_layout();

        Ok(match data_layout {
            DataLayout::FlatPlain => Range {
                start,
                end: start
                    .checked_add(size.div_ceil(block_size))
                    .ok_or_else(|| ErofsReaderError::InvalidImage("block range overflow".into()))?,
            },
            DataLayout::FlatInline => Range {
                start,
                end: start
                    .checked_add(size / block_size)
                    .ok_or_else(|| ErofsReaderError::InvalidImage("block range overflow".into()))?,
            },
            DataLayout::ChunkBased => Range { start, end: start },
        })
    }
}

// this lets us avoid returning Box<dyn InodeOp> from Image.inode()
// but ... wow.
/// Inode type enum allowing static dispatch for different header layouts
#[derive(Debug)]
pub enum InodeType<'img> {
    /// Compact inode with 32-byte header
    Compact(&'img Inode<CompactInodeHeader>),
    /// Extended inode with 64-byte header
    Extended(&'img Inode<ExtendedInodeHeader>),
}

impl InodeHeader for InodeType<'_> {
    fn u(&self) -> u32 {
        match self {
            Self::Compact(inode) => inode.u(),
            Self::Extended(inode) => inode.u(),
        }
    }

    fn size(&self) -> u64 {
        match self {
            Self::Compact(inode) => inode.size(),
            Self::Extended(inode) => inode.size(),
        }
    }

    fn xattr_icount(&self) -> u16 {
        match self {
            Self::Compact(inode) => inode.xattr_icount(),
            Self::Extended(inode) => inode.xattr_icount(),
        }
    }

    fn data_layout(&self) -> DataLayout {
        match self {
            Self::Compact(inode) => inode.data_layout(),
            Self::Extended(inode) => inode.data_layout(),
        }
    }

    fn mode(&self) -> ModeField {
        match self {
            Self::Compact(inode) => inode.mode(),
            Self::Extended(inode) => inode.mode(),
        }
    }

    fn nlink(&self) -> u32 {
        match self {
            Self::Compact(inode) => inode.nlink(),
            Self::Extended(inode) => inode.nlink(),
        }
    }
}

impl InodeOps for InodeType<'_> {
    fn xattrs(&self) -> Option<&InodeXAttrs> {
        match self {
            Self::Compact(inode) => inode.xattrs(),
            Self::Extended(inode) => inode.xattrs(),
        }
    }

    fn inline(&self) -> Option<&[u8]> {
        match self {
            Self::Compact(inode) => inode.inline(),
            Self::Extended(inode) => inode.inline(),
        }
    }

    fn blocks(&self, blkszbits: u8) -> Result<Range<u64>, ErofsReaderError> {
        match self {
            Self::Compact(inode) => inode.blocks(blkszbits),
            Self::Extended(inode) => inode.blocks(blkszbits),
        }
    }
}

/// Parsed EROFS image with references to key structures
#[derive(Debug)]
pub struct Image<'i> {
    /// Raw image bytes
    pub image: &'i [u8],
    /// Composefs header
    pub header: &'i ComposefsHeader,
    /// Block size in bits
    pub blkszbits: u8,
    /// Block size in bytes
    pub block_size: usize,
    /// Superblock
    pub sb: &'i Superblock,
    /// Inode metadata region
    pub inodes: &'i [u8],
    /// Extended attributes region
    pub xattrs: &'i [u8],
}

impl<'img> Image<'img> {
    /// Opens an EROFS image from raw bytes
    pub fn open(image: &'img [u8]) -> Result<Self, ErofsReaderError> {
        let header = ComposefsHeader::ref_from_prefix(image)
            .map_err(|_| ErofsReaderError::InvalidImage("cannot parse header".into()))?
            .0;
        let sb_data = image.get(1024..).ok_or_else(|| {
            ErofsReaderError::InvalidImage("image too small for superblock".into())
        })?;
        let sb = Superblock::ref_from_prefix(sb_data)
            .map_err(|_| ErofsReaderError::InvalidImage("cannot parse superblock".into()))?
            .0;
        let blkszbits = sb.blkszbits;
        if blkszbits as u32 >= usize::BITS {
            return Err(ErofsReaderError::InvalidImage(format!(
                "blkszbits {blkszbits} >= platform word size {}",
                usize::BITS
            )));
        }
        let block_size = 1usize << blkszbits;
        let inodes_start = (sb.meta_blkaddr.get() as usize)
            .checked_mul(block_size)
            .ok_or(ErofsReaderError::OutOfBounds)?;
        let xattrs_start = (sb.xattr_blkaddr.get() as usize)
            .checked_mul(block_size)
            .ok_or(ErofsReaderError::OutOfBounds)?;
        let inodes = image
            .get(inodes_start..)
            .ok_or(ErofsReaderError::OutOfBounds)?;
        let xattrs = image
            .get(xattrs_start..)
            .ok_or(ErofsReaderError::OutOfBounds)?;
        Ok(Image {
            image,
            header,
            blkszbits,
            block_size,
            sb,
            inodes,
            xattrs,
        })
    }

    /// Returns an inode by its ID
    pub fn inode(&self, id: u64) -> Result<InodeType<'_>, ErofsReaderError> {
        let offset = usize::try_from(id)
            .ok()
            .and_then(|id| id.checked_mul(32))
            .ok_or(ErofsReaderError::InvalidInode(id))?;
        let inode_data = self
            .inodes
            .get(offset..)
            .ok_or(ErofsReaderError::InvalidInode(id))?;
        let first_byte = *inode_data
            .first()
            .ok_or(ErofsReaderError::InvalidInode(id))?;
        if first_byte & 1 != 0 {
            let header = ExtendedInodeHeader::ref_from_bytes(
                inode_data
                    .get(..64)
                    .ok_or(ErofsReaderError::InvalidInode(id))?,
            )
            .map_err(|_| ErofsReaderError::InvalidInode(id))?;
            Ok(InodeType::Extended(
                Inode::<ExtendedInodeHeader>::ref_from_prefix_with_elems(
                    inode_data,
                    header.additional_bytes(self.blkszbits)?,
                )
                .map_err(|_| ErofsReaderError::InvalidInode(id))?
                .0,
            ))
        } else {
            let header = CompactInodeHeader::ref_from_bytes(
                inode_data
                    .get(..32)
                    .ok_or(ErofsReaderError::InvalidInode(id))?,
            )
            .map_err(|_| ErofsReaderError::InvalidInode(id))?;
            Ok(InodeType::Compact(
                Inode::<CompactInodeHeader>::ref_from_prefix_with_elems(
                    inode_data,
                    header.additional_bytes(self.blkszbits)?,
                )
                .map_err(|_| ErofsReaderError::InvalidInode(id))?
                .0,
            ))
        }
    }

    /// Returns a shared extended attribute by its ID
    pub fn shared_xattr(&self, id: u32) -> Result<&XAttr, ErofsReaderError> {
        let start = (id as usize)
            .checked_mul(4)
            .ok_or(ErofsReaderError::OutOfBounds)?;
        let xattr_data = self
            .xattrs
            .get(start..)
            .ok_or(ErofsReaderError::OutOfBounds)?;
        let header =
            XAttrHeader::ref_from_bytes(xattr_data.get(..4).ok_or(ErofsReaderError::OutOfBounds)?)
                .map_err(|_| ErofsReaderError::OutOfBounds)?;
        Ok(
            XAttr::ref_from_prefix_with_elems(xattr_data, header.calculate_n_elems())
                .map_err(|_| ErofsReaderError::OutOfBounds)?
                .0,
        )
    }

    /// Returns a data block by its ID
    pub fn block(&self, id: u64) -> Result<&[u8], ErofsReaderError> {
        let start = usize::try_from(id)
            .ok()
            .and_then(|id| id.checked_mul(self.block_size))
            .ok_or(ErofsReaderError::OutOfBounds)?;
        let end = start
            .checked_add(self.block_size)
            .ok_or(ErofsReaderError::OutOfBounds)?;
        self.image
            .get(start..end)
            .ok_or(ErofsReaderError::OutOfBounds)
    }

    /// Returns a data block by its ID as a DataBlock reference
    pub fn data_block(&self, id: u64) -> Result<&DataBlock, ErofsReaderError> {
        DataBlock::ref_from_bytes(self.block(id)?).map_err(|_| ErofsReaderError::OutOfBounds)
    }

    /// Returns a directory block by its ID
    pub fn directory_block(&self, id: u64) -> Result<&DirectoryBlock, ErofsReaderError> {
        DirectoryBlock::ref_from_bytes(self.block(id)?).map_err(|_| ErofsReaderError::OutOfBounds)
    }

    /// Returns the root directory inode
    pub fn root(&self) -> Result<InodeType<'_>, ErofsReaderError> {
        self.inode(self.sb.root_nid.get() as u64)
    }
}

// TODO: there must be an easier way...
#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C)]
struct Array<T>([T]);

impl InodeXAttrs {
    /// Returns the array of shared xattr IDs
    pub fn shared(&self) -> &[U32] {
        &Array::ref_from_prefix_with_elems(&self.data, self.header.shared_count as usize)
            .unwrap()
            .0
             .0
    }

    /// Returns an iterator over local (non-shared) xattrs
    pub fn local(&self) -> XAttrIter<'_> {
        XAttrIter {
            data: &self.data[self.header.shared_count as usize * 4..],
        }
    }
}

/// Iterator over local extended attributes
#[derive(Debug)]
pub struct XAttrIter<'img> {
    data: &'img [u8],
}

impl<'img> Iterator for XAttrIter<'img> {
    type Item = &'img XAttr;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.data.is_empty() {
            let (result, rest) = XAttr::from_prefix(self.data);
            self.data = rest;
            Some(result)
        } else {
            None
        }
    }
}

/// Data block containing file content
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
pub struct DataBlock(pub [u8]);

/// Directory block containing directory entries
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
pub struct DirectoryBlock(pub [u8]);

impl DirectoryBlock {
    /// Returns the directory entry header at the given index
    pub fn get_entry_header(&self, n: usize) -> &DirectoryEntryHeader {
        let entry_data = &self.0
            [n * size_of::<DirectoryEntryHeader>()..(n + 1) * size_of::<DirectoryEntryHeader>()];
        DirectoryEntryHeader::ref_from_bytes(entry_data).unwrap()
    }

    /// Returns all directory entry headers as a slice
    pub fn get_entry_headers(&self) -> &[DirectoryEntryHeader] {
        &Array::ref_from_prefix_with_elems(&self.0, self.n_entries())
            .unwrap()
            .0
             .0
    }

    /// Returns the number of entries in this directory block
    pub fn n_entries(&self) -> usize {
        let first = self.get_entry_header(0);
        let offset = first.name_offset.get();
        assert!(offset != 0);
        assert!(offset.is_multiple_of(12));
        offset as usize / 12
    }

    /// Returns an iterator over directory entries
    pub fn entries(&self) -> DirectoryEntries<'_> {
        DirectoryEntries {
            block: self,
            length: self.n_entries(),
            position: 0,
        }
    }
}

// High-level iterator interface
/// A single directory entry with header and name
#[derive(Debug)]
pub struct DirectoryEntry<'a> {
    /// Directory entry header
    pub header: &'a DirectoryEntryHeader,
    /// Entry name
    pub name: &'a [u8],
}

impl DirectoryEntry<'_> {
    fn nid(&self) -> u64 {
        self.header.inode_offset.get()
    }
}

/// Iterator over directory entries in a directory block
#[derive(Debug)]
pub struct DirectoryEntries<'d> {
    block: &'d DirectoryBlock,
    length: usize,
    position: usize,
}

impl<'d> Iterator for DirectoryEntries<'d> {
    type Item = DirectoryEntry<'d>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position < self.length {
            let header = self.block.get_entry_header(self.position);
            let name_start = header.name_offset.get() as usize;
            self.position += 1;

            let name = if self.position == self.length {
                let with_padding = &self.block.0[name_start..];
                let end = with_padding.partition_point(|c| *c != 0);
                &with_padding[..end]
            } else {
                let next = self.block.get_entry_header(self.position);
                let name_end = next.name_offset.get() as usize;
                &self.block.0[name_start..name_end]
            };

            Some(DirectoryEntry { header, name })
        } else {
            None
        }
    }
}

/// Errors that can occur when reading EROFS images
#[derive(Error, Debug)]
pub enum ErofsReaderError {
    /// Invalid EROFS image data
    #[error("Invalid image: {0}")]
    InvalidImage(String),
    /// Invalid inode ID
    #[error("Invalid inode: {0}")]
    InvalidInode(u64),
    /// Offset or index out of bounds
    #[error("Offset out of bounds")]
    OutOfBounds,
    /// Directory has multiple hard links (not allowed)
    #[error("Hardlinked directories detected")]
    DirectoryHardlinks,
    /// Directory nesting exceeds maximum depth
    #[error("Maximum directory depth exceeded")]
    DepthExceeded,
    /// The '.' entry is invalid
    #[error("Invalid '.' entry in directory")]
    InvalidSelfReference,
    /// The '..' entry is invalid
    #[error("Invalid '..' entry in directory")]
    InvalidParentReference,
    /// File type in directory entry doesn't match inode
    #[error("File type in dirent doesn't match type in inode")]
    FileTypeMismatch,
}

type ReadResult<T> = Result<T, ErofsReaderError>;

/// Collects object references from an EROFS image for garbage collection
#[derive(Debug)]
pub struct ObjectCollector<ObjectID: FsVerityHashValue> {
    visited_nids: HashSet<u64>,
    nids_to_visit: BTreeSet<u64>,
    objects: HashSet<ObjectID>,
}

impl<ObjectID: FsVerityHashValue> ObjectCollector<ObjectID> {
    fn visit_xattr(&mut self, attr: &XAttr) {
        // This is the index of "trusted".  See XATTR_PREFIXES in format.rs.
        if attr.header.name_index != 4 {
            return;
        }
        if attr.suffix() != b"overlay.metacopy" {
            return;
        }
        if let Ok(value) = OverlayMetacopy::read_from_bytes(attr.value()) {
            if value.valid() {
                self.objects.insert(value.digest);
            }
        }
    }

    fn visit_xattrs(&mut self, img: &Image, xattrs: &InodeXAttrs) -> ReadResult<()> {
        for id in xattrs.shared() {
            self.visit_xattr(img.shared_xattr(id.get())?);
        }
        for attr in xattrs.local() {
            self.visit_xattr(attr);
        }
        Ok(())
    }

    fn visit_directory_block(&mut self, block: &DirectoryBlock) {
        for entry in block.entries() {
            if entry.name != b"." && entry.name != b".." {
                let nid = entry.nid();
                if !self.visited_nids.contains(&nid) {
                    self.nids_to_visit.insert(nid);
                }
            }
        }
    }

    fn visit_nid(&mut self, img: &Image, nid: u64) -> ReadResult<()> {
        let first_time = self.visited_nids.insert(nid);
        assert!(first_time); // should not have been added to the "to visit" list otherwise

        let inode = img.inode(nid)?;

        if let Some(xattrs) = inode.xattrs() {
            self.visit_xattrs(img, xattrs)?;
        }

        if inode.mode().is_dir() {
            for blkid in inode.blocks(img.sb.blkszbits)? {
                self.visit_directory_block(img.directory_block(blkid)?);
            }

            if let Some(inline) = inode.inline() {
                let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
                self.visit_directory_block(inline_block);
            }
        }

        Ok(())
    }
}

/// Collects all object references from an EROFS image
///
/// This function walks the directory tree and extracts fsverity object IDs
/// from overlay.metacopy xattrs for garbage collection purposes.
///
/// Returns a set of all referenced object IDs.
pub fn collect_objects<ObjectID: FsVerityHashValue>(image: &[u8]) -> ReadResult<HashSet<ObjectID>> {
    let img = Image::open(image)?;
    let mut this = ObjectCollector {
        visited_nids: HashSet::new(),
        nids_to_visit: BTreeSet::new(),
        objects: HashSet::new(),
    };

    // nids_to_visit is initialized with the root directory.  Visiting directory nids will add
    // more nids to the "to visit" list.  Keep iterating until it's empty.
    this.nids_to_visit.insert(img.sb.root_nid.get() as u64);
    while let Some(nid) = this.nids_to_visit.pop_first() {
        this.visit_nid(&img, nid)?;
    }
    Ok(this.objects)
}

/// Construct the full xattr name from a prefix index and suffix.
fn construct_xattr_name(xattr: &XAttr) -> Vec<u8> {
    let prefix = XATTR_PREFIXES[xattr.header.name_index as usize];
    let suffix = xattr.suffix();
    let mut full_name = Vec::with_capacity(prefix.len() + suffix.len());
    full_name.extend_from_slice(prefix);
    full_name.extend_from_slice(suffix);
    full_name
}

/// Build a `tree::Stat` from an erofs inode, reversing the xattr namespace
/// transformations applied by the writer:
/// - Strips `trusted.overlay.metacopy` and `trusted.overlay.redirect`
/// - Unescapes `trusted.overlay.overlay.X` back to `trusted.overlay.X`
fn stat_from_inode_for_tree(img: &Image, inode: &InodeType) -> anyhow::Result<tree::Stat> {
    let (st_mode, st_uid, st_gid, st_mtim_sec) = match inode {
        InodeType::Compact(inode) => (
            inode.header.mode.0.get() as u32 & 0o7777,
            inode.header.uid.get() as u32,
            inode.header.gid.get() as u32,
            // Compact inodes don't store mtime; the writer uses build_time
            // but for round-trip purposes, 0 matches what was written for
            // compact headers (the writer always uses ExtendedInodeHeader)
            0i64,
        ),
        InodeType::Extended(inode) => (
            inode.header.mode.0.get() as u32 & 0o7777,
            inode.header.uid.get(),
            inode.header.gid.get(),
            inode.header.mtime.get() as i64,
        ),
    };

    let mut xattrs = BTreeMap::new();

    if let Some(xattrs_section) = inode.xattrs() {
        // Process shared xattrs
        for id in xattrs_section.shared() {
            let xattr = img.shared_xattr(id.get())?;
            if let Some((name, value)) = transform_xattr(xattr) {
                xattrs.insert(name, value);
            }
        }
        // Process local xattrs
        for xattr in xattrs_section.local() {
            if let Some((name, value)) = transform_xattr(xattr) {
                xattrs.insert(name, value);
            }
        }
    }

    Ok(tree::Stat {
        st_mode,
        st_uid,
        st_gid,
        st_mtim_sec,
        xattrs: RefCell::new(xattrs),
    })
}

/// Transform a single xattr, reversing writer escaping.
/// Returns None for internal overlay xattrs that should be stripped.
fn transform_xattr(xattr: &XAttr) -> Option<(Box<OsStr>, Box<[u8]>)> {
    let full_name = construct_xattr_name(xattr);

    // Skip internal overlay xattrs added by the writer
    if full_name == b"trusted.overlay.metacopy" || full_name == b"trusted.overlay.redirect" {
        return None;
    }

    // Unescape: trusted.overlay.overlay.X -> trusted.overlay.X
    let final_name = if let Some(rest) = full_name.strip_prefix(b"trusted.overlay.overlay.") {
        let mut unescaped = b"trusted.overlay.".to_vec();
        unescaped.extend_from_slice(rest);
        unescaped
    } else {
        full_name
    };

    let name = Box::from(OsStr::from_bytes(&final_name));
    let value = Box::from(xattr.value());
    Some((name, value))
}

/// Extract file data from an inode (inline and block data combined).
fn extract_all_file_data(img: &Image, inode: &InodeType) -> anyhow::Result<Vec<u8>> {
    let file_size = (inode.size() as usize).min(img.image.len());
    if file_size == 0 {
        return Ok(Vec::new());
    }

    let mut data = Vec::with_capacity(file_size);

    // Read block data first
    for blkid in inode.blocks(img.blkszbits)? {
        let block = img.block(blkid)?;
        data.extend_from_slice(block);
    }

    // Read inline data
    if let Some(inline) = inode.inline() {
        data.extend_from_slice(inline);
    }

    data.truncate(file_size);
    Ok(data)
}

/// Try to extract a metacopy digest from an inode's xattrs.
fn extract_metacopy_digest<ObjectID: FsVerityHashValue>(
    img: &Image,
    inode: &InodeType,
) -> anyhow::Result<Option<ObjectID>> {
    let Some(xattrs_section) = inode.xattrs() else {
        return Ok(None);
    };

    for id in xattrs_section.shared() {
        let xattr = img.shared_xattr(id.get())?;
        if let Some(digest) = check_metacopy_xattr(xattr) {
            return Ok(Some(digest));
        }
    }
    for xattr in xattrs_section.local() {
        if let Some(digest) = check_metacopy_xattr(xattr) {
            return Ok(Some(digest));
        }
    }
    Ok(None)
}

/// Check if a single xattr is a valid overlay.metacopy and return the digest.
fn check_metacopy_xattr<ObjectID: FsVerityHashValue>(xattr: &XAttr) -> Option<ObjectID> {
    // name_index 4 = "trusted.", suffix = "overlay.metacopy"
    if xattr.header.name_index != 4 {
        return None;
    }
    if xattr.suffix() != b"overlay.metacopy" {
        return None;
    }
    if let Ok(value) = OverlayMetacopy::<ObjectID>::read_from_bytes(xattr.value()) {
        if value.valid() {
            return Some(value.digest.clone());
        }
    }
    None
}

/// Collect directory entries from an inode, yielding (name_bytes, nid) pairs.
/// Skips "." and "..".
fn dir_entries<'a>(
    img: &'a Image<'a>,
    dir_inode: &'a InodeType<'a>,
) -> anyhow::Result<Vec<(&'a [u8], u64)>> {
    let mut entries = Vec::new();

    // Block-based entries
    for blkid in dir_inode.blocks(img.blkszbits)? {
        let block = img.directory_block(blkid)?;
        for entry in block.entries() {
            if entry.name != b"." && entry.name != b".." {
                entries.push((entry.name, entry.nid()));
            }
        }
    }

    // Inline entries
    if let Some(data) = dir_inode.inline() {
        if let Ok(block) = DirectoryBlock::ref_from_bytes(data) {
            for entry in block.entries() {
                if entry.name != b"." && entry.name != b".." {
                    entries.push((entry.name, entry.nid()));
                }
            }
        }
    }

    Ok(entries)
}

/// Recursively populate a `tree::Directory` from an erofs directory inode.
fn populate_directory<ObjectID: FsVerityHashValue>(
    img: &Image,
    dir_inode: &InodeType,
    dir: &mut tree::Directory<ObjectID>,
    hardlinks: &mut HashMap<u64, Rc<tree::Leaf<ObjectID>>>,
) -> anyhow::Result<()> {
    for (name_bytes, nid) in dir_entries(img, dir_inode)? {
        let name = OsStr::from_bytes(name_bytes);
        let child_inode = img.inode(nid)?;

        if child_inode.mode().is_dir() {
            let child_stat = stat_from_inode_for_tree(img, &child_inode)?;
            let mut child_dir = tree::Directory::new(child_stat);
            populate_directory(img, &child_inode, &mut child_dir, hardlinks)
                .with_context(|| format!("reading directory {:?}", name))?;
            dir.insert(name, tree::Inode::Directory(Box::new(child_dir)));
        } else {
            // Check if this is a hardlink (same nid seen before)
            if let Some(existing_leaf) = hardlinks.get(&nid) {
                dir.insert(name, tree::Inode::Leaf(Rc::clone(existing_leaf)));
                continue;
            }

            let stat = stat_from_inode_for_tree(img, &child_inode)?;
            let mode = child_inode.mode().0.get();
            let file_type = mode & S_IFMT;

            let content = match file_type {
                S_IFREG => {
                    if let Some(digest) = extract_metacopy_digest::<ObjectID>(img, &child_inode)? {
                        tree::LeafContent::Regular(tree::RegularFile::External(
                            digest,
                            child_inode.size(),
                        ))
                    } else {
                        let data = extract_all_file_data(img, &child_inode)?;
                        tree::LeafContent::Regular(tree::RegularFile::Inline(data.into()))
                    }
                }
                S_IFLNK => {
                    let target_data = child_inode.inline().unwrap_or(&[]);
                    let target = OsStr::from_bytes(target_data);
                    tree::LeafContent::Symlink(Box::from(target))
                }
                S_IFBLK => tree::LeafContent::BlockDevice(child_inode.u() as u64),
                S_IFCHR => tree::LeafContent::CharacterDevice(child_inode.u() as u64),
                S_IFIFO => tree::LeafContent::Fifo,
                S_IFSOCK => tree::LeafContent::Socket,
                _ => anyhow::bail!("unknown file type {:#o} for {:?}", file_type, name),
            };

            let leaf = Rc::new(tree::Leaf { stat, content });

            // Track for hardlink detection if nlink > 1
            if child_inode.nlink() > 1 {
                hardlinks.insert(nid, Rc::clone(&leaf));
            }

            dir.insert(name, tree::Inode::Leaf(leaf));
        }
    }

    Ok(())
}

/// Converts an EROFS image into a `tree::FileSystem`.
///
/// This is the inverse of `mkfs_erofs`: it reads an EROFS image and
/// reconstructs the tree structure, including proper handling of hardlinks
/// (via `Rc` sharing), xattr namespace transformations, and metacopy-based
/// external file references.
pub fn erofs_to_filesystem<ObjectID: FsVerityHashValue>(
    image_data: &[u8],
) -> anyhow::Result<tree::FileSystem<ObjectID>> {
    let img = Image::open(image_data)?;
    let root_inode = img.root()?;

    let root_stat = stat_from_inode_for_tree(&img, &root_inode)?;
    let mut fs = tree::FileSystem::new(root_stat);

    let mut hardlinks: HashMap<u64, Rc<tree::Leaf<ObjectID>>> = HashMap::new();

    populate_directory(&img, &root_inode, &mut fs.root, &mut hardlinks)
        .context("reading root directory")?;

    Ok(fs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dumpfile::{dumpfile_to_filesystem, write_dumpfile},
        erofs::writer::mkfs_erofs,
        fsverity::Sha256HashValue,
    };
    use std::collections::HashMap;

    /// Helper to validate that directory entries can be read correctly
    fn validate_directory_entries(img: &Image, nid: u64, expected_names: &[&str]) {
        let inode = img.inode(nid).unwrap();
        assert!(inode.mode().is_dir(), "Expected directory inode");

        let mut found_names = Vec::new();

        // Read inline entries if present
        if let Some(inline) = inode.inline() {
            let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
            for entry in inline_block.entries() {
                let name = std::str::from_utf8(entry.name).unwrap();
                found_names.push(name.to_string());
            }
        }

        // Read block entries
        for blkid in inode.blocks(img.blkszbits).unwrap() {
            let block = img.directory_block(blkid).unwrap();
            for entry in block.entries() {
                let name = std::str::from_utf8(entry.name).unwrap();
                found_names.push(name.to_string());
            }
        }

        // Sort for comparison (entries should include . and ..)
        found_names.sort();
        let mut expected_sorted: Vec<_> = expected_names.iter().map(|s| s.to_string()).collect();
        expected_sorted.sort();

        assert_eq!(
            found_names, expected_sorted,
            "Directory entries mismatch for nid {nid}"
        );
    }

    #[test]
    fn test_empty_directory() {
        // Create filesystem with empty directory
        let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/empty_dir 4096 40755 2 0 0 0 1000.0 - - -
"#;

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let image = mkfs_erofs(&fs);
        let img = Image::open(&image).unwrap();

        // Root should have . and .. and empty_dir
        let root_nid = img.sb.root_nid.get() as u64;
        validate_directory_entries(&img, root_nid, &[".", "..", "empty_dir"]);

        // Find empty_dir entry
        let root_inode = img.root().unwrap();
        let mut empty_dir_nid = None;
        if let Some(inline) = root_inode.inline() {
            let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
            for entry in inline_block.entries() {
                if entry.name == b"empty_dir" {
                    empty_dir_nid = Some(entry.nid());
                    break;
                }
            }
        }
        for blkid in root_inode.blocks(img.blkszbits).unwrap() {
            let block = img.directory_block(blkid).unwrap();
            for entry in block.entries() {
                if entry.name == b"empty_dir" {
                    empty_dir_nid = Some(entry.nid());
                    break;
                }
            }
        }

        let empty_dir_nid = empty_dir_nid.expect("empty_dir not found");
        validate_directory_entries(&img, empty_dir_nid, &[".", ".."]);
    }

    #[test]
    fn test_directory_with_inline_entries() {
        // Create filesystem with directory that has a few entries (should be inline)
        let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/dir1 4096 40755 2 0 0 0 1000.0 - - -
/dir1/file1 5 100644 1 0 0 0 1000.0 - hello -
/dir1/file2 5 100644 1 0 0 0 1000.0 - world -
"#;

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let image = mkfs_erofs(&fs);
        let img = Image::open(&image).unwrap();

        // Find dir1
        let root_inode = img.root().unwrap();
        let mut dir1_nid = None;
        if let Some(inline) = root_inode.inline() {
            let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
            for entry in inline_block.entries() {
                if entry.name == b"dir1" {
                    dir1_nid = Some(entry.nid());
                    break;
                }
            }
        }
        for blkid in root_inode.blocks(img.blkszbits).unwrap() {
            let block = img.directory_block(blkid).unwrap();
            for entry in block.entries() {
                if entry.name == b"dir1" {
                    dir1_nid = Some(entry.nid());
                    break;
                }
            }
        }

        let dir1_nid = dir1_nid.expect("dir1 not found");
        validate_directory_entries(&img, dir1_nid, &[".", "..", "file1", "file2"]);
    }

    #[test]
    fn test_directory_with_many_entries() {
        // Create a directory with many entries to force block storage
        let mut dumpfile = String::from("/ 4096 40755 2 0 0 0 1000.0 - - -\n");
        dumpfile.push_str("/bigdir 4096 40755 2 0 0 0 1000.0 - - -\n");

        // Add many files to force directory blocks
        for i in 0..100 {
            dumpfile.push_str(&format!(
                "/bigdir/file{i:03} 5 100644 1 0 0 0 1000.0 - hello -\n"
            ));
        }

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(&dumpfile).unwrap();
        let image = mkfs_erofs(&fs);
        let img = Image::open(&image).unwrap();

        // Find bigdir
        let root_inode = img.root().unwrap();
        let mut bigdir_nid = None;
        if let Some(inline) = root_inode.inline() {
            let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
            for entry in inline_block.entries() {
                if entry.name == b"bigdir" {
                    bigdir_nid = Some(entry.nid());
                    break;
                }
            }
        }
        for blkid in root_inode.blocks(img.blkszbits).unwrap() {
            let block = img.directory_block(blkid).unwrap();
            for entry in block.entries() {
                if entry.name == b"bigdir" {
                    bigdir_nid = Some(entry.nid());
                    break;
                }
            }
        }

        let bigdir_nid = bigdir_nid.expect("bigdir not found");

        // Build expected names
        let mut expected: Vec<String> = vec![".".to_string(), "..".to_string()];
        for i in 0..100 {
            expected.push(format!("file{i:03}"));
        }
        let expected_refs: Vec<&str> = expected.iter().map(|s| s.as_str()).collect();

        validate_directory_entries(&img, bigdir_nid, &expected_refs);
    }

    #[test]
    fn test_nested_directories() {
        // Test deeply nested directory structure
        let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/a 4096 40755 2 0 0 0 1000.0 - - -
/a/b 4096 40755 2 0 0 0 1000.0 - - -
/a/b/c 4096 40755 2 0 0 0 1000.0 - - -
/a/b/c/file.txt 5 100644 1 0 0 0 1000.0 - hello -
"#;

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let image = mkfs_erofs(&fs);
        let img = Image::open(&image).unwrap();

        // Navigate through the structure
        let root_nid = img.sb.root_nid.get() as u64;
        validate_directory_entries(&img, root_nid, &[".", "..", "a"]);

        // Helper to find a directory entry by name
        let find_entry = |parent_nid: u64, name: &[u8]| -> u64 {
            let inode = img.inode(parent_nid).unwrap();

            if let Some(inline) = inode.inline() {
                let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
                for entry in inline_block.entries() {
                    if entry.name == name {
                        return entry.nid();
                    }
                }
            }

            for blkid in inode.blocks(img.blkszbits).unwrap() {
                let block = img.directory_block(blkid).unwrap();
                for entry in block.entries() {
                    if entry.name == name {
                        return entry.nid();
                    }
                }
            }
            panic!("Entry not found: {:?}", std::str::from_utf8(name));
        };

        let a_nid = find_entry(root_nid, b"a");
        validate_directory_entries(&img, a_nid, &[".", "..", "b"]);

        let b_nid = find_entry(a_nid, b"b");
        validate_directory_entries(&img, b_nid, &[".", "..", "c"]);

        let c_nid = find_entry(b_nid, b"c");
        validate_directory_entries(&img, c_nid, &[".", "..", "file.txt"]);
    }

    #[test]
    fn test_mixed_entry_types() {
        // Test directory with various file types
        let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/mixed 4096 40755 2 0 0 0 1000.0 - - -
/mixed/regular 10 100644 1 0 0 0 1000.0 - content123 -
/mixed/symlink 7 120777 1 0 0 0 1000.0 /target - -
/mixed/fifo 0 10644 1 0 0 0 1000.0 - - -
/mixed/subdir 4096 40755 2 0 0 0 1000.0 - - -
"#;

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let image = mkfs_erofs(&fs);
        let img = Image::open(&image).unwrap();

        let root_inode = img.root().unwrap();
        let mut mixed_nid = None;
        if let Some(inline) = root_inode.inline() {
            let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
            for entry in inline_block.entries() {
                if entry.name == b"mixed" {
                    mixed_nid = Some(entry.nid());
                    break;
                }
            }
        }
        for blkid in root_inode.blocks(img.blkszbits).unwrap() {
            let block = img.directory_block(blkid).unwrap();
            for entry in block.entries() {
                if entry.name == b"mixed" {
                    mixed_nid = Some(entry.nid());
                    break;
                }
            }
        }

        let mixed_nid = mixed_nid.expect("mixed not found");
        validate_directory_entries(
            &img,
            mixed_nid,
            &[".", "..", "regular", "symlink", "fifo", "subdir"],
        );
    }

    #[test]
    fn test_collect_objects_traversal() {
        // Test that object collection properly traverses all directories
        let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/dir1 4096 40755 2 0 0 0 1000.0 - - -
/dir1/file1 5 100644 1 0 0 0 1000.0 - hello -
/dir2 4096 40755 2 0 0 0 1000.0 - - -
/dir2/subdir 4096 40755 2 0 0 0 1000.0 - - -
/dir2/subdir/file2 5 100644 1 0 0 0 1000.0 - world -
"#;

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let image = mkfs_erofs(&fs);

        // This should traverse all directories without error
        let result = collect_objects::<Sha256HashValue>(&image);
        assert!(
            result.is_ok(),
            "Failed to collect objects: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_pr188_empty_inline_directory() -> anyhow::Result<()> {
        // Regression test for https://github.com/containers/composefs-rs/pull/188
        //
        // The bug: ObjectCollector::visit_inode at lines 553-554 unconditionally does:
        //   let tail = DirectoryBlock::ref_from_bytes(inode.inline()).unwrap();
        //   self.visit_directory_block(tail);
        //
        // When inode.inline() is empty, DirectoryBlock::ref_from_bytes succeeds but then
        // visit_directory_block calls n_entries() which panics trying to read 12 bytes
        // from an empty slice.
        //
        // This test generates an erofs image using C mkcomposefs, which creates directories
        // with empty inline sections (unlike the Rust implementation which always includes
        // . and .. entries).

        // Generate a C-generated erofs image using mkcomposefs
        let dumpfile_content = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/empty_dir 4096 40755 2 0 0 0 1000.0 - - -
"#;

        // Create temporary files for dumpfile and erofs output
        let temp_dir = tempfile::TempDir::new()?;
        let temp_dir = temp_dir.path();
        let dumpfile_path = temp_dir.join("pr188_test.dump");
        let erofs_path = temp_dir.join("pr188_test.erofs");

        // Write dumpfile
        std::fs::write(&dumpfile_path, dumpfile_content).expect("Failed to write test dumpfile");

        // Run mkcomposefs to generate erofs image
        let output = std::process::Command::new("mkcomposefs")
            .arg("--from-file")
            .arg(&dumpfile_path)
            .arg(&erofs_path)
            .output()
            .expect("Failed to run mkcomposefs - is it installed?");

        assert!(
            output.status.success(),
            "mkcomposefs failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        // Read the generated erofs image
        let image = std::fs::read(&erofs_path).expect("Failed to read generated erofs");

        // The C mkcomposefs creates directories with empty inline sections.
        let r = collect_objects::<Sha256HashValue>(&image).unwrap();
        assert_eq!(r.len(), 0);

        Ok(())
    }

    #[test]
    fn test_round_trip_basic() {
        // Full round-trip: dumpfile -> tree -> erofs -> read back -> validate
        let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/file1 5 100644 1 0 0 0 1000.0 - hello -
/file2 6 100644 1 0 0 0 1000.0 - world! -
/dir1 4096 40755 2 0 0 0 1000.0 - - -
/dir1/nested 8 100644 1 0 0 0 1000.0 - content1 -
"#;

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let image = mkfs_erofs(&fs);
        let img = Image::open(&image).unwrap();

        // Verify root entries
        let root_nid = img.sb.root_nid.get() as u64;
        validate_directory_entries(&img, root_nid, &[".", "..", "file1", "file2", "dir1"]);

        // Collect all entries and verify structure
        let mut entries_map: HashMap<Vec<u8>, u64> = HashMap::new();
        let root_inode = img.root().unwrap();

        if let Some(inline) = root_inode.inline() {
            let inline_block = DirectoryBlock::ref_from_bytes(inline).unwrap();
            for entry in inline_block.entries() {
                entries_map.insert(entry.name.to_vec(), entry.nid());
            }
        }

        for blkid in root_inode.blocks(img.blkszbits).unwrap() {
            let block = img.directory_block(blkid).unwrap();
            for entry in block.entries() {
                entries_map.insert(entry.name.to_vec(), entry.nid());
            }
        }

        // Verify we can read file contents
        let file1_nid = entries_map
            .get(b"file1".as_slice())
            .expect("file1 not found");
        let file1_inode = img.inode(*file1_nid).unwrap();
        assert!(!file1_inode.mode().is_dir());
        assert_eq!(file1_inode.size(), 5);

        let inline_data = file1_inode.inline();
        assert_eq!(inline_data, Some(b"hello".as_slice()));
    }

    /// Helper: round-trip a dumpfile through erofs and compare the result.
    fn round_trip_dumpfile(input: &str) -> (String, String) {
        let fs_orig = dumpfile_to_filesystem::<Sha256HashValue>(input).unwrap();

        let mut orig_output = Vec::new();
        write_dumpfile(&mut orig_output, &fs_orig).unwrap();
        let orig_str = String::from_utf8(orig_output).unwrap();

        let image = mkfs_erofs(&fs_orig);
        let fs_rt = erofs_to_filesystem::<Sha256HashValue>(&image).unwrap();

        let mut rt_output = Vec::new();
        write_dumpfile(&mut rt_output, &fs_rt).unwrap();
        let rt_str = String::from_utf8(rt_output).unwrap();

        (orig_str, rt_str)
    }

    #[test]
    fn test_erofs_to_filesystem_empty_root() {
        let dumpfile = "/ 4096 40755 2 0 0 0 1000.0 - - -\n";
        let (orig, rt) = round_trip_dumpfile(dumpfile);
        assert_eq!(orig, rt);
    }

    #[test]
    fn test_erofs_to_filesystem_inline_files() {
        let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/empty 0 100644 1 0 0 0 1000.0 - - -
/hello 5 100644 1 0 0 0 1000.0 - hello -
/world 6 100644 1 0 0 0 1000.0 - world! -
"#;
        let (orig, rt) = round_trip_dumpfile(dumpfile);
        assert_eq!(orig, rt);
    }

    #[test]
    fn test_erofs_to_filesystem_symlinks() {
        let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/link1 7 120777 1 0 0 0 1000.0 /target - -
/link2 11 120777 1 0 0 0 1000.0 /other/path - -
"#;
        let (orig, rt) = round_trip_dumpfile(dumpfile);
        assert_eq!(orig, rt);
    }

    #[test]
    fn test_erofs_to_filesystem_nested_dirs() {
        let dumpfile = r#"/ 4096 40755 3 0 0 0 1000.0 - - -
/a 4096 40755 3 0 0 0 1000.0 - - -
/a/b 4096 40755 3 0 0 0 1000.0 - - -
/a/b/c 4096 40755 2 0 0 0 1000.0 - - -
/a/b/c/file.txt 5 100644 1 0 0 0 1000.0 - hello -
/a/b/other 3 100644 1 0 0 0 1000.0 - abc -
"#;
        let (orig, rt) = round_trip_dumpfile(dumpfile);
        assert_eq!(orig, rt);
    }

    #[test]
    fn test_erofs_to_filesystem_devices_and_fifos() {
        let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/blk 0 60660 1 0 0 2049 1000.0 - - -
/chr 0 20666 1 0 0 1025 1000.0 - - -
/fifo 0 10644 1 0 0 0 1000.0 - - -
"#;
        let (orig, rt) = round_trip_dumpfile(dumpfile);
        assert_eq!(orig, rt);
    }

    #[test]
    fn test_erofs_to_filesystem_xattrs() {
        let dumpfile =
            "/ 4096 40755 2 0 0 0 1000.0 - - - security.selinux=system_u:object_r:root_t:s0\n\
             /file 5 100644 1 0 0 0 1000.0 - hello - user.myattr=myvalue\n";
        let (orig, rt) = round_trip_dumpfile(dumpfile);
        assert_eq!(orig, rt);
    }

    #[test]
    fn test_erofs_to_filesystem_escaped_overlay_xattrs() {
        // The writer escapes trusted.overlay.X to trusted.overlay.overlay.X.
        // Round-tripping must preserve the original xattr name.
        let dumpfile = "/ 4096 40755 2 0 0 0 1000.0 - - -\n\
             /file 5 100644 1 0 0 0 1000.0 - hello - trusted.overlay.custom=val\n";
        let (orig, rt) = round_trip_dumpfile(dumpfile);
        assert_eq!(orig, rt);
    }

    #[test]
    fn test_erofs_to_filesystem_external_file() {
        // External file with a known fsverity digest
        let digest = "a".repeat(64);
        let pathname = format!("{}/{}", &digest[..2], &digest[2..]);
        let dumpfile = format!(
            "/ 4096 40755 2 0 0 0 1000.0 - - -\n\
             /ext 1024 100644 1 0 0 0 1000.0 {pathname} - {digest}\n"
        );
        let (orig, rt) = round_trip_dumpfile(&dumpfile);
        assert_eq!(orig, rt);
    }

    #[test]
    fn test_erofs_to_filesystem_hardlinks() {
        let dumpfile = r#"/ 4096 40755 2 0 0 0 1000.0 - - -
/original 11 100644 2 0 0 0 1000.0 - hello_world -
/hardlink 0 @120000 2 0 0 0 0.0 /original - -
"#;

        let fs_orig = dumpfile_to_filesystem::<Sha256HashValue>(dumpfile).unwrap();
        let image = mkfs_erofs(&fs_orig);
        let fs_rt = erofs_to_filesystem::<Sha256HashValue>(&image).unwrap();

        // Verify hardlink Rc sharing (scope the extra refs so strong_count
        // is correct when write_dumpfile checks nlink)
        {
            let orig_leaf = fs_rt.root.ref_leaf(OsStr::new("original")).unwrap();
            let hardlink_leaf = fs_rt.root.ref_leaf(OsStr::new("hardlink")).unwrap();
            assert!(
                Rc::ptr_eq(&orig_leaf, &hardlink_leaf),
                "hardlink entries should share the same Rc"
            );
        }

        // Verify dumpfile round-trips correctly
        let mut orig_output = Vec::new();
        write_dumpfile(&mut orig_output, &fs_orig).unwrap();
        let orig_str = String::from_utf8(orig_output).unwrap();

        let mut rt_output = Vec::new();
        write_dumpfile(&mut rt_output, &fs_rt).unwrap();
        let rt_str = String::from_utf8(rt_output).unwrap();
        assert_eq!(orig_str, rt_str);
    }

    #[test]
    fn test_erofs_to_filesystem_mixed_types() {
        let dumpfile = r#"/ 4096 40755 3 0 0 0 1000.0 - - -
/blk 0 60660 1 0 6 259 1000.0 - - -
/chr 0 20666 1 0 6 1025 1000.0 - - -
/dir 4096 40755 2 42 42 0 2000.0 - - -
/dir/nested 3 100644 1 42 42 0 2000.0 - abc -
/fifo 0 10644 1 0 0 0 1000.0 - - -
/hello 5 100644 1 1000 1000 0 1500.0 - hello -
/link 7 120777 1 0 0 0 1000.0 /target - -
"#;
        let (orig, rt) = round_trip_dumpfile(dumpfile);
        assert_eq!(orig, rt);
    }

    mod proptest_tests {
        use super::*;
        use crate::fsverity::Sha512HashValue;
        use crate::test::proptest_strategies::{build_filesystem, filesystem_spec};
        use proptest::prelude::*;

        /// Round-trip a FileSystem through erofs with a given ObjectID type
        /// and compare dumpfile output before and after.
        fn round_trip_filesystem<ObjectID: FsVerityHashValue>(
            fs_orig: &tree::FileSystem<ObjectID>,
        ) {
            let mut orig_output = Vec::new();
            write_dumpfile(&mut orig_output, fs_orig).unwrap();

            let image = mkfs_erofs(fs_orig);
            let fs_rt = erofs_to_filesystem::<ObjectID>(&image).unwrap();

            let mut rt_output = Vec::new();
            write_dumpfile(&mut rt_output, &fs_rt).unwrap();

            assert_eq!(orig_output, rt_output);
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn test_erofs_round_trip_sha256(spec in filesystem_spec()) {
                let fs = build_filesystem::<Sha256HashValue>(spec);
                round_trip_filesystem(&fs);
            }

            #[test]
            fn test_erofs_round_trip_sha512(spec in filesystem_spec()) {
                let fs = build_filesystem::<Sha512HashValue>(spec);
                round_trip_filesystem(&fs);
            }
        }
    }
}
