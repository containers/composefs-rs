//! EROFS image reading and parsing functionality.
//!
//! This module provides safe parsing and navigation of EROFS filesystem
//! images, including inode traversal, directory reading, and object
//! reference collection for garbage collection.

use core::mem::size_of;
use std::collections::{BTreeSet, HashSet};
use std::ops::Range;

use thiserror::Error;
use zerocopy::{little_endian::U32, FromBytes, Immutable, KnownLayout};

use crate::{
    composefs::OverlayMetacopy,
    format::{
        CompactInodeHeader, ComposefsHeader, DataLayout, DirectoryEntryHeader, ExtendedInodeHeader,
        InodeXAttrHeader, ModeField, Superblock, XAttrHeader,
    },
};
use composefs_types::fsverity::FsVerityHashValue;

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
    /// Returns the user ID
    fn uid(&self) -> u32;
    /// Returns the group ID
    fn gid(&self) -> u32;
    /// Returns the number of hard links
    fn nlink(&self) -> u32;
    /// Returns the modification time in seconds since epoch
    fn mtime(&self) -> i64;
    /// Returns the modification time nanoseconds component
    fn mtime_nsec(&self) -> u32;
    /// Returns the device number (for block/character devices, from the `u` field)
    fn rdev(&self) -> u32 {
        self.u()
    }

    /// Calculates the number of additional bytes after the header
    fn additional_bytes(&self, blkszbits: u8) -> usize {
        let block_size = 1 << blkszbits;
        self.xattr_size()
            + match self.data_layout() {
                DataLayout::FlatPlain => 0,
                DataLayout::FlatInline => self.size() as usize % block_size,
                DataLayout::ChunkBased => 4,
            }
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

    fn uid(&self) -> u32 {
        self.uid.get()
    }

    fn gid(&self) -> u32 {
        self.gid.get()
    }

    fn nlink(&self) -> u32 {
        self.nlink.get()
    }

    fn mtime(&self) -> i64 {
        self.mtime.get() as i64
    }

    fn mtime_nsec(&self) -> u32 {
        self.mtime_nsec.get()
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

    fn uid(&self) -> u32 {
        self.uid.get() as u32
    }

    fn gid(&self) -> u32 {
        self.gid.get() as u32
    }

    fn nlink(&self) -> u32 {
        self.nlink.get() as u32
    }

    fn mtime(&self) -> i64 {
        // Compact inodes don't have mtime; return 0
        0
    }

    fn mtime_nsec(&self) -> u32 {
        // Compact inodes don't have mtime_nsec; return 0
        0
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
    /// Calculates the total number of elements for an xattr entry including padding
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
    fn blocks(&self, blkszbits: u8) -> Range<u64>;
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

    fn uid(&self) -> u32 {
        self.header.uid()
    }

    fn gid(&self) -> u32 {
        self.header.gid()
    }

    fn nlink(&self) -> u32 {
        self.header.nlink()
    }

    fn mtime(&self) -> i64 {
        self.header.mtime()
    }

    fn mtime_nsec(&self) -> u32 {
        self.header.mtime_nsec()
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

    fn blocks(&self, blkszbits: u8) -> Range<u64> {
        let size = self.header.size();
        let block_size = 1 << blkszbits;
        let start = self.header.u() as u64;

        match self.header.data_layout() {
            DataLayout::FlatPlain => Range {
                start,
                end: start + size.div_ceil(block_size),
            },
            DataLayout::FlatInline => Range {
                start,
                end: start + size / block_size,
            },
            DataLayout::ChunkBased => Range { start, end: start },
        }
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

    fn uid(&self) -> u32 {
        match self {
            Self::Compact(inode) => inode.uid(),
            Self::Extended(inode) => inode.uid(),
        }
    }

    fn gid(&self) -> u32 {
        match self {
            Self::Compact(inode) => inode.gid(),
            Self::Extended(inode) => inode.gid(),
        }
    }

    fn nlink(&self) -> u32 {
        match self {
            Self::Compact(inode) => inode.nlink(),
            Self::Extended(inode) => inode.nlink(),
        }
    }

    fn mtime(&self) -> i64 {
        match self {
            Self::Compact(inode) => inode.mtime(),
            Self::Extended(inode) => inode.mtime(),
        }
    }

    fn mtime_nsec(&self) -> u32 {
        match self {
            Self::Compact(inode) => inode.mtime_nsec(),
            Self::Extended(inode) => inode.mtime_nsec(),
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

    fn blocks(&self, blkszbits: u8) -> Range<u64> {
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
    pub fn open(image: &'img [u8]) -> Self {
        let header = ComposefsHeader::ref_from_prefix(image)
            .expect("header err")
            .0;
        let sb = Superblock::ref_from_prefix(&image[1024..])
            .expect("superblock err")
            .0;
        let blkszbits = sb.blkszbits;
        let block_size = 1usize << blkszbits;
        assert!(block_size != 0);
        let inodes = &image[sb.meta_blkaddr.get() as usize * block_size..];
        let xattrs = &image[sb.xattr_blkaddr.get() as usize * block_size..];
        Image {
            image,
            header,
            blkszbits,
            block_size,
            sb,
            inodes,
            xattrs,
        }
    }

    /// Returns an inode by its ID
    pub fn inode(&self, id: u64) -> InodeType<'_> {
        let inode_data = &self.inodes[id as usize * 32..];
        if inode_data[0] & 1 != 0 {
            let header = ExtendedInodeHeader::ref_from_bytes(&inode_data[..64]).unwrap();
            InodeType::Extended(
                Inode::<ExtendedInodeHeader>::ref_from_prefix_with_elems(
                    inode_data,
                    header.additional_bytes(self.blkszbits),
                )
                .unwrap()
                .0,
            )
        } else {
            let header = CompactInodeHeader::ref_from_bytes(&inode_data[..32]).unwrap();
            InodeType::Compact(
                Inode::<CompactInodeHeader>::ref_from_prefix_with_elems(
                    inode_data,
                    header.additional_bytes(self.blkszbits),
                )
                .unwrap()
                .0,
            )
        }
    }

    /// Returns a shared extended attribute by its ID
    pub fn shared_xattr(&self, id: u32) -> &XAttr {
        let xattr_data = &self.xattrs[id as usize * 4..];
        let header = XAttrHeader::ref_from_bytes(&xattr_data[..4]).unwrap();
        XAttr::ref_from_prefix_with_elems(xattr_data, header.calculate_n_elems())
            .unwrap()
            .0
    }

    /// Returns a data block by its ID
    pub fn block(&self, id: u64) -> &[u8] {
        &self.image[id as usize * self.block_size..][..self.block_size]
    }

    /// Returns a data block by its ID as a DataBlock reference
    pub fn data_block(&self, id: u64) -> &DataBlock {
        DataBlock::ref_from_bytes(self.block(id)).unwrap()
    }

    /// Returns a directory block by its ID
    pub fn directory_block(&self, id: u64) -> &DirectoryBlock {
        DirectoryBlock::ref_from_bytes(self.block(id)).unwrap()
    }

    /// Returns the root directory inode
    pub fn root(&self) -> InodeType<'_> {
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
    /// Returns the inode number (nid) for this directory entry.
    pub fn nid(&self) -> u64 {
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
pub struct ObjectCollector<'f, ObjectID: FsVerityHashValue> {
    visited_nids: HashSet<u64>,
    nids_to_visit: BTreeSet<u64>,
    objects: HashSet<ObjectID>,
    /// Optional filters for top-level entries
    filters: &'f [String],
    /// Whether we're currently at the root directory
    at_root: bool,
}

impl<ObjectID: FsVerityHashValue> std::fmt::Debug for ObjectCollector<'_, ObjectID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectCollector")
            .field("visited_nids", &self.visited_nids)
            .field("nids_to_visit", &self.nids_to_visit)
            .field("objects_count", &self.objects.len())
            .field("filters", &self.filters)
            .field("at_root", &self.at_root)
            .finish()
    }
}

impl<ObjectID: FsVerityHashValue> ObjectCollector<'_, ObjectID> {
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
            self.visit_xattr(img.shared_xattr(id.get()));
        }
        for attr in xattrs.local() {
            self.visit_xattr(attr);
        }
        Ok(())
    }

    fn visit_directory_block(&mut self, block: &DirectoryBlock, apply_filter: bool) {
        for entry in block.entries() {
            if entry.name != b"." && entry.name != b".." {
                // Apply filter at root level if filters are specified
                if apply_filter && !self.filters.is_empty() {
                    let name_str = String::from_utf8_lossy(entry.name);
                    if !self.filters.iter().any(|f| f == name_str.as_ref()) {
                        continue;
                    }
                }

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

        let inode = img.inode(nid);

        if let Some(xattrs) = inode.xattrs() {
            self.visit_xattrs(img, xattrs)?;
        }

        if inode.mode().is_dir() {
            // Apply filters only when visiting the root directory
            let apply_filter = self.at_root;
            self.at_root = false;

            for blkid in inode.blocks(img.sb.blkszbits) {
                self.visit_directory_block(img.directory_block(blkid), apply_filter);
            }

            if let Some(inline) = inode.inline() {
                if let Ok(inline_block) = DirectoryBlock::ref_from_bytes(inline) {
                    self.visit_directory_block(inline_block, apply_filter);
                }
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
/// If `filters` is provided and non-empty, only top-level entries whose names
/// match one of the filter strings will be traversed.
///
/// Returns a set of all referenced object IDs.
pub fn collect_objects<ObjectID: FsVerityHashValue>(
    image: &[u8],
    filters: &[String],
) -> ReadResult<HashSet<ObjectID>> {
    let img = Image::open(image);
    let mut this = ObjectCollector {
        visited_nids: HashSet::new(),
        nids_to_visit: BTreeSet::new(),
        objects: HashSet::new(),
        filters,
        at_root: true,
    };

    // nids_to_visit is initialized with the root directory.  Visiting directory nids will add
    // more nids to the "to visit" list.  Keep iterating until it's empty.
    this.nids_to_visit.insert(img.sb.root_nid.get() as u64);
    while let Some(nid) = this.nids_to_visit.pop_first() {
        this.visit_nid(&img, nid)?;
    }
    Ok(this.objects)
}
