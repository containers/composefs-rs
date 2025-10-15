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

use super::{
    composefs::OverlayMetacopy,
    format::{
        CompactInodeHeader, ComposefsHeader, DataLayout, DirectoryEntryHeader, ExtendedInodeHeader,
        InodeXAttrHeader, ModeField, Superblock, XAttrHeader,
    },
};
use crate::fsverity::FsVerityHashValue;

pub fn round_up(n: usize, to: usize) -> usize {
    (n + to - 1) & !(to - 1)
}

pub trait InodeHeader {
    fn data_layout(&self) -> DataLayout;
    fn xattr_icount(&self) -> u16;
    fn mode(&self) -> ModeField;
    fn size(&self) -> u64;
    fn u(&self) -> u32;

    fn additional_bytes(&self, blkszbits: u8) -> usize {
        let block_size = 1 << blkszbits;
        self.xattr_size()
            + match self.data_layout() {
                DataLayout::FlatPlain => 0,
                DataLayout::FlatInline => self.size() as usize % block_size,
                DataLayout::ChunkBased => 4,
            }
    }

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
}

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
pub struct XAttr {
    pub header: XAttrHeader,
    pub data: [u8],
}

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
pub struct Inode<Header: InodeHeader> {
    pub header: Header,
    pub data: [u8],
}

#[repr(C)]
#[derive(Debug, FromBytes, Immutable, KnownLayout)]
pub struct InodeXAttrs {
    pub header: InodeXAttrHeader,
    pub data: [u8],
}

impl XAttrHeader {
    pub fn calculate_n_elems(&self) -> usize {
        round_up(self.name_len as usize + self.value_size.get() as usize, 4)
    }
}

impl XAttr {
    pub fn from_prefix(data: &[u8]) -> (&XAttr, &[u8]) {
        let header = XAttrHeader::ref_from_bytes(&data[..4]).unwrap();
        Self::ref_from_prefix_with_elems(data, header.calculate_n_elems()).unwrap()
    }

    pub fn suffix(&self) -> &[u8] {
        &self.data[..self.header.name_len as usize]
    }

    pub fn value(&self) -> &[u8] {
        &self.data[self.header.name_len as usize..][..self.header.value_size.get() as usize]
    }

    pub fn padding(&self) -> &[u8] {
        &self.data[self.header.name_len as usize + self.header.value_size.get() as usize..]
    }
}

pub trait InodeOps {
    fn xattrs(&self) -> Option<&InodeXAttrs>;
    fn inline(&self) -> &[u8];
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
}

impl<Header: InodeHeader> InodeOps for &Inode<Header> {
    fn xattrs(&self) -> Option<&InodeXAttrs> {
        match self.header.xattr_size() {
            0 => None,
            n => Some(InodeXAttrs::ref_from_bytes(&self.data[..n]).unwrap()),
        }
    }

    fn inline(&self) -> &[u8] {
        &self.data[self.header.xattr_size()..]
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
#[derive(Debug)]
pub enum InodeType<'img> {
    Compact(&'img Inode<CompactInodeHeader>),
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
}

impl InodeOps for InodeType<'_> {
    fn xattrs(&self) -> Option<&InodeXAttrs> {
        match self {
            Self::Compact(inode) => inode.xattrs(),
            Self::Extended(inode) => inode.xattrs(),
        }
    }

    fn inline(&self) -> &[u8] {
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

#[derive(Debug)]
pub struct Image<'i> {
    pub image: &'i [u8],
    pub header: &'i ComposefsHeader,
    pub blkszbits: u8,
    pub block_size: usize,
    pub sb: &'i Superblock,
    pub inodes: &'i [u8],
    pub xattrs: &'i [u8],
}

impl<'img> Image<'img> {
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

    pub fn shared_xattr(&self, id: u32) -> &XAttr {
        let xattr_data = &self.xattrs[id as usize * 4..];
        let header = XAttrHeader::ref_from_bytes(&xattr_data[..4]).unwrap();
        XAttr::ref_from_prefix_with_elems(xattr_data, header.calculate_n_elems())
            .unwrap()
            .0
    }

    pub fn block(&self, id: u64) -> &[u8] {
        &self.image[id as usize * self.block_size..][..self.block_size]
    }

    pub fn data_block(&self, id: u64) -> &DataBlock {
        DataBlock::ref_from_bytes(self.block(id)).unwrap()
    }

    pub fn directory_block(&self, id: u64) -> &DirectoryBlock {
        DirectoryBlock::ref_from_bytes(self.block(id)).unwrap()
    }

    pub fn root(&self) -> InodeType<'_> {
        self.inode(self.sb.root_nid.get() as u64)
    }
}

// TODO: there must be an easier way...
#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C)]
struct Array<T>([T]);

impl InodeXAttrs {
    pub fn shared(&self) -> &[U32] {
        &Array::ref_from_prefix_with_elems(&self.data, self.header.shared_count as usize)
            .unwrap()
            .0
             .0
    }

    pub fn local(&self) -> XAttrIter<'_> {
        XAttrIter {
            data: &self.data[self.header.shared_count as usize * 4..],
        }
    }
}

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

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
pub struct DataBlock(pub [u8]);

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
pub struct DirectoryBlock(pub [u8]);

impl DirectoryBlock {
    pub fn get_entry_header(&self, n: usize) -> &DirectoryEntryHeader {
        let entry_data = &self.0
            [n * size_of::<DirectoryEntryHeader>()..(n + 1) * size_of::<DirectoryEntryHeader>()];
        DirectoryEntryHeader::ref_from_bytes(entry_data).unwrap()
    }

    pub fn get_entry_headers(&self) -> &[DirectoryEntryHeader] {
        &Array::ref_from_prefix_with_elems(&self.0, self.n_entries())
            .unwrap()
            .0
             .0
    }

    pub fn n_entries(&self) -> usize {
        let first = self.get_entry_header(0);
        let offset = first.name_offset.get();
        assert!(offset != 0);
        assert!(offset.is_multiple_of(12));
        offset as usize / 12
    }

    pub fn entries(&self) -> DirectoryEntries<'_> {
        DirectoryEntries {
            block: self,
            length: self.n_entries(),
            position: 0,
        }
    }
}

// High-level iterator interface
#[derive(Debug)]
pub struct DirectoryEntry<'a> {
    pub header: &'a DirectoryEntryHeader,
    pub name: &'a [u8],
}

impl DirectoryEntry<'_> {
    fn nid(&self) -> u64 {
        self.header.inode_offset.get()
    }
}

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

#[derive(Error, Debug)]
pub enum ErofsReaderError {
    #[error("Hardlinked directories detected")]
    DirectoryHardlinks,
    #[error("Maximum directory depth exceeded")]
    DepthExceeded,
    #[error("Invalid '.' entry in directory")]
    InvalidSelfReference,
    #[error("Invalid '..' entry in directory")]
    InvalidParentReference,
    #[error("File type in dirent doesn't match type in inode")]
    FileTypeMismatch,
}

type ReadResult<T> = Result<T, ErofsReaderError>;

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
            self.visit_xattr(img.shared_xattr(id.get()));
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

        let inode = img.inode(nid);

        if let Some(xattrs) = inode.xattrs() {
            self.visit_xattrs(img, xattrs)?;
        }

        if inode.mode().is_dir() {
            for blkid in inode.blocks(img.sb.blkszbits) {
                self.visit_directory_block(img.directory_block(blkid));
            }

            let tail = DirectoryBlock::ref_from_bytes(inode.inline()).unwrap();
            self.visit_directory_block(tail);
        }

        Ok(())
    }
}

pub fn collect_objects<ObjectID: FsVerityHashValue>(image: &[u8]) -> ReadResult<HashSet<ObjectID>> {
    let img = Image::open(image);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dumpfile::dumpfile_to_filesystem, erofs::writer::mkfs_erofs, fsverity::Sha256HashValue,
    };
    use std::collections::HashMap;

    /// Helper to validate that directory entries can be read correctly
    fn validate_directory_entries(img: &Image, nid: u64, expected_names: &[&str]) {
        let inode = img.inode(nid);
        assert!(inode.mode().is_dir(), "Expected directory inode");

        let mut found_names = Vec::new();

        // Read inline entries if present
        if !inode.inline().is_empty() {
            let inline_block = DirectoryBlock::ref_from_bytes(inode.inline()).unwrap();
            for entry in inline_block.entries() {
                let name = std::str::from_utf8(entry.name).unwrap();
                found_names.push(name.to_string());
            }
        }

        // Read block entries
        for blkid in inode.blocks(img.blkszbits) {
            let block = img.directory_block(blkid);
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
            "Directory entries mismatch for nid {}",
            nid
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
        let img = Image::open(&image);

        // Root should have . and .. and empty_dir
        let root_nid = img.sb.root_nid.get() as u64;
        validate_directory_entries(&img, root_nid, &[".", "..", "empty_dir"]);

        // Find empty_dir entry
        let root_inode = img.root();
        let mut empty_dir_nid = None;
        if !root_inode.inline().is_empty() {
            let inline_block = DirectoryBlock::ref_from_bytes(root_inode.inline()).unwrap();
            for entry in inline_block.entries() {
                if entry.name == b"empty_dir" {
                    empty_dir_nid = Some(entry.nid());
                    break;
                }
            }
        }
        for blkid in root_inode.blocks(img.blkszbits) {
            let block = img.directory_block(blkid);
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
        let img = Image::open(&image);

        // Find dir1
        let root_inode = img.root();
        let mut dir1_nid = None;
        if !root_inode.inline().is_empty() {
            let inline_block = DirectoryBlock::ref_from_bytes(root_inode.inline()).unwrap();
            for entry in inline_block.entries() {
                if entry.name == b"dir1" {
                    dir1_nid = Some(entry.nid());
                    break;
                }
            }
        }
        for blkid in root_inode.blocks(img.blkszbits) {
            let block = img.directory_block(blkid);
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
                "/bigdir/file{:03} 5 100644 1 0 0 0 1000.0 - hello -\n",
                i
            ));
        }

        let fs = dumpfile_to_filesystem::<Sha256HashValue>(&dumpfile).unwrap();
        let image = mkfs_erofs(&fs);
        let img = Image::open(&image);

        // Find bigdir
        let root_inode = img.root();
        let mut bigdir_nid = None;
        if !root_inode.inline().is_empty() {
            let inline_block = DirectoryBlock::ref_from_bytes(root_inode.inline()).unwrap();
            for entry in inline_block.entries() {
                if entry.name == b"bigdir" {
                    bigdir_nid = Some(entry.nid());
                    break;
                }
            }
        }
        for blkid in root_inode.blocks(img.blkszbits) {
            let block = img.directory_block(blkid);
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
            expected.push(format!("file{:03}", i));
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
        let img = Image::open(&image);

        // Navigate through the structure
        let root_nid = img.sb.root_nid.get() as u64;
        validate_directory_entries(&img, root_nid, &[".", "..", "a"]);

        // Helper to find a directory entry by name
        let find_entry = |parent_nid: u64, name: &[u8]| -> u64 {
            let inode = img.inode(parent_nid);

            if !inode.inline().is_empty() {
                let inline_block = DirectoryBlock::ref_from_bytes(inode.inline()).unwrap();
                for entry in inline_block.entries() {
                    if entry.name == name {
                        return entry.nid();
                    }
                }
            }

            for blkid in inode.blocks(img.blkszbits) {
                let block = img.directory_block(blkid);
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
        let img = Image::open(&image);

        let root_inode = img.root();
        let mut mixed_nid = None;
        if !root_inode.inline().is_empty() {
            let inline_block = DirectoryBlock::ref_from_bytes(root_inode.inline()).unwrap();
            for entry in inline_block.entries() {
                if entry.name == b"mixed" {
                    mixed_nid = Some(entry.nid());
                    break;
                }
            }
        }
        for blkid in root_inode.blocks(img.blkszbits) {
            let block = img.directory_block(blkid);
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
    #[ignore = "Needs https://github.com/containers/composefs-rs/pull/188"]
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
        let img = Image::open(&image);

        // Verify root entries
        let root_nid = img.sb.root_nid.get() as u64;
        validate_directory_entries(&img, root_nid, &[".", "..", "file1", "file2", "dir1"]);

        // Collect all entries and verify structure
        let mut entries_map: HashMap<Vec<u8>, u64> = HashMap::new();
        let root_inode = img.root();

        if !root_inode.inline().is_empty() {
            let inline_block = DirectoryBlock::ref_from_bytes(root_inode.inline()).unwrap();
            for entry in inline_block.entries() {
                entries_map.insert(entry.name.to_vec(), entry.nid());
            }
        }

        for blkid in root_inode.blocks(img.blkszbits) {
            let block = img.directory_block(blkid);
            for entry in block.entries() {
                entries_map.insert(entry.name.to_vec(), entry.nid());
            }
        }

        // Verify we can read file contents
        let file1_nid = entries_map
            .get(b"file1".as_slice())
            .expect("file1 not found");
        let file1_inode = img.inode(*file1_nid);
        assert!(!file1_inode.mode().is_dir());
        assert_eq!(file1_inode.size(), 5);

        let inline_data = file1_inode.inline();
        assert_eq!(inline_data, b"hello");
    }
}
