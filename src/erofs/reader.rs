use core::mem::size_of;
use std::ops::Range;

use zerocopy::{little_endian::U32, Immutable, KnownLayout, TryFromBytes};

use super::format::{
    CompactInodeHeader, ComposefsHeader, DataLayout, DirectoryEntryHeader, ExtendedInodeHeader,
    FileType, InodeXAttrHeader, Superblock, XAttrHeader,
};

fn round_up(n: usize, to: usize) -> usize {
    (n + to - 1) & !(to - 1)
}

pub trait InodeHeader {
    fn data_layout(&self) -> DataLayout;
    fn xattr_icount(&self) -> u16;
    fn mode(&self) -> u16;
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

    fn mode(&self) -> u16 {
        self.mode.get()
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

    fn mode(&self) -> u16 {
        self.mode.get()
    }

    fn size(&self) -> u64 {
        self.size.get() as u64
    }

    fn u(&self) -> u32 {
        self.u.get()
    }
}

#[repr(C)]
#[derive(TryFromBytes, KnownLayout, Immutable)]
pub struct XAttr {
    pub header: XAttrHeader,
    pub data: [u8],
}

#[repr(C)]
#[derive(Debug, TryFromBytes, KnownLayout, Immutable)]
pub struct Inode<Header: InodeHeader> {
    pub header: Header,
    pub data: [u8],
}

#[repr(C)]
#[derive(Debug, TryFromBytes, KnownLayout, Immutable)]
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
        let header = XAttrHeader::try_ref_from_bytes(&data[..4]).unwrap();
        Self::try_ref_from_prefix_with_elems(data, header.calculate_n_elems()).unwrap()
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

    fn mode(&self) -> u16 {
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
            n => Some(InodeXAttrs::try_ref_from_bytes(&self.data[..n]).unwrap()),
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

    fn mode(&self) -> u16 {
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
        let header = ComposefsHeader::try_ref_from_prefix(image)
            .expect("header err")
            .0;
        let sb = Superblock::try_ref_from_prefix(&image[1024..])
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

    pub fn inode(&self, id: u64) -> InodeType {
        let inode_data = &self.inodes[id as usize * 32..];
        if inode_data[0] & 1 != 0 {
            let header = ExtendedInodeHeader::try_ref_from_bytes(&inode_data[..64]).unwrap();
            InodeType::Extended(
                Inode::<ExtendedInodeHeader>::try_ref_from_prefix_with_elems(
                    inode_data,
                    header.additional_bytes(self.blkszbits),
                )
                .unwrap()
                .0,
            )
        } else {
            let header = CompactInodeHeader::try_ref_from_bytes(&inode_data[..32]).unwrap();
            InodeType::Compact(
                Inode::<CompactInodeHeader>::try_ref_from_prefix_with_elems(
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
        let header = XAttrHeader::try_ref_from_bytes(&xattr_data[..4]).unwrap();
        XAttr::try_ref_from_prefix_with_elems(xattr_data, header.calculate_n_elems())
            .unwrap()
            .0
    }

    pub fn data_block(&self, id: u64) -> &[u8] {
        &self.image[id as usize * self.block_size..][..self.block_size]
    }

    pub fn directory_block(&self, id: u64) -> &DirectoryBlock {
        DirectoryBlock::try_ref_from_bytes(self.data_block(id)).unwrap()
    }

    pub fn root(&self) -> InodeType {
        self.inode(self.sb.root_nid.get() as u64)
    }
}

impl InodeXAttrs {
    pub fn shared(&self) -> &[U32] {
        // TODO: there must be an easier way...
        #[derive(TryFromBytes, KnownLayout, Immutable)]
        #[repr(C)]
        struct U32Array([U32]);
        &U32Array::try_ref_from_prefix_with_elems(&self.data, self.header.shared_count as usize)
            .unwrap()
            .0
             .0
    }

    pub fn local(&self) -> XAttrIter {
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
#[derive(Debug, Immutable, KnownLayout, TryFromBytes)]
pub struct DirectoryBlock {
    pub data: [u8],
}

impl DirectoryBlock {
    pub fn get_entry_header(&self, n: usize) -> &DirectoryEntryHeader {
        let entry_data = &self.data
            [n * size_of::<DirectoryEntryHeader>()..(n + 1) * size_of::<DirectoryEntryHeader>()];
        DirectoryEntryHeader::try_ref_from_bytes(entry_data).unwrap()
    }

    pub fn get_entry_headers(&self) -> &[DirectoryEntryHeader] {
        // TODO: there must be an easier way...
        #[derive(TryFromBytes, KnownLayout, Immutable)]
        #[repr(C)]
        struct EntryArray([DirectoryEntryHeader]);
        &EntryArray::try_ref_from_prefix_with_elems(&self.data, self.n_entries())
            .unwrap()
            .0
             .0
    }

    pub fn n_entries(&self) -> usize {
        let first = self.get_entry_header(0);
        let offset = first.name_offset.get();
        assert!(offset != 0);
        assert!(offset % 12 == 0);
        offset as usize / 12
    }

    pub fn entries(&self) -> DirectoryEntries {
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
    pub file_type: FileType,
    pub name: &'a [u8],
    pub inode: u64,
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
            let item = self.block.get_entry_header(self.position);
            let name_start = item.name_offset.get() as usize;
            self.position += 1;

            let name = if self.position == self.length {
                let with_padding = &self.block.data[name_start..];
                let end = with_padding.partition_point(|c| *c != 0);
                &with_padding[..end]
            } else {
                let next = self.block.get_entry_header(self.position);
                let name_end = next.name_offset.get() as usize;
                &self.block.data[name_start..name_end]
            };

            Some(DirectoryEntry {
                name,
                file_type: item.file_type,
                inode: item.inode_offset.get(),
            })
        } else {
            None
        }
    }
}
