use core::mem::offset_of;
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    mem::discriminant,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use zerocopy::{Immutable, KnownLayout, TryFromBytes};

use super::{
    format::{self, CompactInodeHeader, ComposefsHeader, ExtendedInodeHeader, Superblock},
    reader::{DirectoryBlock, Image, Inode, InodeHeader, InodeOps, InodeType, InodeXAttrs, XAttr},
};

macro_rules! print_fields {
    ($ty: ty, $s: expr, $f: ident) => {{
        let value = &$s.$f;
        let default = if false { value } else { &Default::default() };
        if value != default {
            println!("     +{:02x}    {}: {:?}", offset_of!($ty, $f), stringify!($f), value);
        }
    }};
    ($ty: ty, $s:expr, $head: ident; $($tail: ident);+) => {{
        print_fields!($ty, $s, $head);
        print_fields!($ty, $s, $($tail);+);
    }};
}

fn utf8_or_hex(data: &[u8]) -> String {
    if let Ok(str) = std::str::from_utf8(data) {
        format!("\"{str}\"")
    } else {
        hex::encode(data)
    }
}

// This is basically just a fancy fat pointer type
enum SegmentType<'img> {
    Header(&'img ComposefsHeader),
    Superblock(&'img Superblock),
    CompactInode(&'img Inode<CompactInodeHeader>),
    ExtendedInode(&'img Inode<ExtendedInodeHeader>),
    XAttr(&'img XAttr),
    DataBlock(&'img [u8]),
    DirectoryBlock(&'img DirectoryBlock),
}

// TODO: Something for `enum_dispatch` would be good here, but I couldn't get it working...
impl SegmentType<'_> {
    fn addr(&self) -> usize {
        match self {
            SegmentType::Header(h) => &raw const **h as usize,
            SegmentType::Superblock(sb) => &raw const **sb as usize,
            SegmentType::CompactInode(i) => &raw const **i as *const u8 as usize,
            SegmentType::ExtendedInode(i) => &raw const **i as *const u8 as usize,
            SegmentType::XAttr(x) => &raw const **x as *const u8 as usize,
            SegmentType::DataBlock(b) => &raw const **b as *const u8 as usize,
            SegmentType::DirectoryBlock(b) => &raw const **b as *const u8 as usize,
        }
    }

    fn size(&self) -> usize {
        match self {
            SegmentType::Header(h) => size_of_val(*h),
            SegmentType::Superblock(sb) => size_of_val(*sb),
            SegmentType::CompactInode(i) => size_of_val(*i),
            SegmentType::ExtendedInode(i) => size_of_val(*i),
            SegmentType::XAttr(x) => size_of_val(*x),
            SegmentType::DataBlock(b) => size_of_val(*b),
            SegmentType::DirectoryBlock(b) => size_of_val(*b),
        }
    }
}

#[repr(C)]
#[derive(TryFromBytes, KnownLayout, Immutable)]
struct DataBlock([u8]);

struct ImageVisitor<'img> {
    image: &'img Image<'img>,
    visited: BTreeMap<usize, (SegmentType<'img>, Vec<Box<Path>>)>,
}

impl<'img> ImageVisitor<'img> {
    fn note(&mut self, segment: SegmentType<'img>, path: Option<&Path>) -> bool {
        let offset = segment.addr() - self.image.image.as_ptr() as usize;
        match self.visited.entry(offset) {
            std::collections::btree_map::Entry::Occupied(mut e) => {
                let (existing, paths) = e.get_mut();
                // TODO: figure out pointer value equality...
                assert_eq!(discriminant(existing), discriminant(&segment));
                assert_eq!(existing.addr(), segment.addr());
                assert_eq!(existing.size(), segment.size());
                if let Some(path) = path {
                    paths.push(Box::from(path));
                }
                true
            }
            std::collections::btree_map::Entry::Vacant(e) => {
                let mut paths = vec![];
                if let Some(path) = path {
                    paths.push(Box::from(path));
                }
                e.insert((segment, paths));
                false
            }
        }
    }

    fn visit_directory_block(&mut self, block: &DirectoryBlock, path: &Path) {
        for entry in block.entries() {
            if entry.name == b"." || entry.name == b".." {
                // TODO: maybe we want to follow those and let deduplication happen
                continue;
            }
            self.visit_inode(entry.inode, &path.join(OsStr::from_bytes(entry.name)));
        }
    }

    fn visit_inode(&mut self, id: u64, path: &Path) {
        let inode = self.image.inode(id);
        let segment = match inode {
            InodeType::Compact(inode) => SegmentType::CompactInode(inode),
            InodeType::Extended(inode) => SegmentType::ExtendedInode(inode),
        };
        if self.note(segment, Some(path)) {
            // TODO: maybe we want to throw an error if we detect loops
            /* already processed */
            return;
        }

        if let Some(xattrs) = inode.xattrs() {
            for id in xattrs.shared() {
                self.note(
                    SegmentType::XAttr(self.image.shared_xattr(id.get())),
                    Some(path),
                );
            }
        }

        if inode.mode() & format::S_IFMT == format::S_IFDIR {
            let inline = inode.inline();
            if !inline.is_empty() {
                let inline_block = DirectoryBlock::try_ref_from_bytes(inode.inline()).unwrap();
                self.visit_directory_block(inline_block, path);
            }

            for id in inode.blocks(self.image.blkszbits) {
                let block = self.image.directory_block(id);
                self.visit_directory_block(block, path);
                self.note(SegmentType::DirectoryBlock(block), Some(path));
            }
        } else {
            for id in inode.blocks(self.image.blkszbits) {
                let block = self.image.data_block(id);
                self.note(SegmentType::DataBlock(block), Some(path));
            }
        }
    }

    fn visit_image(
        image: &'img Image<'img>,
    ) -> BTreeMap<usize, (SegmentType<'img>, Vec<Box<Path>>)> {
        let mut this = Self {
            image,
            visited: BTreeMap::new(),
        };
        this.note(SegmentType::Header(image.header), None);
        this.note(SegmentType::Superblock(image.sb), None);
        this.visit_inode(image.sb.root_nid.get() as u64, &PathBuf::from("/"));
        this.visited
    }
}

pub fn print_paths(paths: &[Box<Path>]) {
    match paths {
        [] => {}
        [one] => {
            println!("            filename: {one:?}");
        }
        many => {
            println!("            links:");
            many.iter()
                .for_each(|one| println!("               - {one:?}"));
        }
    }
}

impl std::fmt::Debug for XAttr {
    // Injective (ie: accounts for every byte in the input)
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "({} {} {}) {}{} = {}",
            self.header.name_index,
            self.header.name_len,
            self.header.value_size,
            std::str::from_utf8(format::XATTR_PREFIXES[self.header.name_index as usize]).unwrap(),
            utf8_or_hex(self.suffix()),
            utf8_or_hex(self.value()),
        )?;
        if self.padding().iter().any(|c| *c != 0) {
            write!(f, " {:?}", self.padding())?;
        }
        Ok(())
    }
}

// This accounts for every bytes of InodeXAttrs
fn print_xattrs(xattrs: Option<&InodeXAttrs>) {
    let Some(xattrs) = xattrs else {
        return;
    };

    if !xattrs.shared().is_empty() {
        print!("         Shared xattrs:");
        for id in xattrs.shared() {
            print!(" {id}");
        }
        println!();
    }
    println!("         Local xattrs:");
    for xattr in xattrs.local() {
        println!("          - {:?}", xattr);
    }
}

fn hexdump(block: &[u8]) {
    for row in 0..((block.len() + 15) / 16) {
        let offset = row * 16;
        print!("   +{offset:04x}  ");
        for idx in offset..(offset + 16) {
            if idx < block.len() {
                print!("{:02x} ", block[idx]);
            } else {
                print!("   ");
            }
            if idx % 8 == 7 {
                print!(" ");
            }
        }
        print!("|");
        for idx in offset..(offset + 16) {
            if idx < block.len() {
                let c = block[idx];
                if c.is_ascii() && !c.is_ascii_control() {
                    print!("{}", c as char);
                } else {
                    print!(".");
                }
            } else {
                print!(" ");
            }
        }
        println!("|");
    }
}

pub fn print_directory_block(block: &DirectoryBlock) {
    for entry in block.entries() {
        println!(
            "             {} {:?} -> {}",
            utf8_or_hex(entry.name),
            entry.file_type,
            entry.inode
        );
    }
}

fn print_inode_extra(inode: impl InodeOps + InodeHeader) {
    print_xattrs(inode.xattrs());
    let inline = inode.inline();
    if !inline.is_empty() {
        if inode.mode() & format::S_IFMT == format::S_IFDIR {
            let block = DirectoryBlock::try_ref_from_bytes(inline).unwrap();
            print_directory_block(block);
        } else {
            hexdump(inode.inline());
        }
    }
}

pub fn debug_img(data: &[u8]) {
    let image = Image::open(data);
    let visited = ImageVisitor::visit_image(&image);

    let mut offset = 0;
    for (start, (segment, paths)) in visited {
        if offset > start {
            println!("*** Overlapping segments!");
            offset = start;
        }
        if offset < start {
            println!("{offset:08x} Padding");
            let padding = &data[offset..start];
            if padding.iter().all(|c| *c == 0) {
                println!("         {} * nul", padding.len());
            } else {
                println!("         {:?}", padding);
            }
            println!();
            offset = start;
        }

        match segment {
            SegmentType::Header(header) => {
                println!("{offset:08x} ComposefsHeader");
                print_fields!(
                    ComposefsHeader, header,
                    magic; flags; version; composefs_version; unused
                );
            }
            SegmentType::Superblock(sb) => {
                println!("{offset:08x} Superblock");
                print_fields!(
                    Superblock, sb,
                    magic; checksum; feature_compat; blkszbits; extslots; root_nid; inos; build_time;
                    build_time_nsec; blocks; meta_blkaddr; xattr_blkaddr; uuid; volume_name;
                    feature_incompat; available_compr_algs; extra_devices; devt_slotoff; dirblkbits;
                    xattr_prefix_count; xattr_prefix_start; packed_nid; xattr_filter_reserved; reserved2
                );
            }
            SegmentType::CompactInode(inode) => {
                println!("{offset:08x} Inode (compact) #{}", offset / 32); // TODO: doesn't take metablk into account
                print_paths(&paths);
                print_fields!(
                    CompactInodeHeader, inode.header,
                    format; xattr_icount; mode; reserved; size; u; ino; uid; gid; nlink; reserved2;
                    reserved2
                );
                print_inode_extra(inode);
            }
            SegmentType::ExtendedInode(inode) => {
                println!("{offset:08x} Inode (extended) #{}", offset / 32); // TODO: doesn't take metablk into account
                print_paths(&paths);
                print_fields!(
                    ExtendedInodeHeader, inode.header,
                    format; xattr_icount; mode; reserved; size; u; ino; uid; gid; mtime; mtime_nsec; nlink;
                    reserved2
                );
                print_inode_extra(inode);
            }
            SegmentType::XAttr(xattr) => {
                println!("{offset:08x} XAttr #{}", offset / 4); // TODO: doesn't take xattrblk into account
                print_paths(&paths);
                println!("            {:?}", xattr);
            }
            SegmentType::DirectoryBlock(block) => {
                println!("{offset:08x} Directory block");
                print_paths(&paths);
                print_directory_block(block);
            }
            SegmentType::DataBlock(block) => {
                println!("{offset:08x} Data block");
                print_paths(&paths);
                hexdump(block);
            }
        }
        println!();

        offset = start + segment.size();
    }
    if offset < data.len() {
        println!("{offset:08x} Padding");
        let padding = &data[offset..data.len()];
        if padding.iter().any(|c| *c != 0) {
            println!("         {:?}", padding);
        }
        println!();
    }

    if offset > data.len() {
        println!("*** Segments past EOF!");
    }
}
