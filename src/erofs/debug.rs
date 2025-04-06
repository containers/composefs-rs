use std::{
    cmp::Ordering,
    collections::BTreeMap,
    ffi::OsStr,
    fmt,
    mem::discriminant,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use anyhow::Result;
use zerocopy::FromBytes;

use super::{
    format::{self, CompactInodeHeader, ComposefsHeader, ExtendedInodeHeader, Superblock},
    reader::{DataBlock, DirectoryBlock, Image, Inode, InodeHeader, InodeOps, InodeType, XAttr},
};

/// Converts any reference to a thin pointer (as usize)
/// Used for address calculations in various outputs
macro_rules! addr {
    ($ref: expr) => {
        &raw const (*$ref) as *const u8 as usize
    };
}

macro_rules! write_with_offset {
    ($fmt: expr, $base: expr, $label: expr, $ref: expr) => {{
        let offset = addr!($ref) - addr!($base);
        writeln!($fmt, "{offset:+8x}     {}: {:?}", $label, $ref)
    }};
}

macro_rules! write_fields {
    ($fmt: expr, $base: expr, $struct: expr, $field: ident) => {{
        let value = &$struct.$field;
        let default = if false { value } else { &Default::default() };
        if value != default {
            write_with_offset!($fmt, $base, stringify!($field), value)?;
        }
    }};
    ($fmt: expr, $base: expr, $struct: expr, $head: ident; $($tail: ident);+) => {{
        write_fields!($fmt, $base, $struct, $head);
        write_fields!($fmt, $base, $struct, $($tail);+);
    }};
}

fn utf8_or_hex(data: &[u8]) -> String {
    if let Ok(string) = std::str::from_utf8(data) {
        format!("{:?}", string)
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
    DataBlock(&'img DataBlock),
    DirectoryBlock(&'img DirectoryBlock),
}

// TODO: Something for `enum_dispatch` would be good here, but I couldn't get it working...
impl SegmentType<'_> {
    fn addr(&self) -> usize {
        match self {
            SegmentType::Header(h) => addr!(*h),
            SegmentType::Superblock(sb) => addr!(*sb),
            SegmentType::CompactInode(i) => addr!(*i),
            SegmentType::ExtendedInode(i) => addr!(*i),
            SegmentType::XAttr(x) => addr!(*x),
            SegmentType::DataBlock(b) => addr!(*b),
            SegmentType::DirectoryBlock(b) => addr!(*b),
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

    fn typename(&self) -> &'static str {
        match self {
            SegmentType::Header(..) => "header",
            SegmentType::Superblock(..) => "superblock",
            SegmentType::CompactInode(..) => "compact inode",
            SegmentType::ExtendedInode(..) => "extended inode",
            SegmentType::XAttr(..) => "shared xattr",
            SegmentType::DataBlock(..) => "data block",
            SegmentType::DirectoryBlock(..) => "directory block",
        }
    }
}

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
            self.visit_inode(
                entry.header.inode_offset.get(),
                &path.join(OsStr::from_bytes(entry.name)),
            );
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

        if inode.mode().is_dir() {
            let inline = inode.inline();
            if !inline.is_empty() {
                let inline_block = DirectoryBlock::ref_from_bytes(inode.inline()).unwrap();
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

impl fmt::Debug for XAttr {
    // Injective (ie: accounts for every byte in the input)
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

impl fmt::Debug for CompactInodeHeader {
    // Injective (ie: accounts for every byte in the input)
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "CompactInodeHeader")?;
        write_fields!(f, self, self,
            format; xattr_icount; mode; reserved; size; u; ino; uid; gid; nlink; reserved2);
        Ok(())
    }
}

impl fmt::Debug for ExtendedInodeHeader {
    // Injective (ie: accounts for every byte in the input)
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "ExtendedInodeHeader")?;
        write_fields!(f, self, self,
            format; xattr_icount; mode; reserved; size; u; ino; uid;
            gid; mtime; mtime_nsec; nlink; reserved2);
        Ok(())
    }
}

fn hexdump(f: &mut impl fmt::Write, data: &[u8], rel: usize) -> fmt::Result {
    let start = match rel {
        0 => 0,
        ptr => data.as_ptr() as usize - ptr,
    };
    let end = start + data.len();
    let start_row = start / 16;
    let end_row = end.div_ceil(16);

    for row in start_row..end_row {
        let row_start = row * 16;
        let row_end = row * 16 + 16;
        write!(f, "{row_start:+8x}  ")?;

        for idx in row_start..row_end {
            if start <= idx && idx < end {
                write!(f, "{:02x} ", data[idx - start])?;
            } else {
                write!(f, "   ")?;
            }
            if idx % 8 == 7 {
                write!(f, " ")?;
            }
        }
        write!(f, "|")?;

        for idx in row_start..row_end {
            if start <= idx && idx < end {
                let c = data[idx - start];
                if c.is_ascii() && !c.is_ascii_control() {
                    write!(f, "{}", c as char)?;
                } else {
                    write!(f, ".")?;
                }
            } else {
                write!(f, " ")?;
            }
        }
        writeln!(f, "|")?;
    }

    Ok(())
}

impl<T: fmt::Debug + InodeHeader> fmt::Debug for Inode<T> {
    // Injective (ie: accounts for every byte in the input)
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.header, f)?;

        if let Some(xattrs) = self.xattrs() {
            write_fields!(f, self, xattrs.header, name_filter; shared_count; reserved);

            if !xattrs.shared().is_empty() {
                write_with_offset!(f, self, "shared xattrs", xattrs.shared())?;
            }

            for xattr in xattrs.local() {
                write_with_offset!(f, self, "xattr", xattr)?;
            }
        }

        // We want to print one of four things for inline data:
        //   - no data: print nothing
        //   - directory data: dump the entries
        //   - small inline text string: print it
        //   - otherwise, hexdump
        let inline = self.inline();

        // No inline data
        if inline.is_empty() {
            return Ok(());
        }

        // Directory dump
        if self.header.mode().is_dir() {
            let dir = DirectoryBlock::ref_from_bytes(inline).unwrap();
            let offset = addr!(dir) - addr!(self);
            return write!(
                f,
                "     +{offset:02x} --- inline directory entries ---{:#?}",
                dir
            );
        }

        // Small string (<= 128 bytes, utf8, no control characters).
        if inline.len() <= 128 && !inline.iter().any(|c| c.is_ascii_control()) {
            if let Ok(string) = std::str::from_utf8(inline) {
                return write_with_offset!(f, self, "inline", string);
            }
        }

        // Else, hexdump data block
        hexdump(f, inline, &raw const self.header as usize)
    }
}

impl fmt::Debug for DirectoryBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for entry in self.entries() {
            writeln!(f)?;
            write_fields!(f, self, entry.header, inode_offset; name_offset; file_type; reserved);
            writeln!(
                f,
                "{:+8x}     # name: {}",
                entry.header.name_offset.get(),
                utf8_or_hex(entry.name)
            )?;
        }
        // TODO: trailing junk inside of st_size
        // TODO: padding up to block or inode boundary
        Ok(())
    }
}

impl fmt::Debug for DataBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hexdump(f, &self.0, 0)
    }
}

impl fmt::Debug for ComposefsHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "ComposefsHeader")?;
        write_fields!(f, self, self,
            magic; flags; version; composefs_version; unused
        );
        Ok(())
    }
}

impl fmt::Debug for Superblock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Superblock")?;
        write_fields!(f, self, self,
            magic; checksum; feature_compat; blkszbits; extslots; root_nid; inos; build_time;
            build_time_nsec; blocks; meta_blkaddr; xattr_blkaddr; uuid; volume_name;
            feature_incompat; available_compr_algs; extra_devices; devt_slotoff; dirblkbits;
            xattr_prefix_count; xattr_prefix_start; packed_nid; xattr_filter_reserved; reserved2
        );
        Ok(())
    }
}

fn addto<T: Clone + Eq + Ord>(map: &mut BTreeMap<T, usize>, key: &T, count: usize) {
    if let Some(value) = map.get_mut(key) {
        *value += count;
    } else {
        map.insert(key.clone(), count);
    }
}

pub fn dump_unassigned(
    output: &mut impl std::io::Write,
    offset: usize,
    unassigned: &[u8],
) -> Result<()> {
    if unassigned.iter().all(|c| *c == 0) {
        writeln!(output, "{offset:08x} Padding")?;
        writeln!(
            output,
            "{:+8x}     # {} nul bytes",
            unassigned.len(),
            unassigned.len()
        )?;
        writeln!(output)?;
    } else {
        writeln!(output, "{offset:08x} Unknown content")?;
        let mut dump = String::new();
        hexdump(&mut dump, unassigned, 0)?;
        writeln!(output, "{dump}")?;
    }
    Ok(())
}

pub fn debug_img(output: &mut impl std::io::Write, data: &[u8]) -> Result<()> {
    let image = Image::open(data);
    let visited = ImageVisitor::visit_image(&image);

    let inode_start = (image.sb.meta_blkaddr.get() as usize) << image.sb.blkszbits;
    let xattr_start = (image.sb.xattr_blkaddr.get() as usize) << image.sb.blkszbits;

    let mut space_stats = BTreeMap::new();
    let mut padding_stats = BTreeMap::new();

    let mut last_segment_type = "";
    let mut offset = 0;
    for (start, (segment, paths)) in visited {
        let segment_type = segment.typename();
        addto(&mut space_stats, &segment_type, segment.size());

        match offset.cmp(&start) {
            Ordering::Less => {
                dump_unassigned(output, offset, &data[offset..start])?;
                addto(
                    &mut padding_stats,
                    &(last_segment_type, segment_type),
                    start - offset,
                );
                offset = start;
            }
            Ordering::Greater => {
                writeln!(output, "*** Overlapping segments!")?;
                writeln!(output)?;
                offset = start;
            }
            _ => {}
        }

        last_segment_type = segment_type;

        for path in paths {
            writeln!(
                output,
                "# Filename {}",
                utf8_or_hex(path.as_os_str().as_bytes())
            )?;
        }

        match segment {
            SegmentType::Header(header) => {
                writeln!(output, "{offset:08x} {header:?}")?;
            }
            SegmentType::Superblock(sb) => {
                writeln!(output, "{offset:08x} {sb:?}")?;
            }
            SegmentType::CompactInode(inode) => {
                writeln!(output, "# nid #{}", (offset - inode_start) / 32)?;
                writeln!(output, "{offset:08x} {inode:#?}")?;
            }
            SegmentType::ExtendedInode(inode) => {
                writeln!(output, "# nid #{}", (offset - inode_start) / 32)?;
                writeln!(output, "{offset:08x} {inode:#?}")?;
            }
            SegmentType::XAttr(xattr) => {
                writeln!(output, "# xattr #{}", (offset - xattr_start) / 4)?;
                writeln!(output, "{offset:08x} {xattr:?}")?;
            }
            SegmentType::DirectoryBlock(block) => {
                writeln!(output, "# block #{}", offset / image.block_size)?;
                writeln!(output, "{offset:08x} Directory block{block:?}")?;
            }
            SegmentType::DataBlock(block) => {
                writeln!(output, "# block #{}", offset / image.block_size)?;
                writeln!(output, "{offset:08x} Data block\n{block:?}")?;
            }
        }

        offset += segment.size();
    }

    if offset < data.len() {
        let unassigned = &data[offset..];
        dump_unassigned(output, offset, unassigned)?;
        addto(
            &mut padding_stats,
            &(last_segment_type, "eof"),
            unassigned.len(),
        );
        offset = data.len();
        writeln!(output)?;
    }

    if offset > data.len() {
        writeln!(output, "*** Segments past EOF!")?;
        offset = data.len();
    }

    writeln!(output, "Space statistics (total size {offset}B):")?;
    for (key, value) in space_stats {
        writeln!(
            output,
            "  {key} = {value}B, {:.2}%",
            (100. * value as f64) / (offset as f64)
        )?;
    }
    for ((from, to), value) in padding_stats {
        writeln!(
            output,
            "  padding {from} -> {to} = {value}B, {:.2}%",
            (100. * value as f64) / (offset as f64)
        )?;
    }

    Ok(())
}
