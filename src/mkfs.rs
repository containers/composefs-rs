use std::{
    env,
    io::Read,
    process::{Command, Stdio},
};

use anyhow::{bail, Result};

use crate::{dumpfile::write_dumpfile, image::FileSystem};

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    mem::{align_of_val, size_of},
    os::unix::ffi::OsStrExt,
    rc::Rc,
};

use log::debug;
use xxhash_rust::xxh32::xxh32;
use zerocopy::{Immutable, IntoBytes};

use crate::{
    erofs::{debug::debug_img, format},
    image,
};

fn round_up(n: usize, to: usize) -> usize {
    (n + to - 1) & !(to - 1)
}

#[derive(Clone, Copy, Debug)]
enum Offset {
    Header,
    Superblock,
    Inode,
    XAttr,
    Block,
    End,
}

trait Output {
    fn note_offset(&mut self, offset_type: Offset);
    fn get(&self, offset_type: Offset, idx: usize) -> usize;
    fn write(&mut self, data: &[u8]);
    fn pad(&mut self, alignment: usize);
    fn len(&self) -> usize;

    fn get_div(&self, offset_type: Offset, idx: usize, div: usize) -> usize {
        let offset = self.get(offset_type, idx);
        assert_eq!(offset % div, 0);
        offset / div
    }

    fn get_nid(&self, idx: usize) -> u64 {
        self.get_div(Offset::Inode, idx, 32) as u64
    }

    fn get_xattr(&self, idx: usize) -> u32 {
        self.get_div(Offset::XAttr, idx, 4).try_into().unwrap()
    }

    fn write_struct(&mut self, st: impl IntoBytes + Immutable) {
        assert_eq!(self.len() % align_of_val(&st), 0); // TODO: this is less than we want
        self.write(st.as_bytes());
    }
}

#[derive(PartialOrd, PartialEq, Eq, Ord, Clone)]
struct XAttr {
    prefix: u8,
    suffix: Box<[u8]>,
    value: Box<[u8]>,
}

#[derive(Clone, Default)]
struct InodeXAttrs {
    shared: Vec<usize>,
    local: Vec<XAttr>,
    filter: u32,
}

struct DirEnt<'a> {
    name: &'a [u8],
    inode: usize,
    file_type: format::FileType,
}

#[derive(Default)]
struct Directory<'a> {
    blocks: Box<[Box<[DirEnt<'a>]>]>,
    inline: Box<[DirEnt<'a>]>,
    size: usize,
    nlink: usize,
}

struct Leaf<'a> {
    content: &'a image::LeafContent,
    nlink: usize,
}

enum InodeContent<'a> {
    Directory(Directory<'a>),
    Leaf(Leaf<'a>),
}

struct Inode<'a> {
    stat: &'a image::Stat,
    xattrs: InodeXAttrs,
    content: InodeContent<'a>,
}

impl XAttr {
    pub fn write(&self, output: &mut impl Output) {
        output.write_struct(format::XAttrHeader {
            name_len: self.suffix.len() as u8,
            name_index: self.prefix,
            value_size: (self.value.len() as u16).into(),
        });
        output.write(&self.suffix);
        output.write(&self.value);
        output.pad(4);
    }
}

impl InodeXAttrs {
    fn add(&mut self, name: &[u8], value: &[u8]) {
        for (idx, prefix) in format::XATTR_PREFIXES.iter().enumerate().rev() {
            if let Some(suffix) = name.strip_prefix(*prefix) {
                self.filter |= 1 << (xxh32(suffix, format::XATTR_FILTER_SEED + idx as u32) % 32);
                self.local.push(XAttr {
                    prefix: idx as u8,
                    suffix: Box::from(suffix),
                    value: Box::from(value),
                });
                return;
            }
        }
        unreachable!("{:?}", std::str::from_utf8(name)); // worst case: we matched the empty prefix (0)
    }

    fn write(&self, output: &mut impl Output) {
        if self.filter != 0 {
            debug!("  write xattrs block");
            output.write_struct(format::InodeXAttrHeader {
                name_filter: (!self.filter).into(),
                shared_count: self.shared.len() as u8,
                ..Default::default()
            });
            for idx in &self.shared {
                debug!("    shared {} @{}", idx, output.len());
                output.write(&output.get_xattr(*idx).to_le_bytes());
            }
            for attr in &self.local {
                debug!("    local @{}", output.len());
                attr.write(output);
            }
        }
        // our alignment is equal to xattr alignment: no need to pad
    }
}

impl<'a> Directory<'a> {
    pub fn from_entries(entries: Vec<DirEnt<'a>>) -> Self {
        let mut blocks = vec![];
        let mut rest = vec![];

        let mut n_bytes = 0;
        let mut nlink = 0;

        debug!("Directory with {} items", entries.len());

        // The content of the directory is fixed at this point so we may as well split it into
        // blocks.  This lets us avoid measuring and re-measuring.
        for entry in entries.into_iter() {
            let entry_size = size_of::<format::DirectoryEntryHeader>() + entry.name.len();
            assert!(entry_size <= 4096);

            debug!("    {:?}", entry.file_type);

            if matches!(entry.file_type, format::FileType::Directory) {
                nlink += 1;
            }

            n_bytes += entry_size;
            if n_bytes <= 4096 {
                rest.push(entry);
            } else {
                // It won't fit, so we need to store the existing entries in a block.
                debug!("    block {}", rest.len());
                blocks.push(rest.into_boxed_slice());

                // Start over
                rest = vec![entry];
                n_bytes = entry_size;
            }
        }

        // Don't try to store more than 2048 bytes of tail data
        if n_bytes > 2048 {
            blocks.push(rest.into_boxed_slice());
            rest = vec![];
            n_bytes = 0;
        }

        debug!(
            "  blocks {} inline {} inline_size {n_bytes}",
            blocks.len(),
            rest.len()
        );

        let size = format::BLOCK_SIZE * blocks.len() + n_bytes;
        Self {
            blocks: blocks.into_boxed_slice(),
            inline: rest.into_boxed_slice(),
            size,
            nlink,
        }
    }

    fn write_block(&self, output: &mut impl Output, block: &[DirEnt]) {
        debug!("    write dir block {} @{}", block.len(), output.len());
        let mut nameofs = size_of::<format::DirectoryEntryHeader>() * block.len();

        for entry in block {
            debug!(
                "      entry {:?} name {} @{}",
                entry.file_type,
                nameofs,
                output.len()
            );
            output.write_struct(format::DirectoryEntryHeader {
                name_offset: (nameofs as u16).into(),
                inode_offset: output.get_nid(entry.inode).into(),
                file_type: entry.file_type,
                ..Default::default()
            });
            nameofs += entry.name.len();
        }

        for entry in block {
            debug!("      name @{}", output.len());
            output.write(entry.name.as_bytes());
        }
    }

    fn write_inline(&self, output: &mut impl Output) {
        debug!(
            "  write inline len {} expected size {} of {}",
            self.inline.len(),
            self.size % 4096,
            self.size
        );
        self.write_block(output, &self.inline);
    }

    fn write_blocks(&self, output: &mut impl Output) {
        for block in &self.blocks {
            assert_eq!(output.len() % format::BLOCK_SIZE, 0);
            self.write_block(output, block);
            output.pad(format::BLOCK_SIZE);
        }
    }

    fn inode_meta(&self, block_offset: usize) -> (format::DataLayout, u32, u64, usize) {
        let (layout, u) = if self.inline.len() == 0 {
            (format::DataLayout::FlatPlain, block_offset as u32 / 4096)
        } else if self.blocks.len() > 0 {
            (format::DataLayout::FlatInline, block_offset as u32 / 4096)
        } else {
            (format::DataLayout::FlatInline, 0)
        };
        (layout, u, self.size as u64, self.nlink)
    }
}

impl Leaf<'_> {
    fn inode_meta(&self) -> (format::DataLayout, u32, u64, usize) {
        let (layout, u, size) = match &self.content {
            image::LeafContent::InlineFile(data) => {
                if data.is_empty() {
                    (format::DataLayout::FlatPlain, 0, data.len() as u64)
                } else {
                    (format::DataLayout::FlatInline, 0, data.len() as u64)
                }
            }
            image::LeafContent::ExternalFile(.., size) => {
                // TODO: libcomposefs tries harder here.  Should we?
                (format::DataLayout::ChunkBased, 31, *size)
            }
            image::LeafContent::CharacterDevice(rdev) | image::LeafContent::BlockDevice(rdev) => {
                (format::DataLayout::FlatPlain, *rdev as u32, 0)
            }
            image::LeafContent::Fifo | image::LeafContent::Socket => {
                (format::DataLayout::FlatPlain, 0, 0)
            }
            image::LeafContent::Symlink(target) => {
                (format::DataLayout::FlatInline, 0, target.len() as u64)
            }
        };
        (layout, u, size, self.nlink)
    }

    fn write_inline(&self, output: &mut impl Output) {
        output.write(match self.content {
            image::LeafContent::InlineFile(data) => data,
            image::LeafContent::ExternalFile(..) => b"\xff\xff\xff\xff", // null chunk
            image::LeafContent::Symlink(target) => target.as_bytes(),
            _ => &[],
        });
    }
}

impl Inode<'_> {
    fn file_type(&self) -> format::FileType {
        match &self.content {
            InodeContent::Directory(..) => format::FileType::Directory,
            InodeContent::Leaf(leaf) => match &leaf.content {
                image::LeafContent::ExternalFile(..) | image::LeafContent::InlineFile(..) => {
                    format::FileType::RegularFile
                }
                image::LeafContent::CharacterDevice(..) => format::FileType::CharacterDevice,
                image::LeafContent::BlockDevice(..) => format::FileType::BlockDevice,
                image::LeafContent::Fifo => format::FileType::Fifo,
                image::LeafContent::Socket => format::FileType::Socket,
                image::LeafContent::Symlink(..) => format::FileType::Symlink,
            },
        }
    }

    fn write_inode(&self, output: &mut impl Output, idx: usize) {
        let (layout, u, size, nlink) = match &self.content {
            InodeContent::Directory(dir) => dir.inode_meta(output.get(Offset::Block, idx)),
            InodeContent::Leaf(leaf) => leaf.inode_meta(),
        };

        let xattr_size = {
            let mut xattr = FirstPass::default();
            self.xattrs.write(&mut xattr);
            xattr.offset
        };

        // We need to make sure the inline part doesn't overlap a block boundary
        if matches!(layout, format::DataLayout::FlatInline) {
            let inode_and_xattr_size = size_of::<format::ExtendedInodeHeader>() + xattr_size;
            let inline_start = output.len() + inode_and_xattr_size;
            let inline_end = inline_start + (size as usize % format::BLOCK_SIZE);
            if inline_start / format::BLOCK_SIZE != inline_end / format::BLOCK_SIZE {
                // If we proceed, then we'll violate the rule about crossing block boundaries.
                // The easiest thing to do is to add padding so that the inline data starts at a
                // fresh block boundary.
                let pad = vec![0; 4096 - inline_start % 4096];
                debug!("added pad {}", pad.len());
                output.write(&pad);
            }
        }

        let format = format::FormatField::from((format::InodeLayout::Extended, layout));

        output.pad(32);

        debug!(
            "write inode {idx} nid {} {:?} {:?} xattrsize{xattr_size} icount{} inline{} @{}",
            output.len() / 32,
            format,
            self.file_type(),
            match xattr_size {
                0 => 0,
                n => (1 + (n - 12) / 4) as u16,
            },
            size % 4096,
            output.len()
        );

        output.note_offset(Offset::Inode);
        output.write_struct(format::ExtendedInodeHeader {
            format,
            xattr_icount: match xattr_size {
                0 => 0,
                n => (1 + (n - 12) / 4) as u16,
            }
            .into(),
            mode: (self.stat.st_mode as u16 | self.file_type().to_ifmt()).into(),
            size: size.into(),
            u: u.into(),
            ino: ((output.len() / 32) as u32).into(),
            uid: self.stat.st_uid.into(),
            gid: self.stat.st_gid.into(),
            mtime: (self.stat.st_mtim_sec as u64).into(),
            nlink: (nlink as u32).into(),
            ..Default::default()
        });

        self.xattrs.write(output);

        match &self.content {
            InodeContent::Directory(dir) => dir.write_inline(output),
            InodeContent::Leaf(leaf) => leaf.write_inline(output),
        };

        output.pad(32);
    }

    fn write_blocks(&self, output: &mut impl Output) {
        if let InodeContent::Directory(dir) = &self.content {
            dir.write_blocks(output);
        }
    }
}

struct InodeCollector<'a> {
    inodes: Vec<Inode<'a>>,
    hardlinks: HashMap<*const image::Leaf, usize>,
}

impl<'a> InodeCollector<'a> {
    fn push_inode(&mut self, stat: &'a image::Stat, content: InodeContent<'a>) -> usize {
        let mut xattrs = InodeXAttrs::default();

        // We need to record extra xattrs for some files.  These come first.
        if let InodeContent::Leaf(Leaf {
            content: image::LeafContent::ExternalFile(id, ..),
            ..
        }) = content
        {
            let metacopy = [&[0, 36, 0, 1], &id[..]].concat();
            xattrs.add(b"trusted.overlay.metacopy", &metacopy);

            let redirect = format!("/{:02x}/{}", id[0], hex::encode(&id[1..]));
            xattrs.add(b"trusted.overlay.redirect", redirect.as_bytes());
        }

        // Add the normal xattrs.  They're already listed in sorted order.
        for (name, value) in RefCell::borrow(&stat.xattrs).iter() {
            let name = name.as_bytes();

            if let Some(escapee) = name.strip_prefix(b"trusted.overlay.") {
                let escaped = [b"trusted.overlay.overlay.", escapee].concat();
                xattrs.add(&escaped, value);
            } else {
                xattrs.add(name, value);
            }
        }

        // Allocate an inode for ourselves.  At first we write all xattrs as local.  Later (after
        // we've determined which xattrs ought to be shared) we'll come and move some of them over.
        let inode = self.inodes.len();
        self.inodes.push(Inode {
            stat,
            xattrs,
            content,
        });
        inode
    }

    fn collect_leaf(&mut self, leaf: &'a Rc<image::Leaf>) -> usize {
        let nlink = Rc::strong_count(leaf);

        if nlink > 1 {
            if let Some(inode) = self.hardlinks.get(&Rc::as_ptr(leaf)) {
                return *inode;
            }
        }

        let inode = self.push_inode(
            &leaf.stat,
            InodeContent::Leaf(Leaf {
                content: &leaf.content,
                nlink,
            }),
        );

        if nlink > 1 {
            self.hardlinks.insert(Rc::as_ptr(leaf), inode);
        }

        inode
    }

    fn insert_sorted(
        entries: &mut Vec<DirEnt<'a>>,
        name: &'a [u8],
        inode: usize,
        file_type: format::FileType,
    ) {
        let entry = DirEnt {
            name,
            inode,
            file_type,
        };
        let point = entries.partition_point(|e| e.name < entry.name);
        entries.insert(point, entry);
    }

    fn collect_dir(&mut self, dir: &'a image::Directory, parent: usize) -> usize {
        // The root inode number needs to fit in a u16.  That more or less compels us to write the
        // directory inode before the inode of the children of the directory.  Reserve a slot.
        let me = self.push_inode(&dir.stat, InodeContent::Directory(Directory::default()));

        let mut entries = vec![];

        for entry in &dir.entries {
            let child = match &entry.inode {
                image::Inode::Directory(dir) => self.collect_dir(dir, me),
                image::Inode::Leaf(leaf) => self.collect_leaf(leaf),
            };
            entries.push(DirEnt {
                name: entry.name.as_bytes(),
                inode: child,
                file_type: self.inodes[child].file_type(),
            });
        }

        // We're expected to add those, too
        Self::insert_sorted(&mut entries, b".", me, format::FileType::Directory);
        Self::insert_sorted(&mut entries, b"..", parent, format::FileType::Directory);

        // Now that we know the actual content, we can write it to our reserved slot
        self.inodes[me].content = InodeContent::Directory(Directory::from_entries(entries));
        me
    }

    pub fn collect(fs: &'a image::FileSystem) -> Vec<Inode<'a>> {
        let mut this = Self {
            inodes: vec![],
            hardlinks: HashMap::new(),
        };

        // '..' of the root directory is the root directory again
        let root_inode = this.collect_dir(&fs.root, 0);
        assert_eq!(root_inode, 0);

        this.inodes
    }
}

/// Takes a list of inodes where each inode contains only local xattr values, determines which
/// xattrs (key, value) pairs appear more than once, and shares them.
fn share_xattrs(inodes: &mut [Inode]) -> Vec<XAttr> {
    let mut xattrs: BTreeMap<XAttr, usize> = BTreeMap::new();

    // Collect all xattrs from the inodes
    for inode in inodes.iter() {
        for attr in &inode.xattrs.local {
            if let Some(count) = xattrs.get_mut(attr) {
                *count += 1;
            } else {
                xattrs.insert(attr.clone(), 1);
            }
        }
    }

    // Share only xattrs with more than one user
    xattrs.retain(|_k, v| *v > 1);

    // Repurpose the refcount field as an index lookup
    for (idx, value) in xattrs.values_mut().enumerate() {
        *value = idx;
    }

    // Visit each inode and change local xattrs into shared xattrs
    for inode in inodes.iter_mut() {
        inode.xattrs.local.retain(|attr| {
            if let Some(idx) = xattrs.get(attr) {
                inode.xattrs.shared.push(*idx);
                false // drop the local xattr: we converted it
            } else {
                true // retain the local xattr: we didn't convert it
            }
        });
    }

    // Return the shared xattrs as a vec
    xattrs.into_keys().collect()
}

fn write_erofs(output: &mut impl Output, inodes: &[Inode], xattrs: &[XAttr]) {
    // Write composefs header
    output.note_offset(Offset::Header);
    output.write_struct(format::ComposefsHeader {
        magic: format::COMPOSEFS_MAGIC,
        version: format::COMPOSEFS_VERSION,
        flags: 0.into(),
        composefs_version: format::COMPOSEFS_VERSION,
        ..Default::default()
    });
    output.pad(1024);

    // Write superblock
    output.note_offset(Offset::Superblock);
    output.write_struct(format::Superblock {
        magic: format::MAGIC_V1,
        blkszbits: format::BLOCK_BITS,
        feature_compat: format::FEATURE_COMPAT_MTIME | format::FEATURE_COMPAT_XATTR_FILTER,
        root_nid: (output.get_nid(0) as u16).into(),
        inos: (inodes.len() as u64).into(),
        blocks: ((output.get(Offset::End, 0) / format::BLOCK_SIZE) as u32).into(),
        ..Default::default()
    });

    // Write inode table
    for (idx, inode) in inodes.iter().enumerate() {
        // The inode may add padding to itself, so it notes its own offset
        inode.write_inode(output, idx);
    }

    // Write shared xattr table
    for xattr in xattrs {
        output.note_offset(Offset::XAttr);
        xattr.write(output);
    }

    // Write blocks from inodes that have them
    output.pad(4096);
    for inode in inodes.iter() {
        output.note_offset(Offset::Block);
        inode.write_blocks(output);
    }

    // That's it
    output.note_offset(Offset::End);
}

#[derive(Default)]
struct Layout {
    offset_types: Vec<usize>,
    offsets: Vec<usize>,
}

#[derive(Default)]
struct FirstPass {
    offset: usize,
    layout: Layout,
}

struct SecondPass {
    output: Vec<u8>,
    layout: Layout,
}

impl Output for SecondPass {
    fn note_offset(&mut self, _offset_type: Offset) {
        /* no-op */
    }

    fn get(&self, offset_type: Offset, idx: usize) -> usize {
        self.layout.offsets[self.layout.offset_types[offset_type as usize] + idx]
    }

    fn write(&mut self, data: &[u8]) {
        self.output.extend_from_slice(data);
    }

    fn pad(&mut self, alignment: usize) {
        self.output
            .resize(round_up(self.output.len(), alignment), 0);
    }

    fn len(&self) -> usize {
        self.output.len()
    }
}

impl Output for FirstPass {
    fn note_offset(&mut self, offset_type: Offset) {
        if self.layout.offset_types.len() == offset_type as usize {
            self.layout.offset_types.push(self.layout.offsets.len());
        }
        debug!(
            "{:?} #{} @{}",
            offset_type,
            self.layout.offsets.len() - self.layout.offset_types[offset_type as usize],
            self.offset
        );
        self.layout.offsets.push(self.offset);
    }

    fn get(&self, _: Offset, _: usize) -> usize {
        0 // We don't know offsets in the first pass, so fake it
    }

    fn write(&mut self, data: &[u8]) {
        self.offset += data.len();
    }

    fn pad(&mut self, alignment: usize) {
        self.offset = round_up(self.offset, alignment);
    }

    fn len(&self) -> usize {
        self.offset
    }
}

pub fn mkfs_erofs(fs: &image::FileSystem) -> Box<[u8]> {
    // Create the intermediate representation: flattened inodes and shared xattrs
    let mut inodes = InodeCollector::collect(fs);
    let xattrs = share_xattrs(&mut inodes);

    // Do a first pass with the writer to determine the layout
    let mut first_pass = FirstPass::default();
    write_erofs(&mut first_pass, &inodes, &xattrs);

    // Do a second pass with the writer to get the actual bytes
    let mut second_pass = SecondPass {
        output: vec![],
        layout: first_pass.layout,
    };
    write_erofs(&mut second_pass, &inodes, &xattrs);

    // That's it
    second_pass.output.into_boxed_slice()
}

pub fn mkfs_mkcomposefs(filesystem: &FileSystem) -> Result<Box<[u8]>> {
    let mut mkcomposefs = Command::new("mkcomposefs")
        .args(["--from-file", "-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let mut stdin = mkcomposefs.stdin.take().unwrap();
    write_dumpfile(&mut stdin, filesystem)?;
    drop(stdin);

    let mut stdout = mkcomposefs.stdout.take().unwrap();
    let mut image = vec![];
    stdout.read_to_end(&mut image)?;
    drop(stdout);

    if !mkcomposefs.wait()?.success() {
        bail!("mkcomposefs failed");
    };

    Ok(image.into())
}

pub fn mkfs(fs: &FileSystem) -> Result<Box<[u8]>> {
    let image = match env::var("COMPOSEFS_FORMAT") {
        Ok(s) if s == "new" => mkfs_erofs(fs),
        _ => mkfs_mkcomposefs(fs)?,
    };

    if env::var("COMPOSEFS_DUMP_EROFS") == Ok("1".to_string()) {
        debug_img(&image);
    }

    Ok(image)
}
