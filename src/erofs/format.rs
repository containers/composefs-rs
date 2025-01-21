use zerocopy::{
    little_endian::{U16, U32, U64},
    Immutable, IntoBytes, KnownLayout, TryFromBytes,
};

#[derive(Debug)]
pub enum FormatError {
    InvalidDataLayout,
}

pub const BLOCK_BITS: u8 = 12;
pub const BLOCK_SIZE: usize = 1 << BLOCK_BITS;

/* composefs Header */

pub const COMPOSEFS_VERSION: U32 = U32::new(1);
pub const COMPOSEFS_MAGIC: U32 = U32::new(0xd078629a);

#[derive(Debug, Immutable, IntoBytes, TryFromBytes)]
#[repr(u32)]
pub enum ComposefsFlags {
    HasAcl = 1 << 0,
}

#[derive(Debug, Default, Immutable, IntoBytes, KnownLayout, TryFromBytes)]
#[repr(C)]
pub struct ComposefsHeader {
    pub magic: U32,
    pub version: U32,
    pub flags: U32,
    pub composefs_version: U32,
    pub unused: [U32; 4],
}

/* Superblock */

pub const MAGIC_V1: U32 = U32::new(0xE0F5E1E2);
pub const FEATURE_COMPAT_MTIME: U32 = U32::new(2);
pub const FEATURE_COMPAT_XATTR_FILTER: U32 = U32::new(4);

#[derive(Debug, Default, Immutable, IntoBytes, KnownLayout, TryFromBytes)]
#[repr(C)]
pub struct Superblock {
    // vertical whitespace every 16 bytes (hexdump-friendly)
    pub magic: U32,
    pub checksum: U32,
    pub feature_compat: U32,
    pub blkszbits: u8,
    pub extslots: u8,
    pub root_nid: U16,

    pub inos: U64,
    pub build_time: U64,

    pub build_time_nsec: U32,
    pub blocks: U32,
    pub meta_blkaddr: U32,
    pub xattr_blkaddr: U32,

    pub uuid: [u8; 16],

    pub volume_name: [u8; 16],

    pub feature_incompat: U32,
    pub available_compr_algs: U16,
    pub extra_devices: U16,
    pub devt_slotoff: U16,
    pub dirblkbits: u8,
    pub xattr_prefix_count: u8,
    pub xattr_prefix_start: U32,

    pub packed_nid: U64,
    pub xattr_filter_reserved: u8,
    pub reserved2: [u8; 23],
}

/* Inodes */

#[derive(Debug, Default, Immutable, IntoBytes, KnownLayout, TryFromBytes)]
#[repr(C)]
pub struct CompactInodeHeader {
    pub format: FormatField,
    pub xattr_icount: U16,
    pub mode: U16,
    pub nlink: U16,

    pub size: U32,
    pub reserved: U32,

    pub u: U32,
    pub ino: U32, // only used for 32-bit stat compatibility

    pub uid: U16,
    pub gid: U16,
    pub reserved2: [u8; 4],
}

#[derive(Debug, Default, Immutable, IntoBytes, KnownLayout, TryFromBytes)]
#[repr(C)]
pub struct ExtendedInodeHeader {
    pub format: FormatField,
    pub xattr_icount: U16,
    pub mode: U16,
    pub reserved: U16,
    pub size: U64,

    pub u: U32,
    pub ino: U32, // only used for 32-bit stat compatibility
    pub uid: U32,
    pub gid: U32,

    pub mtime: U64,

    pub mtime_nsec: U32,
    pub nlink: U32,

    pub reserved2: [u8; 16],
}

#[derive(Debug, Default, Immutable, KnownLayout, IntoBytes, TryFromBytes)]
#[repr(C)]
pub struct InodeXAttrHeader {
    pub name_filter: U32,
    pub shared_count: u8,
    pub reserved: [u8; 7],
}

#[derive(Clone, Copy, Immutable, KnownLayout, IntoBytes, PartialEq, TryFromBytes)]
pub struct FormatField(U16);

impl Default for FormatField {
    fn default() -> Self {
        Self(0xffff.into())
    }
}

impl std::fmt::Debug for FormatField {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{} = {:?} | {:?}",
            self.0.get(),
            InodeLayout::from(*self),
            DataLayout::try_from(*self)
        )
    }
}

const INODE_LAYOUT_MASK: u16 = 0b00000001;
const INODE_LAYOUT_COMPACT: u16 = 0;
const INODE_LAYOUT_EXTENDED: u16 = 1;

#[derive(Debug)]
#[repr(u16)]
pub enum InodeLayout {
    Compact = INODE_LAYOUT_COMPACT,
    Extended = INODE_LAYOUT_EXTENDED,
}

impl From<FormatField> for InodeLayout {
    fn from(value: FormatField) -> Self {
        match value.0.get() & INODE_LAYOUT_MASK {
            INODE_LAYOUT_COMPACT => InodeLayout::Compact,
            INODE_LAYOUT_EXTENDED => InodeLayout::Extended,
            _ => unreachable!(),
        }
    }
}

const INODE_DATALAYOUT_MASK: u16 = 0b00001110;
const INODE_DATALAYOUT_FLAT_PLAIN: u16 = 0;
const INODE_DATALAYOUT_FLAT_INLINE: u16 = 4;
const INODE_DATALAYOUT_CHUNK_BASED: u16 = 8;

#[derive(Debug)]
#[repr(u16)]
pub enum DataLayout {
    FlatPlain = 0,
    FlatInline = 4,
    ChunkBased = 8,
}

impl TryFrom<FormatField> for DataLayout {
    type Error = FormatError;

    fn try_from(value: FormatField) -> Result<Self, FormatError> {
        match value.0.get() & INODE_DATALAYOUT_MASK {
            INODE_DATALAYOUT_FLAT_PLAIN => Ok(DataLayout::FlatPlain),
            INODE_DATALAYOUT_FLAT_INLINE => Ok(DataLayout::FlatInline),
            INODE_DATALAYOUT_CHUNK_BASED => Ok(DataLayout::ChunkBased),
            _ => Err(FormatError::InvalidDataLayout),
        }
    }
}

impl From<(InodeLayout, DataLayout)> for FormatField {
    fn from(value: (InodeLayout, DataLayout)) -> FormatField {
        FormatField(
            (match value.0 {
                InodeLayout::Compact => INODE_LAYOUT_COMPACT,
                InodeLayout::Extended => INODE_LAYOUT_EXTENDED,
            } | match value.1 {
                DataLayout::FlatPlain => INODE_DATALAYOUT_FLAT_PLAIN,
                DataLayout::FlatInline => INODE_DATALAYOUT_FLAT_INLINE,
                DataLayout::ChunkBased => INODE_DATALAYOUT_CHUNK_BASED,
            })
            .into(),
        )
    }
}

/* Extended attributes */
pub const XATTR_FILTER_SEED: u32 = 0x25BBE08F;

#[derive(Debug, Immutable, IntoBytes, KnownLayout, TryFromBytes)]
#[repr(C)]
pub struct XAttrHeader {
    pub name_len: u8,
    pub name_index: u8,
    pub value_size: U16,
}

pub const XATTR_PREFIXES: [&[u8]; 7] = [
    b"",
    b"user.",
    b"system.posix_acl_access",
    b"system.posix_acl_default",
    b"trusted.",
    b"lustre.",
    b"security.",
];

/* Directories */

#[derive(Clone, Copy, Debug, Default, Immutable, IntoBytes, TryFromBytes)]
#[repr(u8)]
pub enum FileType {
    #[default]
    Unknown,
    RegularFile,
    Directory,
    CharacterDevice,
    BlockDevice,
    Fifo,
    Socket,
    Symlink,
}
pub const S_IFMT: u16 = 0o170000;
pub const S_IFREG: u16 = 0o100000;
pub const S_IFCHR: u16 = 0o020000;
pub const S_IFDIR: u16 = 0o040000;
pub const S_IFBLK: u16 = 0o060000;
pub const S_IFIFO: u16 = 0o010000;
pub const S_IFLNK: u16 = 0o120000;
pub const S_IFSOCK: u16 = 0o140000;

impl FileType {
    pub fn to_ifmt(&self) -> u16 {
        match self {
            Self::RegularFile => S_IFREG,
            Self::CharacterDevice => S_IFCHR,
            Self::Directory => S_IFDIR,
            Self::BlockDevice => S_IFBLK,
            Self::Fifo => S_IFIFO,
            Self::Symlink => S_IFLNK,
            Self::Socket => S_IFSOCK,
            Self::Unknown => unreachable!(),
        }
    }
}

#[derive(Debug, Default, Immutable, IntoBytes, KnownLayout, TryFromBytes)]
#[repr(C)]
pub struct DirectoryEntryHeader {
    pub inode_offset: U64,
    pub name_offset: U16,
    pub file_type: FileType, // TODO: change to u8 for trivial transmute?
    pub reserved: u8,
}
