//! Debug implementations for EROFS on-disk format structures.

use std::fmt;

use crate::format::{CompactInodeHeader, ComposefsHeader, ExtendedInodeHeader, Superblock};

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
