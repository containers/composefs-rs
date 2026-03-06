//! Debug implementations for EROFS on-disk format structures.

use std::fmt;

use zerocopy::FromBytes;

use crate::format::{self, CompactInodeHeader, ComposefsHeader, ExtendedInodeHeader, Superblock};
use crate::reader::{DataBlock, DirectoryBlock, Inode, InodeHeader, InodeOps, XAttr};

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

fn utf8_or_hex(data: &[u8]) -> String {
    if let Ok(string) = std::str::from_utf8(data) {
        format!("{string:?}")
    } else {
        hex::encode(data)
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
        let Some(inline) = self.inline() else {
            // No inline data
            return Ok(());
        };

        // Directory dump
        if self.header.mode().is_dir() {
            let dir = DirectoryBlock::ref_from_bytes(inline).unwrap();
            let offset = addr!(dir) - addr!(self);
            return write!(
                f,
                "     +{offset:02x} --- inline directory entries ---{dir:#?}"
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
