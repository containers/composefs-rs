use thiserror::Error;
use zerocopy::{
    little_endian::{U16, U32},
    FromBytes, Immutable, KnownLayout,
};

use crate::os_release::OsReleaseInfo;

// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
#[derive(Debug, FromBytes, Immutable, KnownLayout)]
#[cfg_attr(test, derive(zerocopy::IntoBytes, Default))]
#[repr(C)]
struct DosStub {
    _unused1: [u8; 0x20],
    _unused2: [u8; 0x1c],
    pe_offset: U32,
}

#[derive(Debug, FromBytes, Immutable, KnownLayout)]
#[cfg_attr(test, derive(zerocopy::IntoBytes, Default))]
#[repr(C)]
struct CoffFileHeader {
    machine: U16,
    number_of_sections: U16,
    time_date_stamp: U32,
    pointer_to_symbol_table: U32,
    number_of_symbols: U32,
    size_of_optional_header: U16,
    characteristics: U16,
}

#[derive(Debug, FromBytes, Immutable, KnownLayout)]
#[cfg_attr(test, derive(zerocopy::IntoBytes, Default))]
#[repr(C)]
struct PeHeader {
    pe_magic: [u8; 4], // P E \0 \0
    coff_file_header: CoffFileHeader,
}
const PE_MAGIC: [u8; 4] = *b"PE\0\0";

#[derive(Debug, FromBytes, Immutable, KnownLayout)]
#[cfg_attr(test, derive(zerocopy::IntoBytes, Default))]
#[repr(C)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: U32,
    virtual_address: U32,
    size_of_raw_data: U32,
    pointer_to_raw_data: U32,
    pointer_to_relocations: U32,
    pointer_to_line_numbers: U32,
    number_of_relocations: U16,
    number_of_line_numbers: U16,
    characteristics: U32,
}

#[derive(Debug, Error, PartialEq)]
pub enum UkiError {
    #[error("UKI is not valid EFI executable")]
    PortableExecutableError,
    #[error("UKI doesn't contain a '{0}' section")]
    MissingSection(&'static str),
    #[error("UKI section '{0}' is not UTF-8")]
    UnicodeError(&'static str),
    #[error("No name information found in .osrel section")]
    NoName,
}

// We use `None` as a way to say `Err(UkiError::PortableExecutableError)` for two reasons:
//   - .get(..) returns Option<> and using `?` with that is extremely convenient
//   - the error types returned from FromBytes can't be used with `?` because they try to return a
//     reference to the data, which causes problems with lifetime rules
//   - it saves us from having to type Err(UkiError::PortableExecutableError) everywhere
fn get_text_section<'a>(
    image: &'a [u8],
    section_name: &'static str,
) -> Option<Result<&'a str, UkiError>> {
    // Turn the section_name ".osrel" into a section_key b".osrel\0\0".
    // This will panic if section_name.len() > 8, which is what we want.
    let mut section_key = [0u8; 8];
    section_key[..section_name.len()].copy_from_slice(section_name.as_bytes());

    // Skip the DOS stub
    let (dos_stub, ..) = DosStub::ref_from_prefix(image).ok()?;
    let rest = image.get(dos_stub.pe_offset.get() as usize..)?;

    // Get the PE header
    let (pe_header, rest) = PeHeader::ref_from_prefix(rest).ok()?;
    if pe_header.pe_magic != PE_MAGIC {
        return None;
    }

    // Skip the optional header
    let rest = rest.get(pe_header.coff_file_header.size_of_optional_header.get() as usize..)?;

    // Try to load the section headers
    let n_sections = pe_header.coff_file_header.number_of_sections.get() as usize;
    let (sections, ..) = <[SectionHeader]>::ref_from_prefix_with_elems(rest, n_sections).ok()?;

    for section in sections {
        if section.name == section_key {
            let bytes = image
                .get(section.pointer_to_raw_data.get() as usize..)?
                .get(..section.virtual_size.get() as usize)?;
            return Some(std::str::from_utf8(bytes).or(Err(UkiError::UnicodeError(section_name))));
        }
    }

    Some(Err(UkiError::MissingSection(section_name)))
}

/// Gets an appropriate label for display in the boot menu for the given UKI image, according to
/// the "Type #2 EFI Unified Kernel Images" section in the Boot Loader Specification.  This will be
/// based on the "PRETTY_NAME" and "VERSION_ID" fields found in the os-release file (falling back
/// to "ID" and/or "VERSION" if they are not present).
///
/// For more information, see:
///  - <https://uapi-group.org/specifications/specs/boot_loader_specification/>
///  - <https://www.freedesktop.org/software/systemd/man/latest/os-release.html>
///
/// # Arguments
///
///  * `image`: the complete UKI image as a byte slice
///
/// # Return value
///
/// If we could successfully parse the provided UKI as a Portable Executable file and find an
/// ".osrel" section in it, return a string to use as the boootloader entry.  If we were unable to
/// find any meaningful content in the os-release information this will be "Unknown 0".
///
/// If we couldn't parse the PE file or couldn't find an ".osrel" section then an error will be
/// returned.
pub fn get_boot_label(image: &[u8]) -> Result<String, UkiError> {
    let osrel = get_text_section(image, ".osrel").ok_or(UkiError::PortableExecutableError)??;
    OsReleaseInfo::parse(osrel)
        .get_boot_label()
        .ok_or(UkiError::NoName)
}

/// Gets the contents of the .cmdline section of a UKI.
pub fn get_cmdline(image: &[u8]) -> Result<&str, UkiError> {
    get_text_section(image, ".cmdline").ok_or(UkiError::PortableExecutableError)?
}

#[cfg(test)]
mod test {
    use core::mem::size_of;

    use similar_asserts::assert_eq;
    use zerocopy::IntoBytes;

    use super::*;

    fn data_offset(n_sections: usize) -> usize {
        size_of::<DosStub>() + size_of::<PeHeader>() + n_sections * size_of::<SectionHeader>()
    }

    fn peify(optional: &[u8], sections: &[SectionHeader], rest: &[&[u8]]) -> Vec<u8> {
        let mut output = vec![];
        output.extend_from_slice(
            DosStub {
                pe_offset: U32::new(size_of::<DosStub>() as u32),
                ..Default::default()
            }
            .as_bytes(),
        );
        output.extend_from_slice(
            PeHeader {
                pe_magic: PE_MAGIC,
                coff_file_header: CoffFileHeader {
                    number_of_sections: U16::new(sections.len() as u16),
                    size_of_optional_header: U16::new(optional.len() as u16),
                    ..Default::default()
                },
            }
            .as_bytes(),
        );
        output.extend_from_slice(optional);
        for section in sections {
            output.extend_from_slice(section.as_bytes());
        }
        assert_eq!(output.len(), data_offset(sections.len()));
        for data in rest {
            output.extend_from_slice(data);
        }

        output
    }

    fn ukify(osrel: &[u8]) -> Vec<u8> {
        let osrel_offset = data_offset(1);
        peify(
            b"",
            &[SectionHeader {
                name: *b".osrel\0\0",
                virtual_size: U32::new(osrel.len() as u32),
                pointer_to_raw_data: U32::new(osrel_offset as u32),
                ..Default::default()
            }],
            &[osrel],
        )
    }

    #[test]
    fn test_simple() {
        let uki = ukify(
            br#"
PRETTY_NAME='prettyOS'
VERSION_ID="Rocky Racoon"
VERSION=42
ID=pretty-os
"#,
        );

        assert_eq!(
            get_boot_label(uki.as_ref()).unwrap(),
            "prettyOS Rocky Racoon"
        );
    }

    #[test]
    fn test_bad_pe() {
        fn pe_err(img: &[u8]) {
            assert_eq!(get_boot_label(img), Err(UkiError::PortableExecutableError));
        }
        fn no_sec(img: &[u8]) {
            assert_eq!(get_boot_label(img), Err(UkiError::MissingSection(".osrel")));
        }

        pe_err(b"");
        pe_err(b"This is definitely not an EFI executable, but it's big enough to pass the first step...");

        pe_err(
            DosStub {
                pe_offset: U32::new(0),
                ..Default::default()
            }
            .as_bytes(),
        );

        // no section headers
        no_sec(&peify(b"", &[], &[]));
        // no .osrel section
        no_sec(&peify(
            b"",
            &[
                SectionHeader {
                    name: *b".text\0\0\0",
                    ..Default::default()
                },
                SectionHeader {
                    name: *b".rodata\0",
                    ..Default::default()
                },
            ],
            &[],
        ));

        // .osrel points to invalid offset
        pe_err(&peify(
            b"",
            &[SectionHeader {
                name: *b".osrel\0\0",
                pointer_to_raw_data: U32::new(1234567),
                ..Default::default()
            }],
            &[],
        ));
    }
}
