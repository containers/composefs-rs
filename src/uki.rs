use std::collections::HashMap;

use thiserror::Error;
use zerocopy::{
    little_endian::{U16, U32},
    FromBytes, Immutable, KnownLayout,
};

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
const OSREL_SECTION: [u8; 8] = *b".osrel\0\0";

#[derive(Debug, Error, PartialEq)]
pub enum UkiError {
    #[error("UKI is not valid EFI executable")]
    PortableExecutableError,
    #[error("UKI doesn't contain a '.osrel' section")]
    MissingOsrelSection,
    #[error(".osrel section is not UTF-8")]
    UnicodeError,
    #[error("No name information found in .osrel section")]
    NoName,
}

// We use `None` as a way to say `Err(UkiError::PortableExecutableError)` for two reasons:
//   - .get(..) returns Option<> and using `?` with that is extremely convenient
//   - the error types returned from FromBytes can't be used with `?` because they try to return a
//     reference to the data, which causes problems with lifetime rules
//   - it saves us from having to type Err(UkiError::PortableExecutableError) everywhere
fn get_osrel_section(image: &[u8]) -> Option<Result<&str, UkiError>> {
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
        if section.name == OSREL_SECTION {
            let bytes = image
                .get(section.pointer_to_raw_data.get() as usize..)?
                .get(..section.virtual_size.get() as usize)?;
            return Some(std::str::from_utf8(bytes).or(Err(UkiError::UnicodeError)));
        }
    }

    Some(Err(UkiError::MissingOsrelSection))
}

// We could be using 'shlex' for this but we really only need to parse a subset of the spec and
// it's easy enough to do for ourselves.  Also note that the spec itself suggests using
// `ast.literal_eval()` in Python which is substantially different from a proper shlex,
// particularly in terms of treatment of escape sequences.
fn dequote(value: &str) -> Option<String> {
    // https://pubs.opengroup.org/onlinepubs/009604499/utilities/xcu_chap02.html
    let mut result = String::new();
    let mut iter = value.trim().chars();

    // os-release spec says we don't have to support concatenation of independently-quoted
    // substrings, but honestly, it's easier if we do...
    while let Some(c) = iter.next() {
        match c {
            '"' => loop {
                result.push(match iter.next()? {
                    // Strictly speaking, we should only handle \" \$ \` and \\...
                    '\\' => iter.next()?,
                    '"' => break,
                    other => other,
                });
            },

            '\'' => loop {
                result.push(match iter.next()? {
                    '\'' => break,
                    other => other,
                });
            },

            // Per POSIX we should handle '\\' sequences here, but os-release spec says we'll only
            // encounter A-Za-z0-9 outside of quotes, so let's not bother with that for now...
            other => result.push(other),
        }
    }

    Some(result)
}

/// Gets the value that matches the first key that's present and successfully dequotes, or None.
fn get_value(map: &HashMap<&str, &str>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| map.get(key).and_then(|v| dequote(v)))
}

/// Gets an appropriate label for display in the boot menu for the given UKI image, according to
/// the "Type #2 EFI Unified Kernel Images" section in the Boot Loader Specification.  This will be
/// based on the "PRETTY_NAME" and "VERSION_ID" fields found in the os-release file (falling back
/// to "ID" and/or "VERSION" if they are not present).
///
/// For more information, see:
///  - https://uapi-group.org/specifications/specs/boot_loader_specification/
///  - https://www.freedesktop.org/software/systemd/man/latest/os-release.html
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
    let osrel = get_osrel_section(image).ok_or(UkiError::PortableExecutableError)??;
    let map = HashMap::from_iter(
        osrel
            .lines()
            .filter(|line| !line.trim().starts_with('#'))
            .filter_map(|line| line.split_once('=')),
    );

    // At least one of the name fields must be present
    let mut result = get_value(&map, &["PRETTY_NAME", "NAME", "ID"]).ok_or(UkiError::NoName)?;

    // But version is optional
    if let Some(version) = get_value(&map, &["VERSION_ID", "VERSION"]) {
        result.push_str(&format!(" {version}"));
    }

    Ok(result)
}

#[cfg(test)]
mod test {
    use core::mem::size_of;

    use similar_asserts::assert_eq;
    use zerocopy::IntoBytes;

    use super::*;

    #[test]
    fn test_dequote() {
        let cases = r##"

        We encode the testcases inside of a custom string format to give
        us more flexibility and less visual noise.  Lines with 4 pipes
        are successful testcases (left is quoted, right is unquoted):

            |"example"|        |example|

        and lines with 2 pipes are failing testcases:

            |"broken example|

        Lines with no pipes are ignored as comments.  Now, the cases:

            ||                  ||              Empty is empty...
            |""|                ||
            |''|                ||
            |""''""|            ||

        Unquoted stuff

            |hello|             |hello|
            |1234|              |1234|
            |\\\\|              |\\\\|          ...this is non-POSIX...
            |\$\`\\|            |\$\`\\|        ...this too...

        Double quotes

            |"closed"|          |closed|
            |"closed\\"|        |closed\|
            |"a"|               |a|
            |" "|               | |
            |"\""|              |"|
            |"\\"|              |\|
            |"\$5"|             |$5|
            |"$5"|              |$5|            non-POSIX
            |"\`tick\`"|        |`tick`|
            |"`tick`"|          |`tick`|        non-POSIX

            |"\'"|              |'|             non-POSIX
            |"\'"|              |'|             non-POSIX

            ...failures...
            |"not closed|
            |"not closed\"|
            |"|
            |"\\|
            |"\"|

        Single quotes

            |'a'|               |a|
            |' '|               | |
            |'\'|               |\|
            |'\$'|              |\$|
            |'closed\'|         |closed\|

            ...failures...
            |'|                 not closed
            |'not closed|
            |'\''|              this is '\' + a second unclosed quote '

        "##;

        for case in cases.lines() {
            match case.split('|').collect::<Vec<&str>>()[..] {
                [_comment] => {}
                [_, quoted, _, result, _] => assert_eq!(dequote(quoted).as_deref(), Some(result)),
                [_, quoted, _] => assert_eq!(dequote(quoted), None),
                _ => unreachable!("Invalid test line {case:?}"),
            }
        }
    }

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
                name: OSREL_SECTION,
                virtual_size: U32::new(osrel.len() as u32),
                pointer_to_raw_data: U32::new(osrel_offset as u32),
                ..Default::default()
            }],
            &[osrel],
        )
    }

    #[test]
    fn test_fallbacks() {
        let cases = [
            (
                r#"
PRETTY_NAME='prettyOS'
VERSION_ID="Rocky Racoon"
VERSION=42
ID=pretty-os
"#,
                "prettyOS Rocky Racoon",
            ),
            (
                r#"
PRETTY_NAME='prettyOS
VERSION_ID="Rocky Racoon"
VERSION=42
ID=pretty-os
"#,
                "pretty-os Rocky Racoon",
            ),
            (
                r#"
PRETTY_NAME='prettyOS
VERSION=42
ID=pretty-os
"#,
                "pretty-os 42",
            ),
            (
                r#"
PRETTY_NAME='prettyOS
VERSION=42
ID=pretty-os
"#,
                "pretty-os 42",
            ),
            (
                r#"
PRETTY_NAME='prettyOS'
ID=pretty-os
"#,
                "prettyOS",
            ),
            (
                r#"
ID=pretty-os
"#,
                "pretty-os",
            ),
        ];

        for (osrel, label) in cases {
            assert_eq!(
                get_boot_label(&ukify(osrel.as_bytes())).as_deref(),
                Ok(label)
            );
        }
    }

    #[test]
    fn test_bad_pe() {
        fn pe_err(img: &[u8]) {
            assert_eq!(get_boot_label(img), Err(UkiError::PortableExecutableError));
        }
        fn no_sec(img: &[u8]) {
            assert_eq!(get_boot_label(img), Err(UkiError::MissingOsrelSection));
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
                name: OSREL_SECTION,
                pointer_to_raw_data: U32::new(1234567),
                ..Default::default()
            }],
            &[],
        ));
    }
}
