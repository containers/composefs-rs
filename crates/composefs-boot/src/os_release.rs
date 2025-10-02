//! Parsing and handling of os-release files.
//!
//! This module provides functionality to parse os-release files according to the
//! freedesktop.org specification. It handles shell-style quoting and variable assignment,
//! extracting common fields like PRETTY_NAME, VERSION_ID, and ID for use in boot labels.
//! The `OsReleaseInfo` type provides methods to generate appropriate boot entry titles.

use std::collections::HashMap;

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

#[derive(Debug)]
pub struct OsReleaseInfo<'a> {
    map: HashMap<&'a str, &'a str>,
}

impl<'a> OsReleaseInfo<'a> {
    /// Parses an /etc/os-release file
    pub fn parse(content: &'a str) -> Self {
        let map = HashMap::from_iter(
            content
                .lines()
                .filter(|line| !line.trim().starts_with('#'))
                .filter_map(|line| line.split_once('=')),
        );
        Self { map }
    }

    /// Looks up a key (like "PRETTY_NAME") in the os-release file and returns the properly
    /// dequoted and unescaped value, if one exists.
    pub fn get_value(&self, keys: &[&str]) -> Option<String> {
        keys.iter()
            .find_map(|key| self.map.get(key).and_then(|v| dequote(v)))
    }

    /// Returns the value of the PRETTY_NAME, NAME, or ID field, whichever is found first.
    pub fn get_pretty_name(&self) -> Option<String> {
        self.get_value(&["PRETTY_NAME", "NAME", "ID"])
    }

    /// Returns the value of the VERSION_ID or VERSION field, whichever is found first.
    pub fn get_version(&self) -> Option<String> {
        self.get_value(&["VERSION_ID", "VERSION"])
    }

    /// Combines get_pretty_name() with get_version() as specified in the Boot Loader
    /// Specification to produce a boot label.  This will return None if we can't find a name, but
    /// failing to find a version isn't fatal.
    pub fn get_boot_label(&self) -> Option<String> {
        let mut result = self.get_pretty_name()?;
        if let Some(version) = self.get_version() {
            result.push_str(&format!(" {version}"));
        }
        Some(result)
    }
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

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
            let info = OsReleaseInfo::parse(osrel);
            assert_eq!(info.get_boot_label().unwrap(), label);
        }
    }
}
