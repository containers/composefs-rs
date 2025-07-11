use anyhow::{Context, Result};
use composefs::fsverity::FsVerityHashValue;

/// Perform kernel command line splitting.
///
/// The way this works in the kernel is to split on whitespace with an extremely simple quoting
/// mechanism: whitespace inside of double quotes is literal, but there is no escaping mechanism.
/// That means that having a literal double quote in the cmdline is effectively impossible.
pub(crate) fn split_cmdline(cmdline: &str) -> impl Iterator<Item = &str> {
    let mut in_quotes = false;

    cmdline.split(move |c: char| {
        if c == '"' {
            in_quotes = !in_quotes;
        }
        !in_quotes && c.is_ascii_whitespace()
    })
}

/// Gets the value of an entry from the kernel cmdline.
///
/// The prefix should be something like "composefs=".
///
/// This iterates the entries in the provided cmdline string searching for an entry that starts
/// with the provided prefix.  This will successfully handle quoting of other items in the cmdline,
/// but the value of the searched entry is returned verbatim (ie: not dequoted).
pub fn get_cmdline_value<'a>(cmdline: &'a str, prefix: &str) -> Option<&'a str> {
    split_cmdline(cmdline).find_map(|item| item.strip_prefix(prefix))
}

pub fn get_cmdline_composefs<ObjectID: FsVerityHashValue>(
    cmdline: &str,
) -> Result<(ObjectID, bool)> {
    let id = get_cmdline_value(cmdline, "composefs=").context("composefs= value not found")?;
    if let Some(stripped) = id.strip_prefix('?') {
        Ok((ObjectID::from_hex(stripped)?, true))
    } else {
        Ok((ObjectID::from_hex(id)?, false))
    }
}

pub fn make_cmdline_composefs(id: &str, insecure: bool) -> String {
    match insecure {
        true => format!("composefs=?{id}"),
        false => format!("composefs={id}"),
    }
}
