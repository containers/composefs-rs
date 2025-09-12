use core::ops::Range;
use std::{collections::HashMap, ffi::OsStr, os::unix::ffi::OsStrExt, str::from_utf8};

use anyhow::{bail, Result};

use composefs::{
    fsverity::FsVerityHashValue,
    repository::Repository,
    tree::{Directory, FileSystem, ImageError, Inode, LeafContent, RegularFile},
};

use crate::cmdline::{Cmdline, Parameter};

/// Strips the key (if it matches) plus the following whitespace from a single line in a "Type #1
/// Boot Loader Specification Entry" file.
///
/// The line needs to start with the name of the key, followed by at least one whitespace
/// character.  The whitespace is consumed.  If the current line doesn't match the key, None is
/// returned.
fn strip_ble_key<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?;
    if !rest.chars().next()?.is_ascii_whitespace() {
        return None;
    }
    Some(rest.trim_start())
}

// https://doc.rust-lang.org/std/primitive.str.html#method.substr_range
fn substr_range(parent: &str, substr: &str) -> Option<Range<usize>> {
    let parent_start = parent as *const str as *const u8 as usize;
    let parent_end = parent_start + parent.len();
    let substr_start = substr as *const str as *const u8 as usize;
    let substr_end = substr_start + substr.len();

    if parent_start <= substr_start && substr_end <= parent_end {
        Some((substr_start - parent_start)..(substr_end - parent_start))
    } else {
        None
    }
}

#[derive(Debug)]
pub struct BootLoaderEntryFile {
    pub lines: Vec<String>,
}

impl BootLoaderEntryFile {
    pub fn new(content: &str) -> Self {
        Self {
            lines: content.split_terminator('\n').map(String::from).collect(),
        }
    }

    pub fn get_values<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.lines
            .iter()
            .filter_map(|line| strip_ble_key(line, key))
    }

    pub fn get_value(&self, key: &str) -> Option<&str> {
        self.lines.iter().find_map(|line| strip_ble_key(line, key))
    }

    /// Adds a kernel command-line argument, possibly replacing a previous value.
    ///
    /// arg can be something like "composefs=xyz" but it can also be something like "rw".  In
    /// either case, if the argument already existed, it will be replaced.
    pub fn add_cmdline(&mut self, arg: &Parameter) {
        // There are three possible paths in this function:
        //   1. options line with key= already in it (replace it)
        //   2. options line with no key= in it (append key=value)
        //   3. no options line (append the entire thing)
        for line in &mut self.lines {
            if let Some(cmdline) = strip_ble_key(line, "options") {
                let mut cmdline = Cmdline::from(cmdline);
                cmdline.add_or_modify(arg);

                *line = format!("options {cmdline}");
                return;
            }
        }

        // 3. Append new "options" line with our argument
        self.lines.push(format!("options {arg}"));
    }

    /// Adjusts the kernel command-line arguments by adding a composefs= parameter (if appropriate)
    /// and adding additional arguments, as requested.
    pub fn adjust_cmdline<T: FsVerityHashValue>(
        &mut self,
        composefs: Option<&T>,
        insecure: bool,
        extra: &[Parameter],
    ) {
        if let Some(id) = composefs {
            let id = id.to_hex();
            let cfs_str = match insecure {
                true => format!("composefs=?{id}"),
                false => format!("composefs={id}"),
            };

            let param = Parameter::parse(&cfs_str).unwrap();
            self.add_cmdline(&param);
        }

        for item in extra {
            self.add_cmdline(item);
        }
    }
}

#[derive(Debug)]
pub struct Type1Entry<ObjectID: FsVerityHashValue> {
    /// This is the basename of the bootloader entry .conf file
    pub filename: Box<OsStr>,
    pub entry: BootLoaderEntryFile,
    pub files: HashMap<Box<str>, RegularFile<ObjectID>>,
}

impl<ObjectID: FsVerityHashValue> Type1Entry<ObjectID> {
    // Relocates boot resources.
    //
    // This is a bit of a strange operation: for each file mentioned in the bootloader entry, move
    // the file into the given 'entry_id' pathname and rename the entry file itself to
    // "{entry_id}.conf".
    pub fn relocate(&mut self, boot_subdir: Option<&str>, entry_id: &str) {
        self.filename = Box::from(format!("{entry_id}.conf").as_ref());
        for line in &mut self.entry.lines {
            for key in ["linux", "initrd", "efi"] {
                let Some(value) = strip_ble_key(line, key) else {
                    continue;
                };
                let Some((_dir, basename)) = value.rsplit_once("/") else {
                    continue;
                };

                let file = self.files.remove(value);

                let new = format!("/{entry_id}/{basename}");
                let range = substr_range(line, value).unwrap();

                let final_entry_path = if let Some(boot_subdir) = boot_subdir {
                    format!("/{boot_subdir}{new}")
                } else {
                    new.clone()
                };

                line.replace_range(range, &final_entry_path);

                if let Some(file) = file {
                    self.files.insert(new.into_boxed_str(), file);
                }
            }
        }
    }

    pub fn load(
        filename: &OsStr,
        file: &RegularFile<ObjectID>,
        root: &Directory<ObjectID>,
        repo: &Repository<ObjectID>,
    ) -> Result<Self> {
        let entry = BootLoaderEntryFile::new(from_utf8(&composefs::fs::read_file(file, repo)?)?);

        let mut files = HashMap::new();
        for key in ["linux", "initrd", "efi"] {
            for pathname in entry.get_values(key) {
                let (dir, filename) = root.split(pathname.as_ref())?;
                files.insert(Box::from(pathname), dir.get_file(filename)?.clone());
            }
        }

        Ok(Self {
            filename: Box::from(filename),
            entry,
            files,
        })
    }

    pub fn load_all(root: &Directory<ObjectID>, repo: &Repository<ObjectID>) -> Result<Vec<Self>> {
        let mut entries = vec![];

        match root.get_directory("/boot/loader/entries".as_ref()) {
            Ok(entries_dir) => {
                for (filename, inode) in entries_dir.entries() {
                    if !filename.as_bytes().ends_with(b".conf") {
                        continue;
                    }

                    let Inode::Leaf(leaf) = inode else {
                        bail!("/boot/loader/entries/{filename:?} is a directory");
                    };

                    let LeafContent::Regular(file) = &leaf.content else {
                        bail!("/boot/loader/entries/{filename:?} is not a regular file");
                    };

                    entries.push(Self::load(filename, file, root, repo)?);
                }
            }
            Err(ImageError::NotFound(..)) => {}
            Err(other) => Err(other)?,
        };

        Ok(entries)
    }
}

#[derive(Debug)]
pub struct Type2Entry<ObjectID: FsVerityHashValue> {
    // This is the basename of the UKI .efi file
    pub filename: Box<OsStr>,
    pub file: RegularFile<ObjectID>,
}

impl<ObjectID: FsVerityHashValue> Type2Entry<ObjectID> {
    pub fn rename(&mut self, name: &str) {
        self.filename = Box::from(format!("{name}.efi").as_ref());
    }

    pub fn load_all(root: &Directory<ObjectID>) -> Result<Vec<Self>> {
        let mut entries = vec![];

        match root.get_directory("/boot/EFI/Linux".as_ref()) {
            Ok(entries_dir) => {
                for (filename, inode) in entries_dir.entries() {
                    if !filename.as_bytes().ends_with(b".efi") {
                        continue;
                    }

                    let Inode::Leaf(leaf) = inode else {
                        bail!("/boot/EFI/Linux/{filename:?} is a directory");
                    };

                    let LeafContent::Regular(file) = &leaf.content else {
                        bail!("/boot/EFI/Linux/{filename:?} is not a regular file");
                    };

                    entries.push(Self {
                        filename: Box::from(filename),
                        file: file.clone(),
                    })
                }
            }
            Err(ImageError::NotFound(..)) => {}
            Err(other) => Err(other)?,
        };

        Ok(entries)
    }
}

#[derive(Debug)]
pub struct UsrLibModulesUki<ObjectID: FsVerityHashValue> {
    pub kver: Box<OsStr>,
    pub filename: Box<OsStr>,
    pub uki: RegularFile<ObjectID>,
}

impl<ObjectID: FsVerityHashValue> UsrLibModulesUki<ObjectID> {
    pub fn load_all(root: &Directory<ObjectID>) -> Result<Vec<Self>> {
        let mut entries = vec![];

        match root.get_directory("/usr/lib/modules".as_ref()) {
            Ok(modules_dir) => {
                for (kver, inode) in modules_dir.entries() {
                    let Inode::Directory(dir) = inode else {
                        continue;
                    };

                    for (filename, inode) in dir.entries() {
                        if !filename.as_bytes().ends_with(b".efi") {
                            continue;
                        }

                        let Inode::Leaf(leaf) = inode else {
                            bail!("/boot/EFI/Linux/{filename:?} is a directory");
                        };

                        let LeafContent::Regular(file) = &leaf.content else {
                            bail!("/boot/EFI/Linux/{filename:?} is not a regular file");
                        };

                        entries.push(Self {
                            kver: Box::from(kver),
                            filename: Box::from(filename),
                            uki: file.clone(),
                        })
                    }
                }
            }
            Err(ImageError::NotFound(..)) => {}
            Err(other) => Err(other)?,
        };

        Ok(entries)
    }
}

#[derive(Debug)]
pub struct UsrLibModulesVmlinuz<ObjectID: FsVerityHashValue> {
    pub kver: Box<str>,
    pub vmlinuz: RegularFile<ObjectID>,
    pub initramfs: Option<RegularFile<ObjectID>>,
    pub os_release: Option<RegularFile<ObjectID>>,
}

impl<ObjectID: FsVerityHashValue> UsrLibModulesVmlinuz<ObjectID> {
    pub fn into_type1(self, entry_id: Option<&str>) -> Type1Entry<ObjectID> {
        let id = entry_id.unwrap_or(&self.kver);

        let title = "todoOS";
        let version = "0-todo";
        let entry = BootLoaderEntryFile::new(&format!(
            r#"# File created by composefs
title {title}
version {version}
linux /{id}/vmlinuz
initrd /{id}/initramfs.img
"#
        ));

        let filename = Box::from(format!("{id}.conf").as_ref());

        Type1Entry {
            filename,
            entry,
            files: HashMap::from([
                (Box::from(format!("/{id}/vmlinuz")), self.vmlinuz),
                (
                    Box::from(format!("/{id}/initramfs.img")),
                    self.initramfs.unwrap(),
                ),
            ]),
        }
    }

    pub fn load_all(root: &Directory<ObjectID>) -> Result<Vec<Self>> {
        let mut entries = vec![];

        match root.get_directory("/usr/lib/modules".as_ref()) {
            Ok(modules_dir) => {
                for (kver, inode) in modules_dir.entries() {
                    let Inode::Directory(dir) = inode else {
                        continue;
                    };

                    if let Ok(vmlinuz) = dir.get_file("vmlinuz".as_ref()) {
                        // TODO: maybe initramfs should be mandatory: the kernel isn't useful
                        // without it
                        let initramfs = dir.get_file("initramfs.img".as_ref()).ok();
                        let os_release = root.get_file("/usr/lib/os-release".as_ref()).ok();
                        entries.push(Self {
                            kver: Box::from(std::str::from_utf8(kver.as_bytes())?),
                            vmlinuz: vmlinuz.clone(),
                            initramfs: initramfs.cloned(),
                            os_release: os_release.cloned(),
                        });
                    }
                }
            }
            Err(ImageError::NotFound(..)) => {}
            Err(other) => Err(other)?,
        };

        Ok(entries)
    }
}

#[derive(Debug)]
pub enum BootEntry<ObjectID: FsVerityHashValue> {
    Type1(Type1Entry<ObjectID>),
    Type2(Type2Entry<ObjectID>),
    UsrLibModulesUki(UsrLibModulesUki<ObjectID>),
    UsrLibModulesVmLinuz(UsrLibModulesVmlinuz<ObjectID>),
}

pub fn get_boot_resources<ObjectID: FsVerityHashValue>(
    image: &FileSystem<ObjectID>,
    repo: &Repository<ObjectID>,
) -> Result<Vec<BootEntry<ObjectID>>> {
    let mut entries = vec![];

    for e in Type1Entry::load_all(&image.root, repo)? {
        entries.push(BootEntry::Type1(e));
    }
    for e in Type2Entry::load_all(&image.root)? {
        entries.push(BootEntry::Type2(e));
    }
    for e in UsrLibModulesUki::load_all(&image.root)? {
        entries.push(BootEntry::UsrLibModulesUki(e));
    }
    for e in UsrLibModulesVmlinuz::load_all(&image.root)? {
        entries.push(BootEntry::UsrLibModulesVmLinuz(e));
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use composefs::fsverity::Sha256HashValue;
    use zerocopy::FromZeros;

    use super::*;

    fn sha256() -> Sha256HashValue {
        Sha256HashValue::new_zeroed()
    }

    fn sha256str() -> String {
        sha256().to_hex()
    }

    fn param(input: &str) -> Parameter<'_> {
        Parameter::parse(input).unwrap()
    }

    fn params<'a>(input: &'a [&'a str]) -> Vec<Parameter<'a>> {
        input.iter().map(|p| param(*p)).collect()
    }

    #[test]
    fn test_bootloader_entry_file_new() {
        let content = "title Test Entry\nversion 1.0\nlinux /vmlinuz\ninitrd /initramfs.img\noptions quiet splash\n";
        let entry = BootLoaderEntryFile::new(content);

        assert_eq!(entry.lines.len(), 5);
        assert_eq!(entry.lines[0], "title Test Entry");
        assert_eq!(entry.lines[1], "version 1.0");
        assert_eq!(entry.lines[2], "linux /vmlinuz");
        assert_eq!(entry.lines[3], "initrd /initramfs.img");
        assert_eq!(entry.lines[4], "options quiet splash");
    }

    #[test]
    fn test_bootloader_entry_file_new_empty() {
        let entry = BootLoaderEntryFile::new("");
        assert_eq!(entry.lines.len(), 0);
    }

    #[test]
    fn test_bootloader_entry_file_new_single_line() {
        let entry = BootLoaderEntryFile::new("title Test");
        assert_eq!(entry.lines.len(), 1);
        assert_eq!(entry.lines[0], "title Test");
    }

    #[test]
    fn test_bootloader_entry_file_new_trailing_newline() {
        let content = "title Test\nversion 1.0\n";
        let entry = BootLoaderEntryFile::new(content);
        assert_eq!(entry.lines.len(), 2);
        assert_eq!(entry.lines[0], "title Test");
        assert_eq!(entry.lines[1], "version 1.0");
    }

    #[test]
    fn test_get_value() {
        let content = "title Test Entry\nversion 1.0\nlinux /vmlinuz\ninitrd /initramfs.img\noptions quiet splash\n";
        let entry = BootLoaderEntryFile::new(content);

        assert_eq!(entry.get_value("title"), Some("Test Entry"));
        assert_eq!(entry.get_value("version"), Some("1.0"));
        assert_eq!(entry.get_value("linux"), Some("/vmlinuz"));
        assert_eq!(entry.get_value("initrd"), Some("/initramfs.img"));
        assert_eq!(entry.get_value("options"), Some("quiet splash"));
        assert_eq!(entry.get_value("nonexistent"), None);
    }

    #[test]
    fn test_get_value_whitespace_handling() {
        let content = "title\t\tTest Entry\nversion   1.0\nlinux\t/vmlinuz\n";
        let entry = BootLoaderEntryFile::new(content);

        assert_eq!(entry.get_value("title"), Some("Test Entry"));
        assert_eq!(entry.get_value("version"), Some("1.0"));
        assert_eq!(entry.get_value("linux"), Some("/vmlinuz"));
    }

    #[test]
    fn test_get_value_no_whitespace_after_key() {
        let content = "titleTest Entry\nversionno_space\n";
        let entry = BootLoaderEntryFile::new(content);

        assert_eq!(entry.get_value("title"), None);
        assert_eq!(entry.get_value("version"), None);
    }

    #[test]
    fn test_get_values_multiple() {
        let content = "title Test Entry\ninitrd /initramfs1.img\ninitrd /initramfs2.img\noptions quiet\noptions splash\n";
        let entry = BootLoaderEntryFile::new(content);

        let initrd_values: Vec<_> = entry.get_values("initrd").collect();
        assert_eq!(initrd_values, vec!["/initramfs1.img", "/initramfs2.img"]);

        let options_values: Vec<_> = entry.get_values("options").collect();
        assert_eq!(options_values, vec!["quiet", "splash"]);

        let title_values: Vec<_> = entry.get_values("title").collect();
        assert_eq!(title_values, vec!["Test Entry"]);

        let nonexistent_values: Vec<_> = entry.get_values("nonexistent").collect();
        assert_eq!(nonexistent_values, Vec::<&str>::new());
    }

    #[test]
    fn test_add_cmdline_new_options_line() {
        let mut entry = BootLoaderEntryFile::new("title Test Entry\nlinux /vmlinuz\n");
        entry.add_cmdline(&param("quiet"));

        assert_eq!(entry.lines.len(), 3);
        assert_eq!(entry.lines[2], "options quiet");
    }

    #[test]
    fn test_add_cmdline_append_to_existing_options() {
        let mut entry = BootLoaderEntryFile::new("title Test Entry\noptions splash\n");
        entry.add_cmdline(&param("quiet"));

        assert_eq!(entry.lines.len(), 2);
        assert_eq!(entry.lines[1], "options splash quiet");
    }

    #[test]
    fn test_add_cmdline_replace_existing_key_value() {
        let mut entry =
            BootLoaderEntryFile::new("title Test Entry\noptions quiet splash root=/dev/sda1\n");
        entry.add_cmdline(&param("root=/dev/sda2"));

        assert_eq!(entry.lines.len(), 2);
        assert_eq!(entry.lines[1], "options quiet splash root=/dev/sda2");
    }

    #[test]
    fn test_add_cmdline_replace_existing_key_only() {
        let mut entry = BootLoaderEntryFile::new("title Test Entry\noptions quiet rw splash\n");
        entry.add_cmdline(&param("rw")); // Same key, should replace itself (no-op in this case)

        assert_eq!(entry.lines.len(), 2);
        assert_eq!(entry.lines[1], "options quiet rw splash");

        // Test replacing with different key
        entry.add_cmdline(&param("ro"));
        assert_eq!(entry.lines[1], "options quiet rw splash ro");
    }

    #[test]
    fn test_add_cmdline_key_with_equals() {
        let mut entry = BootLoaderEntryFile::new("title Test Entry\noptions quiet\n");
        entry.add_cmdline(&param("composefs=abc123"));

        assert_eq!(entry.lines.len(), 2);
        assert_eq!(entry.lines[1], "options quiet composefs=abc123");
    }

    #[test]
    fn test_add_cmdline_replace_key_with_equals() {
        let mut entry =
            BootLoaderEntryFile::new("title Test Entry\noptions quiet composefs=old123\n");
        entry.add_cmdline(&param("composefs=new456"));

        assert_eq!(entry.lines.len(), 2);
        assert_eq!(entry.lines[1], "options quiet composefs=new456");
    }

    #[test]
    fn test_adjust_cmdline_with_composefs() {
        let mut entry = BootLoaderEntryFile::new("title Test Entry\nlinux /vmlinuz\n");
        entry.adjust_cmdline(Some(&sha256()), false, &params(&["quiet", "splash"]));

        assert_eq!(entry.lines.len(), 3);
        assert_eq!(
            entry.lines[2],
            format!("options composefs={} quiet splash", sha256str())
        );
    }

    #[test]
    fn test_adjust_cmdline_with_composefs_insecure() {
        let mut entry = BootLoaderEntryFile::new("title Test Entry\nlinux /vmlinuz\n");
        entry.adjust_cmdline(Some(&sha256()), true, &[]);

        assert_eq!(entry.lines.len(), 3);
        // Assuming make_cmdline_composefs adds digest=off for insecure mode
        assert!(entry.lines[2].contains(&sha256str()));
    }

    #[test]
    fn test_adjust_cmdline_no_composefs() {
        let mut entry = BootLoaderEntryFile::new("title Test Entry\nlinux /vmlinuz\n");
        entry.adjust_cmdline(
            None::<&Sha256HashValue>,
            false,
            &params(&["quiet", "splash"]),
        );

        assert_eq!(entry.lines.len(), 3);
        assert_eq!(entry.lines[2], "options quiet splash");
    }

    #[test]
    fn test_adjust_cmdline_existing_options() {
        let mut entry = BootLoaderEntryFile::new("title Test Entry\noptions root=/dev/sda1\n");
        entry.adjust_cmdline(Some(&sha256()), false, &params(&["quiet"]));

        assert_eq!(entry.lines.len(), 2);
        assert!(entry.lines[1].contains("root=/dev/sda1"));
        assert!(entry.lines[1].contains(&sha256str()));
        assert!(entry.lines[1].contains("quiet"));
    }

    #[test]
    fn test_strip_ble_key_helper() {
        assert_eq!(
            strip_ble_key("title Test Entry", "title"),
            Some("Test Entry")
        );
        assert_eq!(
            strip_ble_key("title\tTest Entry", "title"),
            Some("Test Entry")
        );
        assert_eq!(
            strip_ble_key("title  Test Entry", "title"),
            Some("Test Entry")
        );
        assert_eq!(strip_ble_key("titleTest Entry", "title"), None);
        assert_eq!(strip_ble_key("other Test Entry", "title"), None);
        assert_eq!(strip_ble_key("title", "title"), None); // No whitespace after key
    }

    #[test]
    fn test_substr_range_helper() {
        let parent = "hello world test";
        let substr = &parent[6..11]; // "world" - actual substring slice
        let range = substr_range(parent, substr).unwrap();
        assert_eq!(range, 6..11);
        assert_eq!(&parent[range], "world");

        // Test with different substring
        let other_substr = &parent[0..5]; // "hello"
        let range2 = substr_range(parent, other_substr).unwrap();
        assert_eq!(range2, 0..5);
        assert_eq!(&parent[range2], "hello");

        // Test non-substring (separate string with same content)
        let separate_string = String::from("world");
        assert_eq!(substr_range(parent, &separate_string), None);
    }
}
