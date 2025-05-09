use core::ops::Range;
use std::{
    collections::HashMap, ffi::OsStr, fs::File, io::Read, os::unix::ffi::OsStrExt, str::from_utf8,
};

use anyhow::{bail, ensure, Result};

use composefs::{
    fsverity::FsVerityHashValue,
    repository::Repository,
    tree::{Directory, FileSystem, ImageError, Inode, LeafContent, RegularFile},
};

use crate::cmdline::split_cmdline;

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
    pub fn add_cmdline(&mut self, arg: &str) {
        let key = match arg.find('=') {
            Some(pos) => &arg[..=pos], // include the '='
            None => arg,
        };

        // There are three possible paths in this function:
        //   1. options line with key= already in it (replace it)
        //   2. options line with no key= in it (append key=value)
        //   3. no options line (append the entire thing)
        for line in &mut self.lines {
            if let Some(cmdline) = strip_ble_key(line, "options") {
                let segment = split_cmdline(cmdline).find(|s| s.starts_with(key));

                if let Some(old) = segment {
                    // 1. Replace existing key
                    let range = substr_range(line, old).unwrap();
                    line.replace_range(range, arg);
                } else {
                    // 2. Append new argument
                    line.push(' ');
                    line.push_str(arg);
                }

                return;
            }
        }

        // 3. Append new "options" line with our argument
        self.lines.push(format!("options {arg}"));
    }

    /// Adjusts the kernel command-line arguments by adding a composefs= parameter (if appropriate)
    /// and adding additional arguments, as requested.
    pub fn adjust_cmdline(&mut self, composefs: Option<&str>, extra: &[&str]) {
        if let Some(id) = composefs {
            self.add_cmdline(&format!("composefs={id}"));
        }

        for item in extra {
            self.add_cmdline(item);
        }
    }
}

pub(crate) fn read_file<ObjectID: FsVerityHashValue>(
    file: &RegularFile<ObjectID>,
    repo: &Repository<ObjectID>,
) -> Result<Box<[u8]>> {
    match file {
        RegularFile::Inline(data) => Ok(data.clone()),
        RegularFile::External(id, size) => {
            let mut data = vec![];
            File::from(repo.open_object(id)?).read_to_end(&mut data)?;
            ensure!(
                *size == data.len() as u64,
                "File content doesn't have the expected length"
            );
            Ok(data.into_boxed_slice())
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
        let entry = BootLoaderEntryFile::new(from_utf8(&read_file(file, repo)?)?);

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
