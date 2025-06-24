use std::{
    fs::{create_dir_all, write},
    path::Path,
};

use anyhow::{ensure, Result};

use composefs::{fsverity::FsVerityHashValue, repository::Repository};

use crate::{
    bootloader::{read_file, BootEntry, Type1Entry, Type2Entry},
    cmdline::get_cmdline_composefs,
    uki,
};

pub fn write_t1_simple<ObjectID: FsVerityHashValue>(
    mut t1: Type1Entry<ObjectID>,
    bootdir: &Path,
    boot_subdir: Option<&str>,
    root_id: &ObjectID,
    insecure: bool,
    cmdline_extra: &[&str],
    repo: &Repository<ObjectID>,
) -> Result<()> {
    let bootdir = if let Some(subdir) = boot_subdir {
        let subdir_path = Path::new(subdir);
        bootdir.join(subdir_path.strip_prefix("/").unwrap_or(subdir_path))
    } else {
        bootdir.to_path_buf()
    };

    t1.entry
        .adjust_cmdline(Some(&root_id.to_hex()), insecure, cmdline_extra);

    // Write the content before we write the loader entry
    for (filename, file) in &t1.files {
        let pathname = Path::new(filename.as_ref());
        let file_path = bootdir.join(pathname.strip_prefix(Path::new("/"))?);
        // SAFETY: what safety? :)
        create_dir_all(file_path.parent().unwrap())?;
        write(file_path, read_file(file, repo)?)?;
    }

    // And now the loader entry itself
    let loader_entries = bootdir.join("loader/entries");
    create_dir_all(&loader_entries)?;
    let entry = loader_entries.join(t1.filename.as_ref());
    let entry_content = t1.entry.lines.join("\n") + "\n";
    write(entry, entry_content)?;
    Ok(())
}

pub fn write_t2_simple<ObjectID: FsVerityHashValue>(
    t2: Type2Entry<ObjectID>,
    bootdir: &Path,
    root_id: &ObjectID,
    repo: &Repository<ObjectID>,
) -> Result<()> {
    let efi_linux = bootdir.join("EFI/Linux");
    create_dir_all(&efi_linux)?;
    let filename = efi_linux.join(t2.filename.as_ref());
    let content = read_file(&t2.file, repo)?;
    let (composefs, _) = get_cmdline_composefs::<ObjectID>(uki::get_cmdline(&content)?)?;

    ensure!(
        &composefs == root_id,
        "The UKI has the wrong composefs= parameter (is '{composefs:?}', should be {root_id:?})"
    );
    write(filename, content)?;
    Ok(())
}

/// Writes boot entry to the boot partition
///
/// # Arguments
///
/// * repo           - The composefs repository
/// * entry          - Boot entry variant to be written
/// * root_id        - The content hash of the generated EROFS image id
/// * boot_partition - Path to the boot partition/directory
/// * boot_subdir    - If `Some(path)`, the path is prepended to `initrd` and `linux` keys in the BLS entry
///
/// For example, if `boot_partition = "/boot"` and `boot_subdir = Some("1")` ,
/// the BLS entry will contain
///
/// ```text
/// linux /boot/1/<entry_id>/linux
/// initrd /boot/1/<entry_id>/initrd
/// ```
///
/// If `boot_partition = "/boot"` and `boot_subdir = None` , the BLS entry will contain
///
/// ```text
/// linux /<entry_id>/linux
/// initrd /<entry_id>/initrd
/// ```
///
/// * entry_id       - In case of a BLS entry, the name of file to be generated in `loader/entries`
/// * cmdline_extra  - Extra kernel command line arguments
///
#[allow(clippy::too_many_arguments)]
pub fn write_boot_simple<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    entry: BootEntry<ObjectID>,
    root_id: &ObjectID,
    insecure: bool,
    boot_partition: &Path,
    boot_subdir: Option<&str>,
    entry_id: Option<&str>,
    cmdline_extra: &[&str],
) -> Result<()> {
    match entry {
        BootEntry::Type1(mut t1) => {
            if let Some(name) = entry_id {
                t1.relocate(boot_subdir, name);
            }
            write_t1_simple(
                t1,
                boot_partition,
                boot_subdir,
                root_id,
                insecure,
                cmdline_extra,
                repo,
            )?;
        }
        BootEntry::Type2(mut t2) => {
            if let Some(name) = entry_id {
                t2.rename(name);
            }
            ensure!(cmdline_extra.is_empty(), "Can't add --cmdline args to UKIs");
            write_t2_simple(t2, boot_partition, root_id, repo)?;
        }
        BootEntry::UsrLibModulesUki(_entry) => todo!(),
        BootEntry::UsrLibModulesVmLinuz(entry) => {
            let mut t1 = entry.into_type1(entry_id);
            if let Some(name) = entry_id {
                t1.relocate(boot_subdir, name);
            }
            write_t1_simple(
                t1,
                boot_partition,
                boot_subdir,
                root_id,
                insecure,
                cmdline_extra,
                repo,
            )?;
        }
    };

    Ok(())
}
