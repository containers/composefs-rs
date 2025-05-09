use std::{
    fs::{create_dir_all, write},
    path::Path,
};

use anyhow::{bail, ensure, Result};

use composefs::{fsverity::FsVerityHashValue, repository::Repository};

use crate::{
    bootloader::{read_file, BootEntry, Type1Entry, Type2Entry},
    cmdline::get_cmdline_value,
    uki,
};

pub fn write_t1_simple<ObjectID: FsVerityHashValue>(
    mut t1: Type1Entry<ObjectID>,
    bootdir: &Path,
    root_id: &ObjectID,
    cmdline_extra: &[&str],
    repo: &Repository<ObjectID>,
) -> Result<()> {
    t1.entry
        .adjust_cmdline(Some(&root_id.to_hex()), cmdline_extra);

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
    let Some(composefs) = get_cmdline_value(uki::get_cmdline(&content)?, "composefs=") else {
        bail!("The UKI is missing a composefs= commandline parameter");
    };
    let expected = root_id.to_hex();
    ensure!(
        composefs == expected,
        "The UKI has the wrong composefs= parameter (is '{composefs}', should be {expected})"
    );
    write(filename, content)?;
    Ok(())
}

pub fn write_boot_simple<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    entry: BootEntry<ObjectID>,
    root_id: &ObjectID,
    bootdir: &Path,
    entry_id: Option<&str>,
    cmdline_extra: &[&str],
) -> Result<()> {
    match entry {
        BootEntry::Type1(mut t1) => {
            if let Some(name) = entry_id {
                t1.relocate(name);
            }
            write_t1_simple(t1, bootdir, root_id, cmdline_extra, repo)?;
        }
        BootEntry::Type2(mut t2) => {
            if let Some(name) = entry_id {
                t2.rename(name);
            }
            ensure!(cmdline_extra.is_empty(), "Can't add --cmdline args to UKIs");
            write_t2_simple(t2, bootdir, root_id, repo)?;
        }
        BootEntry::UsrLibModulesUki(_entry) => todo!(),
        BootEntry::UsrLibModulesVmLinuz(entry) => {
            let mut t1 = entry.into_type1(entry_id);
            if let Some(name) = entry_id {
                t1.relocate(name)?;
            }
            write_t1_simple(t1, bootdir, root_id, cmdline_extra, repo)?;
        }
    };

    Ok(())
}
