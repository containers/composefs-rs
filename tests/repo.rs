use std::{fmt::Write, fs::create_dir_all, io::Read, path::PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use composefs::{oci, repository::Repository};

fn append_data(builder: &mut tar::Builder<Vec<u8>>, name: &str, size: usize) -> Result<()> {
    let mut header = tar::Header::new_ustar();
    header.set_uid(0);
    header.set_gid(0);
    header.set_mode(0o700);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(size as u64);
    Ok(builder.append_data(&mut header, name, std::io::repeat(0u8).take(size as u64))?)
}

fn example_layer() -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(vec![]);
    append_data(&mut builder, "file0", 0)?;
    append_data(&mut builder, "file4095", 4095)?;
    append_data(&mut builder, "file4096", 4096)?;
    append_data(&mut builder, "file4097", 4097)?;
    Ok(builder.into_inner()?)
}

fn test_global_tmpdir() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("CFS_TEST_TMPDIR") {
        return Ok(path.into());
    }
    // We can't use /tmp because that's usually a tmpfs (no fsverity)
    // We also can't use /var/tmp because it's an overlayfs in toolbox (no fsverity)
    // So let's try something in the user's homedir?
    let home = std::env::var("HOME").with_context(|| "$HOME must be set when in user mode")?;
    let tmp = PathBuf::from(home).join(".var/tmp");
    create_dir_all(&tmp)?;
    Ok(tmp)
}

#[test]
fn test_layer() -> Result<()> {
    let layer = example_layer()?;
    let mut context = Sha256::new();
    context.update(&layer);
    let layer_id: [u8; 32] = context.finalize().into();

    let tmpfile = tempfile::TempDir::with_prefix_in("composefs-test-", test_global_tmpdir()?)?;
    let repo = Repository::open_path(tmpfile.path().to_path_buf())?;
    let id = oci::import_layer(&repo, &layer_id, Some("name"), &mut layer.as_slice())?;

    let mut dump = String::new();
    let mut split_stream = repo.open_stream("refs/name", Some(&id))?;
    while let Some(entry) = oci::tar::get_entry(&mut split_stream)? {
        writeln!(dump, "{}", entry)?;
    }
    assert_eq!(dump, "\
/file0 0 100700 1 0 0 0 0.0 - - -
/file4095 4095 100700 1 0 0 0 0.0 53/72beb83c78537c8970c8361e3254119fafdf1763854ecd57d3f0fe2da7c719 - 5372beb83c78537c8970c8361e3254119fafdf1763854ecd57d3f0fe2da7c719
/file4096 4096 100700 1 0 0 0 0.0 ba/bc284ee4ffe7f449377fbf6692715b43aec7bc39c094a95878904d34bac97e - babc284ee4ffe7f449377fbf6692715b43aec7bc39c094a95878904d34bac97e
/file4097 4097 100700 1 0 0 0 0.0 09/3756e4ea9683329106d4a16982682ed182c14bf076463a9e7f97305cbac743 - 093756e4ea9683329106d4a16982682ed182c14bf076463a9e7f97305cbac743
");
    Ok(())
}
