use std::{
    ffi::OsString,
    fs::{create_dir_all, File},
    path::PathBuf,
};

use tempfile::{tempfile_in, TempDir};

use once_cell::sync::Lazy;

static TMPDIR: Lazy<OsString> = Lazy::new(|| {
    if let Some(path) = std::env::var_os("CFS_TEST_TMPDIR") {
        eprintln!("temporary directory from $CFS_TEST_TMPDIR: {path:?}");
        path
    } else {
        // We can't use /tmp because that's usually a tmpfs (no fsverity)
        // We also can't use /var/tmp because it's an overlayfs in toolbox (no fsverity)
        // So let's try something in the user's homedir?
        let home = std::env::var("HOME").expect("$HOME must be set when running tests");
        let tmp = PathBuf::from(home).join(".var/tmp");
        create_dir_all(&tmp).expect("can't create ~/.var/tmp");
        eprintln!("temporary directory from ~/.var/tmp: {tmp:?}");
        tmp.into()
    }
});

pub fn tempdir() -> TempDir {
    TempDir::with_prefix_in("composefs-test-", TMPDIR.as_os_str()).unwrap()
}
