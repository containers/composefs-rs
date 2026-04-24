//! Tests for backward compatibility with old-format composefs-rs repositories.
//!
//! These tests require an old version of cfsctl to create a repo with
//! old-format splitstream headers (pre-repr(C)). Set `CFSCTL_PATH_OLD`
//! to the path of an old cfsctl binary to enable these tests.
//!
//! Build an old binary from the bootc-pinned rev:
//! ```sh
//! git worktree add /tmp/composefs-rs-old 2203e8f
//! cargo build --release --bin cfsctl -p cfsctl \
//!     --manifest-path /tmp/composefs-rs-old/Cargo.toml
//! export CFSCTL_PATH_OLD=/tmp/composefs-rs-old/target/release/cfsctl
//! ```

use anyhow::Result;
use std::path::PathBuf;
use xshell::{Shell, cmd};

use crate::{cfsctl, integration_test};

/// Returns the path to the old cfsctl binary, or None if not configured.
fn cfsctl_old() -> Option<PathBuf> {
    std::env::var_os("CFSCTL_PATH_OLD").map(PathBuf::from)
}

/// Returns true if skopeo is available on the system.
fn have_skopeo() -> bool {
    std::process::Command::new("skopeo")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn test_read_old_format_repo() -> Result<()> {
    let old_cfsctl = match cfsctl_old() {
        Some(p) => p,
        None => {
            eprintln!("CFSCTL_PATH_OLD not set, skipping old-format test");
            return Ok(());
        }
    };
    if !have_skopeo() {
        eprintln!("skopeo not found, skipping old-format test");
        return Ok(());
    }
    let cfsctl = cfsctl()?;
    let sh = Shell::new()?;

    // Create a local OCI layout from busybox using skopeo
    let oci_dir = tempfile::tempdir()?;
    let oci_path = oci_dir.path().join("busybox-oci");
    cmd!(
        sh,
        "skopeo copy docker://docker.io/library/busybox:latest oci:{oci_path}"
    )
    .run()?;

    // Create repo with old cfsctl and pull the image.
    // The old cfsctl auto-creates the repo directory structure on pull.
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    std::fs::create_dir_all(repo)?;

    let pull_output = cmd!(
        sh,
        "{old_cfsctl} --insecure --repo {repo} oci pull oci:{oci_path} busybox:latest"
    )
    .read()?;
    eprintln!("old cfsctl pull output: {pull_output}");

    // Old repo has no meta.json — --no-upgrade should refuse to operate
    let result = cmd!(sh, "{cfsctl} --no-upgrade --repo {repo} oci images")
        .ignore_status()
        .read_stderr()?;
    assert!(
        result.contains("meta.json") || result.contains("must be initialized"),
        "new cfsctl --no-upgrade should fail on repo without meta.json, got: {result}"
    );

    // Without --no-upgrade (default), cfsctl should auto-upgrade and work
    let images_output = cmd!(sh, "{cfsctl} --repo {repo} oci images").read()?;

    // Verify meta.json was written by auto-upgrade
    assert!(
        repo.join("meta.json").exists(),
        "meta.json should have been written by auto-upgrade"
    );
    assert!(
        images_output.contains("busybox"),
        "should list busybox image after init, got: {images_output}"
    );

    // Dump filesystem — this reads old-format layer splitstreams
    let dump_output = cmd!(sh, "{cfsctl} --repo {repo} oci dump busybox:latest").read()?;
    assert!(
        dump_output.contains("/bin/sh"),
        "busybox dump should contain /bin/sh, got first 200 chars: {}",
        &dump_output[..dump_output.len().min(200)]
    );

    // GC should work without errors
    let gc_output = cmd!(sh, "{cfsctl} --insecure --repo {repo} gc").read()?;
    assert!(
        gc_output.contains("Objects: 0 removed"),
        "gc should find nothing to remove (all objects are referenced), got: {gc_output}"
    );

    // oci fsck should pass (verifies splitstream integrity)
    let fsck_output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci fsck --json").read()?;
    let fsck: serde_json::Value = serde_json::from_str(&fsck_output)?;
    assert_eq!(
        fsck["ok"], true,
        "oci fsck should pass on old-format repo, got: {fsck_output}"
    );

    Ok(())
}
integration_test!(test_read_old_format_repo);
