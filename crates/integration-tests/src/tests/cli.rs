//! CLI integration tests that run on the host without root.
//!
//! Each test invokes `cfsctl --insecure` as a subprocess against a fresh
//! temp-dir repository. No network access, no fs-verity, no special
//! privileges required — these are the fast "does the CLI basically work"
//! smoke tests.

use anyhow::Result;
use xshell::{cmd, Shell};

use crate::{cfsctl, create_test_rootfs, integration_test};

fn test_gc_empty_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} gc").read()?;
    assert!(
        output.contains("Objects: 0 removed"),
        "expected zero objects removed, got: {output}"
    );
    Ok(())
}
integration_test!(test_gc_empty_repo);

fn test_create_image_from_path() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    let output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs}"
    )
    .read()?;
    assert!(
        !output.trim().is_empty(),
        "expected image ID output, got nothing"
    );
    Ok(())
}
integration_test!(test_create_image_from_path);

fn test_create_image_idempotent() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    let id1 = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs}"
    )
    .read()?;
    let id2 = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs}"
    )
    .read()?;
    assert_eq!(
        id1.trim(),
        id2.trim(),
        "creating the same image twice should produce the same ID"
    );
    Ok(())
}
integration_test!(test_create_image_idempotent);

fn test_create_and_list_objects() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    // Create with a ref name so we can look it up easily
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;

    let objects = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} image-objects refs/my-image"
    )
    .read()?;
    assert!(
        !objects.trim().is_empty(),
        "expected at least one object, got nothing"
    );
    Ok(())
}
integration_test!(test_create_and_list_objects);

fn test_gc_after_create() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs}"
    )
    .read()?;

    // GC with no roots — everything should be collected
    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} gc").read()?;
    assert!(
        output.contains("removed"),
        "expected GC output mentioning removed objects, got: {output}"
    );
    Ok(())
}
integration_test!(test_gc_after_create);

fn test_gc_dry_run() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    // Create an image with a ref name so we can reference it later
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;

    // Dry-run GC
    let gc_output = cmd!(sh, "{cfsctl} --insecure --repo {repo} gc --dry-run").read()?;
    assert!(
        gc_output.contains("Dry run"),
        "expected dry run header, got: {gc_output}"
    );

    // Image should still be accessible after dry run
    let objects = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} image-objects refs/my-image"
    )
    .read()?;
    assert!(
        !objects.trim().is_empty(),
        "image should still exist after dry-run GC"
    );
    Ok(())
}
integration_test!(test_gc_dry_run);
