//! CLI integration tests that run on the host without root.
//!
//! Each test invokes `cfsctl --insecure` as a subprocess against a fresh
//! temp-dir repository. No network access, no fs-verity, no special
//! privileges required — these are the fast "does the CLI basically work"
//! smoke tests.

use anyhow::Result;
use rustix::path::Arg;
use xshell::{cmd, Shell};

use crate::{cfsctl, create_oci_layout, create_test_rootfs, integration_test};

// Pinned composefs image ID for the deterministic OCI layout built by
// create_oci_layout() (layer with usr/, usr/bin/, etc/ dirs + usr/bin/hello.txt,
// mtime=1234567890).
const OCI_LAYOUT_COMPOSEFS_ID: &str =
    "33ce512df33a62c124409f846f97f35acc12e6a51c1af6040a3d2a209e2dcec6d388c34f2dc2dfc7e0\
     a3e1f5eb6e0b4d5669d50f3d8b2349b4829446d8a5ac15";

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

fn test_oci_images_empty_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci images").read()?;
    assert!(
        output.contains("No images found"),
        "expected 'No images found', got: {output}"
    );
    Ok(())
}
integration_test!(test_oci_images_empty_repo);

fn test_oci_images_json_empty_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci images --json").read()?;
    // Empty JSON array
    let parsed: serde_json::Value = serde_json::from_str(&output)?;
    assert!(
        parsed.as_array().map(|a| a.is_empty()).unwrap_or(false),
        "expected empty JSON array, got: {output}"
    );
    Ok(())
}
integration_test!(test_oci_images_json_empty_repo);

fn test_oci_pull_and_inspect() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    // Pull from OCI layout
    let pull_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image"
    )
    .read()?;
    assert!(
        pull_output.contains("manifest sha256:"),
        "expected manifest digest in output, got: {pull_output}"
    );
    assert!(
        pull_output.contains("tagged") && pull_output.contains("test-image"),
        "expected tagged confirmation, got: {pull_output}"
    );

    // List images
    let list_output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci images").read()?;
    assert!(
        list_output.contains("test-image"),
        "expected test-image in list, got: {list_output}"
    );

    // List images as JSON
    let json_output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci images --json").read()?;
    let images: serde_json::Value = serde_json::from_str(&json_output)?;
    let arr = images.as_array().expect("expected array");
    assert_eq!(arr.len(), 1, "expected 1 image");
    assert_eq!(arr[0]["name"], "test-image");
    assert_eq!(arr[0]["architecture"], "amd64");

    // Inspect the image
    let inspect_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci inspect test-image"
    )
    .read()?;
    let inspect: serde_json::Value = serde_json::from_str(&inspect_output)?;
    assert!(
        inspect.get("manifest").is_some(),
        "expected manifest in inspect output"
    );
    assert!(
        inspect.get("config").is_some(),
        "expected config in inspect output"
    );
    assert!(
        inspect.get("referrers").is_some(),
        "expected referrers in inspect output"
    );

    // Inspect --manifest
    let manifest_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci inspect test-image --manifest"
    )
    .read()?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest_output)?;
    assert_eq!(manifest["schemaVersion"], 2);
    assert!(manifest.get("config").is_some());
    assert!(manifest.get("layers").is_some());

    // Inspect --config
    let config_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci inspect test-image --config"
    )
    .read()?;
    let config: serde_json::Value = serde_json::from_str(&config_output)?;
    assert_eq!(config["architecture"], "amd64");
    assert_eq!(config["os"], "linux");

    // Verify composefs image digest stability.
    let config_digest = pull_output
        .lines()
        .find_map(|l| l.strip_prefix("config").map(|s| s.trim().to_string()))
        .expect("config digest in pull output");
    let image_id = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci compute-id {config_digest}"
    )
    .read()?;
    assert_eq!(
        image_id.trim(),
        OCI_LAYOUT_COMPOSEFS_ID,
        "OCI layout composefs image ID changed — the EROFS writer produced \
         different output for the same deterministic OCI image"
    );

    Ok(())
}
integration_test!(test_oci_pull_and_inspect);

fn test_oci_layer_inspect() -> Result<()> {
    use composefs_oci::composefs::dumpfile_parse::{Entry, Item};
    use std::io::Read;
    use std::path::Path;

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    // Pull from OCI layout
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image"
    )
    .read()?;

    // Get the layer diff_id from the config
    let config_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci inspect test-image --config"
    )
    .read()?;
    let config: serde_json::Value = serde_json::from_str(&config_output)?;
    let diff_ids = config["rootfs"]["diff_ids"]
        .as_array()
        .expect("expected diff_ids array");
    assert_eq!(diff_ids.len(), 1, "expected 1 layer");
    let layer_id = diff_ids[0].as_str().expect("expected string");

    // Test --json output
    let json_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci layer {layer_id} --json"
    )
    .read()?;
    let info: serde_json::Value = serde_json::from_str(&json_output)?;
    assert_eq!(info["diffId"], layer_id);
    assert!(info["verity"].as_str().is_some(), "expected verity hash");
    assert!(info["size"].as_u64().unwrap() > 0, "expected non-zero size");
    assert_eq!(
        info["entryCount"].as_u64().unwrap(),
        4,
        "expected exactly 4 entries (usr/ + usr/bin/ + etc/ + usr/bin/hello.txt)"
    );
    // Check splitstream metadata
    let splitstream = info
        .get("splitstream")
        .expect("expected splitstream metadata");
    assert!(
        splitstream["externalObjects"].as_u64().is_some(),
        "expected externalObjects"
    );
    assert!(
        splitstream["externalSize"].as_u64().is_some(),
        "expected externalSize"
    );
    assert!(
        splitstream["inlineSize"].as_u64().is_some(),
        "expected inlineSize"
    );

    // Test --dumpfile output - parse each line with the dumpfile parser
    let dumpfile_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci layer {layer_id} --dumpfile"
    )
    .read()?;

    let mut found_hello_txt = false;
    for line in dumpfile_output.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let entry = Entry::parse(line)
            .unwrap_or_else(|e| panic!("failed to parse dumpfile line '{line}': {e}"));

        if entry.path.as_ref() == Path::new("/usr/bin/hello.txt") {
            found_hello_txt = true;
            // Verify it's a regular file with inline content
            match &entry.item {
                Item::RegularInline { content, .. } => {
                    assert_eq!(
                        content.as_ref(),
                        b"hello from test layer\n",
                        "hello.txt content mismatch"
                    );
                }
                other => panic!("expected RegularInline for hello.txt, got {:?}", other),
            }
            assert_eq!(entry.uid, 0, "expected uid 0");
            assert_eq!(entry.gid, 0, "expected gid 0");
            // Mode 0o644 + regular file bit (0o100000) = 0o100644 = 33188
            assert_eq!(entry.mode, 0o100644, "expected mode 0o100644");
        }
    }
    assert!(
        found_hello_txt,
        "expected to find /usr/bin/hello.txt in dumpfile"
    );

    // Test raw tar output - parse as actual tar and verify contents
    let tar_output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci layer {layer_id}").output()?;
    let mut archive = tar::Archive::new(tar_output.stdout.as_slice());
    let mut found_in_tar = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        if path.as_ref() == Path::new("usr/bin/hello.txt") {
            found_in_tar = true;
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            assert_eq!(content, "hello from test layer\n", "tar content mismatch");
        }
    }
    assert!(
        found_in_tar,
        "expected to find usr/bin/hello.txt in tar output"
    );

    Ok(())
}
integration_test!(test_oci_layer_inspect);

fn test_dump_files() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;

    // should be of the form /usr/bin/hello <path>
    let output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} dump-files refs/my-image /usr/bin/hello --backing-path-only"
    )
    .read()?;

    let path = output.split_whitespace().nth(1).unwrap();

    assert!(
        path != "inline",
        "usr/bin/hello should've been large enough to be stored in objects directory"
    );

    let path = path.strip_prefix("/").unwrap_or(path);

    let full_path = repo.join("objects").join(path);

    assert!(full_path.exists());

    let file_hash = cmd!(sh, "sha512sum")
        .arg(rootfs.join("usr/bin/hello").as_str()?)
        .read()?;

    let file_hash = file_hash.split_whitespace().next().unwrap().trim();

    let obj_file_hash = cmd!(sh, "sha512sum").arg(full_path.as_str()?).read()?;
    let obj_file_hash = obj_file_hash.split_whitespace().next().unwrap().trim();

    assert_eq!(file_hash, obj_file_hash);

    let output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} dump-files refs/my-image /usr/lib/readme.txt --backing-path-only"
    )
    .read()?;

    let path = output.split_whitespace().nth(1).unwrap();

    assert!(
        path == "inline",
        "usr/lib/readme.txt should've been stored inline"
    );

    Ok(())
}
integration_test!(test_dump_files);

fn test_init_creates_metadata() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    // Init with default algorithm (--repo before subcommand)
    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} init").read()?;
    assert!(
        output.contains("Initialized"),
        "expected initialization message, got: {output}"
    );
    assert!(
        output.contains("fsverity-sha512-12"),
        "expected algorithm in output, got: {output}"
    );

    // Check meta.json exists and is valid
    let meta_path = repo.join("meta.json");
    assert!(meta_path.exists(), "meta.json should exist after init");

    let meta_content = std::fs::read_to_string(&meta_path)?;
    let meta: serde_json::Value = serde_json::from_str(&meta_content)?;
    assert_eq!(meta["version"], 1);
    assert_eq!(meta["algorithm"], "fsverity-sha512-12");
    assert!(
        meta.get("features").is_some(),
        "features key should always be present"
    );

    Ok(())
}
integration_test!(test_init_creates_metadata);

fn test_init_sha256() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    let output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} init --algorithm fsverity-sha256-12"
    )
    .read()?;
    assert!(
        output.contains("fsverity-sha256-12"),
        "expected sha256 algorithm, got: {output}"
    );

    // Verify operations work with auto-detected hash
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;
    let image_id = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs}"
    )
    .read()?;
    assert!(
        !image_id.trim().is_empty(),
        "should produce image ID with auto-detected sha256"
    );

    Ok(())
}
integration_test!(test_init_sha256);

fn test_init_idempotent() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    cmd!(sh, "{cfsctl} --insecure --repo {repo} init").read()?;

    // Second init with same algorithm should succeed (idempotent)
    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} init").read()?;
    assert!(
        output.contains("already initialized"),
        "expected idempotent message, got: {output}"
    );

    Ok(())
}
integration_test!(test_init_idempotent);

fn test_init_conflict() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    cmd!(sh, "{cfsctl} --insecure --repo {repo} init").read()?;

    // Re-init with different algorithm should fail
    let result = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} init --algorithm fsverity-sha256-12"
    )
    .read();
    assert!(
        result.is_err(),
        "re-init with different algorithm should fail"
    );

    Ok(())
}
integration_test!(test_init_conflict);

fn test_hash_mismatch_errors() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    // Init as sha512 repo
    cmd!(sh, "{cfsctl} --insecure --repo {repo} init").read()?;

    // Explicitly passing --hash sha256 on a sha512 repo should error
    let result = cmd!(sh, "{cfsctl} --insecure --hash sha256 --repo {repo} gc").read();
    assert!(
        result.is_err(),
        "should error when --hash sha256 used on sha512 repo"
    );

    Ok(())
}
integration_test!(test_hash_mismatch_errors);

fn test_hash_match_ok() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    // Init as sha512 repo
    cmd!(sh, "{cfsctl} --insecure --repo {repo} init").read()?;

    // Explicitly passing --hash sha512 on a sha512 repo should work
    let output = cmd!(sh, "{cfsctl} --insecure --hash sha512 --repo {repo} gc").read()?;
    assert!(
        output.contains("Objects: 0 removed"),
        "should succeed with matching --hash, got: {output}"
    );

    Ok(())
}
integration_test!(test_hash_match_ok);

fn test_no_metadata_backcompat() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    // Use repo without init (no meta.json) - should work with default sha512
    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} gc").read()?;
    assert!(
        output.contains("Objects: 0 removed"),
        "should work without meta.json (backcompat), got: {output}"
    );

    // Should also work with explicit --hash sha256 (no metadata to conflict)
    let output = cmd!(sh, "{cfsctl} --insecure --hash sha256 --repo {repo} gc").read()?;
    assert!(
        output.contains("Objects: 0 removed"),
        "should work with --hash sha256 and no metadata, got: {output}"
    );

    Ok(())
}
integration_test!(test_no_metadata_backcompat);

fn test_init_creates_directory() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let parent = tempfile::tempdir()?;
    let repo = parent.path().join("new-repo");

    // Init with positional path argument
    let output = cmd!(sh, "{cfsctl} --insecure init {repo}").read()?;
    assert!(
        output.contains("Initialized"),
        "expected initialization message, got: {output}"
    );
    assert!(repo.exists(), "repo directory should be created");
    assert!(
        repo.join("meta.json").exists(),
        "meta.json should exist in created dir"
    );

    Ok(())
}
integration_test!(test_init_creates_directory);

fn test_auto_detect_hash_for_operations() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;

    // Create a sha256 repo
    let repo_dir = tempfile::tempdir()?;
    let repo256 = repo_dir.path();
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo256} init --algorithm fsverity-sha256-12"
    )
    .read()?;

    // Create a sha512 repo
    let repo_dir2 = tempfile::tempdir()?;
    let repo512 = repo_dir2.path();
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo512} init --algorithm fsverity-sha512-12"
    )
    .read()?;

    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    // Create image in sha256 repo (no --hash flag needed)
    let id256 = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo256} create-image {rootfs}"
    )
    .read()?;

    // Create image in sha512 repo (no --hash flag needed)
    let id512 = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo512} create-image {rootfs}"
    )
    .read()?;

    // The image IDs should differ because different hash algorithms produce
    // different fs-verity digests
    assert_ne!(
        id256.trim(),
        id512.trim(),
        "sha256 and sha512 should produce different image IDs"
    );

    Ok(())
}
integration_test!(test_auto_detect_hash_for_operations);

fn test_fsck_empty_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} fsck").read()?;
    assert!(
        output.contains("status: ok"),
        "expected 'status: ok', got: {output}"
    );
    Ok(())
}
integration_test!(test_fsck_empty_repo);

fn test_fsck_healthy_repo() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;

    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} fsck").read()?;
    assert!(
        output.contains("status: ok"),
        "expected healthy fsck, got: {output}"
    );
    // Should have checked some objects
    assert!(
        output.contains("objects:"),
        "expected objects line, got: {output}"
    );
    Ok(())
}
integration_test!(test_fsck_healthy_repo);

fn test_fsck_detects_corrupted_object() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    // Create an image which stores objects
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;

    // Find an object file and corrupt it
    let objects_dir = repo.join("objects");
    let mut corrupted = false;
    'outer: for entry in std::fs::read_dir(&objects_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        for obj_entry in std::fs::read_dir(entry.path())? {
            let obj_entry = obj_entry?;
            if obj_entry.file_type()?.is_file() {
                let path = obj_entry.path();
                // Delete and recreate with wrong content
                std::fs::remove_file(&path)?;
                std::fs::write(&path, b"CORRUPTED DATA")?;
                corrupted = true;
                break 'outer;
            }
        }
    }
    assert!(corrupted, "should have found an object to corrupt");

    // fsck should fail
    let result = cmd!(sh, "{cfsctl} --insecure --repo {repo} fsck")
        .ignore_status()
        .output()?;
    let output = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);

    assert!(
        !result.status.success(),
        "fsck should have exited non-zero after corruption, stdout: {output}, stderr: {stderr}"
    );
    Ok(())
}
integration_test!(test_fsck_detects_corrupted_object);

fn test_oci_fsck_healthy() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image"
    )
    .read()?;

    // OCI fsck should pass
    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci fsck").read()?;
    assert!(
        output.contains("status: ok"),
        "expected healthy oci fsck, got: {output}"
    );
    assert!(
        output.contains("oci images: 1/1 ok"),
        "expected 1 image checked, got: {output}"
    );
    Ok(())
}
integration_test!(test_oci_fsck_healthy);

fn test_oci_fsck_detects_corrupted_manifest() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    // Pull an OCI image
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image"
    )
    .read()?;

    // Find the manifest stream symlink and corrupt its backing object
    let streams_dir = repo.join("streams");
    let mut corrupted = false;
    for entry in std::fs::read_dir(&streams_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("oci-manifest-") {
            // Read the symlink target to find the object
            let target = std::fs::read_link(entry.path())?;
            let obj_path = streams_dir.join(&target);
            if obj_path.exists() {
                std::fs::remove_file(&obj_path)?;
                std::fs::write(&obj_path, b"CORRUPTED MANIFEST DATA")?;
                corrupted = true;
                break;
            }
        }
    }
    assert!(corrupted, "should have found a manifest object to corrupt");

    // OCI fsck should fail
    let result = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci fsck")
        .ignore_status()
        .output()?;
    let output = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);

    assert!(
        !result.status.success(),
        "oci fsck should have exited non-zero after corruption, stdout: {output}, stderr: {stderr}"
    );
    Ok(())
}
integration_test!(test_oci_fsck_detects_corrupted_manifest);

fn test_oci_fsck_single_image() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image"
    )
    .read()?;

    // Check a specific image by name
    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci fsck test-image").read()?;
    assert!(
        output.contains("status: ok"),
        "expected healthy oci fsck for specific image, got: {output}"
    );
    assert!(
        output.contains("oci images: 1/1 ok"),
        "expected 1 image checked, got: {output}"
    );

    // Check a nonexistent image
    let result = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci fsck nonexistent-image"
    )
    .ignore_status()
    .output()?;
    assert!(
        !result.status.success(),
        "oci fsck should fail for nonexistent image"
    );
    Ok(())
}
integration_test!(test_oci_fsck_single_image);

fn test_fsck_json_healthy() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;

    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} fsck --json").read()?;
    let v: serde_json::Value = serde_json::from_str(&output)?;
    assert_eq!(v["ok"], true, "expected ok=true, got: {output}");
    assert!(
        v["objectsChecked"].as_u64().unwrap() > 0,
        "expected objectsChecked > 0"
    );
    assert_eq!(v["objectsCorrupted"], 0);
    assert!(v["errors"].as_array().unwrap().is_empty());
    Ok(())
}
integration_test!(test_fsck_json_healthy);

fn test_fsck_json_corrupted_exits_zero() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;

    // Corrupt an object
    let objects_dir = repo.join("objects");
    let mut corrupted = false;
    'outer: for entry in std::fs::read_dir(&objects_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        for obj_entry in std::fs::read_dir(entry.path())? {
            let obj_entry = obj_entry?;
            if obj_entry.file_type()?.is_file() {
                let path = obj_entry.path();
                std::fs::remove_file(&path)?;
                std::fs::write(&path, b"CORRUPTED DATA")?;
                corrupted = true;
                break 'outer;
            }
        }
    }
    assert!(corrupted, "should have found an object to corrupt");

    // --json should exit 0 even with corruption
    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} fsck --json").read()?;
    let v: serde_json::Value = serde_json::from_str(&output)?;
    assert_eq!(v["ok"], false, "expected ok=false, got: {output}");
    assert!(
        v["objectsCorrupted"].as_u64().unwrap() > 0,
        "expected corrupted > 0"
    );
    assert!(
        !v["errors"].as_array().unwrap().is_empty(),
        "expected errors"
    );
    Ok(())
}
integration_test!(test_fsck_json_corrupted_exits_zero);

fn test_oci_fsck_json() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image"
    )
    .read()?;

    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci fsck --json").read()?;
    let v: serde_json::Value = serde_json::from_str(&output)?;
    assert_eq!(v["ok"], true, "expected ok=true, got: {output}");
    assert_eq!(v["imagesChecked"], 1);
    assert_eq!(v["imagesCorrupted"], 0);
    Ok(())
}
integration_test!(test_oci_fsck_json);

fn test_oci_fsck_json_with_corruption() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image"
    )
    .read()?;

    // Corrupt an object in the repository
    let objects_dir = repo.join("objects");
    let mut corrupted = false;
    'outer: for entry in std::fs::read_dir(&objects_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        for obj_entry in std::fs::read_dir(entry.path())? {
            let obj_entry = obj_entry?;
            if obj_entry.file_type()?.is_file() {
                let path = obj_entry.path();
                std::fs::remove_file(&path)?;
                std::fs::write(&path, b"CORRUPTED OCI DATA")?;
                corrupted = true;
                break 'outer;
            }
        }
    }
    assert!(corrupted, "should have found an object to corrupt");

    // --json should exit 0 even with corruption, reporting it in the output
    let output = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci fsck --json").read()?;
    let v: serde_json::Value = serde_json::from_str(&output)?;
    assert_eq!(v["ok"], false, "expected ok=false, got: {output}");
    let has_repo_errors = v["repoResult"]["errors"]
        .as_array()
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    let has_oci_errors = v["errors"]
        .as_array()
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    let has_repo_corruption = v["repoResult"]["objectsCorrupted"].as_u64().unwrap_or(0) > 0;
    assert!(
        has_repo_errors || has_oci_errors || has_repo_corruption,
        "expected some errors in JSON output, got: {output}"
    );
    Ok(())
}
integration_test!(test_oci_fsck_json_with_corruption);

fn test_fsck_detects_broken_image_ref() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} create-image {rootfs} my-image"
    )
    .read()?;

    let refs_dir = repo.join("images/refs");
    let mut broken = false;
    if refs_dir.exists() {
        for entry in std::fs::read_dir(&refs_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_symlink() {
                let target = std::fs::read_link(entry.path())?;
                let resolved = refs_dir.join(&target);
                if resolved.symlink_metadata().is_ok() {
                    std::fs::remove_file(&resolved)?;
                    broken = true;
                    break;
                }
            }
        }
    }
    assert!(broken, "should have found an image ref to break");

    let result = cmd!(sh, "{cfsctl} --insecure --repo {repo} fsck")
        .ignore_status()
        .output()?;
    let output = String::from_utf8_lossy(&result.stdout);

    assert!(
        !result.status.success(),
        "fsck should fail with broken image ref, stdout: {output}"
    );
    Ok(())
}
integration_test!(test_fsck_detects_broken_image_ref);

fn test_oci_push_to_layout() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    // Pull from OCI layout into repo
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image"
    )
    .read()?;

    // Push to a new OCI layout directory
    let output_dir = tempfile::tempdir()?;
    let output_path = output_dir.path().join("exported");
    let push_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci push test-image oci:{output_path}"
    )
    .read()?;
    assert!(
        push_output.contains("Exported"),
        "expected export confirmation, got: {push_output}"
    );

    assert!(
        output_path.join("oci-layout").exists(),
        "expected oci-layout file"
    );
    assert!(
        output_path.join("index.json").exists(),
        "expected index.json"
    );
    assert!(
        output_path.join("blobs/sha256").exists(),
        "expected blobs/sha256 directory"
    );

    let index_json = std::fs::read_to_string(output_path.join("index.json"))?;
    let index: serde_json::Value = serde_json::from_str(&index_json)?;
    let manifests = index["manifests"]
        .as_array()
        .expect("expected manifests array");
    assert_eq!(manifests.len(), 1, "expected 1 manifest entry");

    let annotations = manifests[0]["annotations"]
        .as_object()
        .expect("expected annotations");
    assert_eq!(
        annotations["org.opencontainers.image.ref.name"],
        "test-image"
    );

    let manifest_digest = manifests[0]["digest"]
        .as_str()
        .expect("expected digest string");
    let manifest_hash = manifest_digest
        .strip_prefix("sha256:")
        .expect("expected sha256 prefix");
    let manifest_blob =
        std::fs::read_to_string(output_path.join("blobs/sha256").join(manifest_hash))?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest_blob)?;
    let layers = manifest["layers"]
        .as_array()
        .expect("expected layers array");
    assert!(!layers.is_empty(), "expected at least one layer");

    assert_eq!(
        layers[0]["mediaType"], "application/vnd.oci.image.layer.v1.tar",
        "expected uncompressed tar media type"
    );

    for layer in layers {
        let layer_digest = layer["digest"].as_str().expect("expected layer digest");
        let layer_hash = layer_digest
            .strip_prefix("sha256:")
            .expect("expected sha256 prefix");
        let layer_blob_path = output_path.join("blobs/sha256").join(layer_hash);
        assert!(layer_blob_path.exists(), "layer blob should exist");
        let metadata = std::fs::metadata(&layer_blob_path)?;
        assert!(metadata.len() > 0, "layer blob should be non-empty");
    }

    let config_digest = manifest["config"]["digest"]
        .as_str()
        .expect("expected config digest");
    let config_hash = config_digest
        .strip_prefix("sha256:")
        .expect("expected sha256 prefix");
    assert!(
        output_path.join("blobs/sha256").join(config_hash).exists(),
        "config blob should exist"
    );

    Ok(())
}
integration_test!(test_oci_push_to_layout);

fn test_oci_push_pull_roundtrip() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    // Pull from OCI layout into repo
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image"
    )
    .read()?;

    // Push to a new OCI layout directory
    let output_dir = tempfile::tempdir()?;
    let output_path = output_dir.path().join("exported");
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci push test-image oci:{output_path}"
    )
    .read()?;

    // Pull from the exported layout into a fresh repo
    let repo2_dir = tempfile::tempdir()?;
    let repo2 = repo2_dir.path();
    let pull_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo2} oci pull oci:{output_path} roundtrip-image"
    )
    .read()?;
    assert!(
        pull_output.contains("manifest sha256:"),
        "expected manifest digest in roundtrip pull, got: {pull_output}"
    );

    let list_output = cmd!(sh, "{cfsctl} --insecure --repo {repo2} oci images --json").read()?;
    let images: serde_json::Value = serde_json::from_str(&list_output)?;
    let arr = images.as_array().expect("expected array");
    assert_eq!(arr.len(), 1, "expected 1 image in new repo");
    assert_eq!(arr[0]["name"], "roundtrip-image");
    assert_eq!(arr[0]["architecture"], "amd64");

    let config_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo2} oci inspect roundtrip-image --config"
    )
    .read()?;
    let config: serde_json::Value = serde_json::from_str(&config_output)?;
    assert_eq!(config["architecture"], "amd64");
    assert_eq!(config["os"], "linux");

    let diff_ids = config["rootfs"]["diff_ids"]
        .as_array()
        .expect("expected diff_ids");
    assert_eq!(diff_ids.len(), 1, "expected 1 layer after roundtrip");

    Ok(())
}
integration_test!(test_oci_push_pull_roundtrip);
