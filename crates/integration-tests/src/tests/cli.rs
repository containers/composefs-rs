//! CLI integration tests that run on the host without root.
//!
//! Each test invokes `cfsctl --insecure` as a subprocess against a fresh
//! temp-dir repository. No network access, no fs-verity, no special
//! privileges required — these are the fast "does the CLI basically work"
//! smoke tests.

use anyhow::Result;
use xshell::{cmd, Shell};

use crate::{cfsctl, create_oci_layout, create_test_rootfs, integration_test};

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

    Ok(())
}
integration_test!(test_oci_pull_and_inspect);

fn test_oci_layer_inspect() -> Result<()> {
    use composefs::dumpfile_parse::{Entry, Item};
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
    assert!(
        info["entryCount"].as_u64().unwrap() >= 1,
        "expected at least 1 entry"
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

    // Verify the output directory structure
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

    // Parse index.json and verify it has a manifest entry
    let index_json = std::fs::read_to_string(output_path.join("index.json"))?;
    let index: serde_json::Value = serde_json::from_str(&index_json)?;
    let manifests = index["manifests"]
        .as_array()
        .expect("expected manifests array");
    assert_eq!(manifests.len(), 1, "expected 1 manifest entry");

    // Verify the manifest has a tag annotation
    let annotations = manifests[0]["annotations"]
        .as_object()
        .expect("expected annotations");
    assert_eq!(
        annotations["org.opencontainers.image.ref.name"],
        "test-image"
    );

    // Read the manifest blob and verify it has layers
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

    // Verify layers are uncompressed tar (not gzip/zstd)
    assert_eq!(
        layers[0]["mediaType"], "application/vnd.oci.image.layer.v1.tar",
        "expected uncompressed tar media type"
    );

    // Verify layer blobs exist and are non-empty
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

    // Verify config blob exists
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

    // Verify the image exists in the new repo
    let list_output = cmd!(sh, "{cfsctl} --insecure --repo {repo2} oci images --json").read()?;
    let images: serde_json::Value = serde_json::from_str(&list_output)?;
    let arr = images.as_array().expect("expected array");
    assert_eq!(arr.len(), 1, "expected 1 image in new repo");
    assert_eq!(arr[0]["name"], "roundtrip-image");
    assert_eq!(arr[0]["architecture"], "amd64");

    // Verify the config is intact
    let config_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo2} oci inspect roundtrip-image --config"
    )
    .read()?;
    let config: serde_json::Value = serde_json::from_str(&config_output)?;
    assert_eq!(config["architecture"], "amd64");
    assert_eq!(config["os"], "linux");

    // Verify layers survived the roundtrip
    let diff_ids = config["rootfs"]["diff_ids"]
        .as_array()
        .expect("expected diff_ids");
    assert_eq!(diff_ids.len(), 1, "expected 1 layer after roundtrip");

    Ok(())
}
integration_test!(test_oci_push_pull_roundtrip);
