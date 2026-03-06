//! OCI image signing integration tests.
//!
//! These tests exercise the `cfsctl oci sign`, `oci verify`, and
//! `oci export-signatures` CLI commands end-to-end against a local OCI
//! layout.  All tests run unprivileged with `--insecure` (no fsverity).

use std::path::{Path, PathBuf};

use anyhow::Result;
use xshell::{cmd, Shell};

use crate::{cfsctl, create_oci_layout, integration_test};

/// Generate a self-signed X.509 certificate and private key for testing.
fn generate_test_cert(dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let sh = Shell::new()?;
    let key_path = dir.join("test-key.pem");
    let cert_path = dir.join("test-cert.pem");
    cmd!(
        sh,
        "openssl req -x509 -newkey rsa:2048 -keyout {key_path} -out {cert_path} -days 1 -nodes -subj /CN=test-ca"
    )
    .run()?;
    Ok((cert_path, key_path))
}

/// Pull a local OCI layout into a repo directory.
fn pull_oci_image(
    sh: &Shell,
    cfsctl: &Path,
    repo: &Path,
    oci_layout: &Path,
    tag_name: &str,
) -> Result<String> {
    let output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} {tag_name}"
    )
    .read()?;
    Ok(output)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn test_sign_unsigned_image() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;
    let cert_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(cert_dir.path())?;

    pull_oci_image(&sh, &cfsctl, repo, &oci_layout, "test-image")?;

    let sign_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci sign test-image --cert {cert} --key {key}"
    )
    .read()?;

    // The sign command prints the artifact digest (sha256:...)
    assert!(
        sign_output.contains("sha256:"),
        "expected artifact digest in sign output, got: {sign_output}"
    );
    Ok(())
}
integration_test!(test_sign_unsigned_image);

fn test_sign_and_verify() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;
    let cert_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(cert_dir.path())?;

    pull_oci_image(&sh, &cfsctl, repo, &oci_layout, "test-image")?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci sign test-image --cert {cert} --key {key}"
    )
    .read()?;

    let verify_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci verify test-image --cert {cert}"
    )
    .read()?;

    assert!(
        verify_output.contains("verified"),
        "expected verification success, got: {verify_output}"
    );
    Ok(())
}
integration_test!(test_sign_and_verify);

fn test_verify_unsigned_fails() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    pull_oci_image(&sh, &cfsctl, repo, &oci_layout, "test-image")?;

    // Verify on an unsigned image should fail
    let result = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci verify test-image"
    )
    .read();

    assert!(
        result.is_err(),
        "expected verify to fail on unsigned image, but it succeeded"
    );
    Ok(())
}
integration_test!(test_verify_unsigned_fails);

fn test_verify_wrong_cert_fails() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    let cert_dir_a = tempfile::tempdir()?;
    let (cert_a, key_a) = generate_test_cert(cert_dir_a.path())?;

    let cert_dir_b = tempfile::tempdir()?;
    let (cert_b, _key_b) = generate_test_cert(cert_dir_b.path())?;

    pull_oci_image(&sh, &cfsctl, repo, &oci_layout, "test-image")?;

    // Sign with cert A
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci sign test-image --cert {cert_a} --key {key_a}"
    )
    .read()?;

    // Verify with cert B — should fail
    let result = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci verify test-image --cert {cert_b}"
    )
    .read();

    assert!(
        result.is_err(),
        "expected verify with wrong cert to fail, but it succeeded"
    );
    Ok(())
}
integration_test!(test_verify_wrong_cert_fails);

fn test_verify_without_cert() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;
    let cert_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(cert_dir.path())?;

    pull_oci_image(&sh, &cfsctl, repo, &oci_layout, "test-image")?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci sign test-image --cert {cert} --key {key}"
    )
    .read()?;

    // Verify without --cert should still succeed (digest matching only)
    let verify_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci verify test-image"
    )
    .read()?;

    assert!(
        verify_output.contains("digest matches"),
        "expected digest-only verification, got: {verify_output}"
    );
    assert!(
        verify_output.contains("no certificate provided"),
        "expected warning about missing certificate, got: {verify_output}"
    );
    Ok(())
}
integration_test!(test_verify_without_cert);

fn test_export_signatures() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;
    let cert_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(cert_dir.path())?;

    pull_oci_image(&sh, &cfsctl, repo, &oci_layout, "test-image")?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci sign test-image --cert {cert} --key {key}"
    )
    .read()?;

    let export_dir = tempfile::tempdir()?;
    let export = export_dir.path();

    let export_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci export-signatures test-image {export}"
    )
    .read()?;

    assert!(
        export_output.contains("Exported"),
        "expected export confirmation, got: {export_output}"
    );
    assert!(
        export.join("index.json").exists(),
        "expected index.json in export directory"
    );
    assert!(
        export.join("blobs").exists(),
        "expected blobs/ directory in export directory"
    );

    // index.json should contain at least one manifest descriptor
    let index_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(export.join("index.json"))?)?;
    let manifests = index_json["manifests"]
        .as_array()
        .expect("expected manifests array");
    assert!(
        !manifests.is_empty(),
        "expected at least one manifest in index.json"
    );
    Ok(())
}
integration_test!(test_export_signatures);

fn test_sign_idempotent() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;
    let cert_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(cert_dir.path())?;

    pull_oci_image(&sh, &cfsctl, repo, &oci_layout, "test-image")?;

    let digest1 = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci sign test-image --cert {cert} --key {key}"
    )
    .read()?;

    let digest2 = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci sign test-image --cert {cert} --key {key}"
    )
    .read()?;

    // Both sign operations should succeed; they may or may not produce the
    // same artifact digest (signatures contain timestamps), but both must
    // be valid sha256 references.
    assert!(
        digest1.contains("sha256:"),
        "first sign should produce artifact digest"
    );
    assert!(
        digest2.contains("sha256:"),
        "second sign should produce artifact digest"
    );

    // Verify should still pass after signing twice
    let verify_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci verify test-image --cert {cert}"
    )
    .read()?;
    assert!(
        verify_output.contains("verified"),
        "verify should pass after double-sign, got: {verify_output}"
    );
    Ok(())
}
integration_test!(test_sign_idempotent);

fn test_pull_require_signature_without_sig() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;
    let cert_dir = tempfile::tempdir()?;
    let (cert, _key) = generate_test_cert(cert_dir.path())?;

    // Pull with --require-signature from an unsigned OCI layout — should fail
    let result = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image --require-signature --trust-cert {cert}"
    )
    .read();

    assert!(
        result.is_err(),
        "expected pull --require-signature to fail on unsigned image, but it succeeded"
    );
    Ok(())
}
integration_test!(test_pull_require_signature_without_sig);

fn test_pull_require_signature_with_sig() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let cert_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(cert_dir.path())?;

    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;

    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();

    // Pull the image first, sign it, so signatures are in the repo.
    pull_oci_image(&sh, &cfsctl, repo, &oci_layout, "test-image")?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci sign test-image --cert {cert} --key {key}"
    )
    .read()?;

    // Re-pull with --require-signature — should succeed because the
    // signature artifacts are already in the repo from the sign step.
    let pull_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull oci:{oci_layout} test-image --require-signature --trust-cert {cert}"
    )
    .read()?;

    assert!(
        pull_output.contains("Signature verification passed") || pull_output.contains("verified"),
        "expected signature verification to pass, got: {pull_output}"
    );
    Ok(())
}
integration_test!(test_pull_require_signature_with_sig);

// ---------------------------------------------------------------------------
// Artifact structure & pipeline tests
// ---------------------------------------------------------------------------

/// Helper: sign an image and export the artifact to an OCI layout, returning
/// the parsed artifact manifest and the export directory path.
fn sign_and_export() -> Result<(serde_json::Value, tempfile::TempDir, tempfile::TempDir)> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;
    let cert_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(cert_dir.path())?;

    pull_oci_image(&sh, &cfsctl, repo, &oci_layout, "test-image")?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci sign test-image --cert {cert} --key {key}"
    )
    .read()?;

    let export_dir = tempfile::tempdir()?;
    let export = export_dir.path();

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci export-signatures test-image {export}"
    )
    .read()?;

    // Parse the OCI index to find the artifact manifest
    let index: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(export.join("index.json"))?)?;
    let manifest_desc = &index["manifests"]
        .as_array()
        .expect("expected manifests array")[0];
    let manifest_digest = manifest_desc["digest"]
        .as_str()
        .expect("expected digest string");
    let hash = manifest_digest
        .strip_prefix("sha256:")
        .expect("expected sha256: prefix");
    let manifest_path = export.join("blobs").join("sha256").join(hash);
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(manifest_path)?)?;

    Ok((manifest, export_dir, repo_dir))
}

fn test_sign_artifact_contains_erofs_layers() -> Result<()> {
    let (manifest, _export_dir, _repo_dir) = sign_and_export()?;

    // Check artifactType
    let artifact_type = manifest["artifactType"]
        .as_str()
        .expect("expected artifactType");
    assert_eq!(
        artifact_type, "application/vnd.composefs.erofs-alongside.v1",
        "unexpected artifactType"
    );

    let layers = manifest["layers"]
        .as_array()
        .expect("expected layers array");
    assert!(!layers.is_empty(), "expected non-empty layers");

    let erofs_layers: Vec<&serde_json::Value> = layers
        .iter()
        .filter(|l| l["mediaType"].as_str() == Some("application/vnd.composefs.v1.erofs"))
        .collect();
    let sig_layers: Vec<&serde_json::Value> = layers
        .iter()
        .filter(|l| l["mediaType"].as_str() == Some("application/vnd.composefs.signature.v1+pkcs7"))
        .collect();

    assert!(
        !erofs_layers.is_empty(),
        "expected at least one EROFS layer"
    );
    assert!(
        !sig_layers.is_empty(),
        "expected at least one signature layer"
    );

    // EROFS layers must come before signature layers in the manifest
    let last_erofs_idx = layers
        .iter()
        .rposition(|l| l["mediaType"].as_str() == Some("application/vnd.composefs.v1.erofs"))
        .unwrap();
    let first_sig_idx = layers
        .iter()
        .position(|l| {
            l["mediaType"].as_str() == Some("application/vnd.composefs.signature.v1+pkcs7")
        })
        .unwrap();
    assert!(
        last_erofs_idx < first_sig_idx,
        "EROFS layers (last at {last_erofs_idx}) must precede signature layers (first at {first_sig_idx})"
    );

    // Each EROFS layer has composefs.erofs.type annotation ("layer" or "merged")
    for layer in &erofs_layers {
        let annotations = layer["annotations"]
            .as_object()
            .expect("expected annotations");
        let erofs_type = annotations
            .get("composefs.erofs.type")
            .and_then(|v| v.as_str())
            .expect("expected composefs.erofs.type annotation");
        assert!(
            erofs_type == "layer" || erofs_type == "merged",
            "unexpected composefs.erofs.type value: {erofs_type}"
        );
    }

    // Each signature layer has composefs.signature.type annotation
    for layer in &sig_layers {
        let annotations = layer["annotations"]
            .as_object()
            .expect("expected annotations");
        assert!(
            annotations.contains_key("composefs.signature.type"),
            "signature layer missing composefs.signature.type annotation"
        );
    }

    // Each layer has a valid hex composefs.digest annotation
    for layer in layers {
        let annotations = layer["annotations"]
            .as_object()
            .expect("expected annotations");
        let digest = annotations
            .get("composefs.digest")
            .and_then(|v| v.as_str())
            .expect("expected composefs.digest annotation");
        assert!(
            !digest.is_empty() && digest.chars().all(|c| c.is_ascii_hexdigit()),
            "composefs.digest is not valid hex: {digest}"
        );
    }

    // The OCI layout creates 1 layer, so we expect:
    //   - 2 EROFS layers (1 per OCI layer + 1 merged)
    //   - 2 signature layers (1 per OCI layer + 1 merged)
    assert_eq!(
        erofs_layers.len(),
        2,
        "expected 2 EROFS layers (1 layer + 1 merged), got {}",
        erofs_layers.len()
    );
    assert_eq!(
        sig_layers.len(),
        2,
        "expected 2 signature layers (1 layer + 1 merged), got {}",
        sig_layers.len()
    );

    // Manifest must have composefs.algorithm annotation
    let manifest_annotations = manifest["annotations"]
        .as_object()
        .expect("expected manifest-level annotations");
    assert!(
        manifest_annotations.contains_key("composefs.algorithm"),
        "manifest missing composefs.algorithm annotation"
    );

    Ok(())
}
integration_test!(test_sign_artifact_contains_erofs_layers);

fn test_sign_erofs_blobs_nonempty() -> Result<()> {
    let (manifest, export_dir, _repo_dir) = sign_and_export()?;
    let export = export_dir.path();

    let layers = manifest["layers"]
        .as_array()
        .expect("expected layers array");

    let erofs_layers: Vec<&serde_json::Value> = layers
        .iter()
        .filter(|l| l["mediaType"].as_str() == Some("application/vnd.composefs.v1.erofs"))
        .collect();

    assert!(!erofs_layers.is_empty(), "no EROFS layers found");

    for layer in &erofs_layers {
        let digest = layer["digest"]
            .as_str()
            .expect("expected digest on EROFS layer");
        let hash = digest
            .strip_prefix("sha256:")
            .expect("expected sha256: prefix on layer digest");
        let blob_path = export.join("blobs").join("sha256").join(hash);
        let metadata = std::fs::metadata(&blob_path)
            .unwrap_or_else(|_| panic!("EROFS blob not found at {}", blob_path.display()));
        assert!(
            metadata.len() > 0,
            "EROFS blob {} is empty (0 bytes)",
            blob_path.display()
        );
    }

    Ok(())
}
integration_test!(test_sign_erofs_blobs_nonempty);

fn test_seal_and_sign_roundtrip() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;
    let cert_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(cert_dir.path())?;

    // 1. Pull
    pull_oci_image(&sh, &cfsctl, repo, &oci_layout, "test-image")?;

    // 2. Sign
    let sign_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci sign test-image --cert {cert} --key {key}"
    )
    .read()?;
    assert!(
        sign_output.contains("sha256:"),
        "sign should produce artifact digest, got: {sign_output}"
    );

    // 3. Verify
    let verify_output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci verify test-image --cert {cert}"
    )
    .read()?;
    assert!(
        verify_output.contains("verified"),
        "verify should succeed, got: {verify_output}"
    );

    // 4. Export
    let export_dir = tempfile::tempdir()?;
    let export = export_dir.path();
    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci export-signatures test-image {export}"
    )
    .read()?;

    // 5. Parse and validate the exported artifact manifest
    let index: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(export.join("index.json"))?)?;
    let manifests = index["manifests"]
        .as_array()
        .expect("expected manifests array");
    assert!(
        !manifests.is_empty(),
        "expected at least one manifest in exported OCI layout"
    );

    let manifest_desc = &manifests[0];
    let hash = manifest_desc["digest"]
        .as_str()
        .expect("expected digest")
        .strip_prefix("sha256:")
        .expect("expected sha256: prefix");
    let artifact_manifest: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        export.join("blobs").join("sha256").join(hash),
    )?)?;

    // Validate artifact structure
    assert_eq!(
        artifact_manifest["artifactType"].as_str(),
        Some("application/vnd.composefs.erofs-alongside.v1"),
    );
    let layers = artifact_manifest["layers"]
        .as_array()
        .expect("expected layers");
    let has_erofs = layers
        .iter()
        .any(|l| l["mediaType"].as_str() == Some("application/vnd.composefs.v1.erofs"));
    let has_sigs = layers
        .iter()
        .any(|l| l["mediaType"].as_str() == Some("application/vnd.composefs.signature.v1+pkcs7"));
    assert!(has_erofs, "artifact should contain EROFS layers");
    assert!(has_sigs, "artifact should contain signature layers");

    // 6. Verify the image has referrers via oci images --json
    let images_json = cmd!(sh, "{cfsctl} --insecure --repo {repo} oci images --json").read()?;
    let images: Vec<serde_json::Value> = serde_json::from_str(&images_json)?;
    let test_image = images
        .iter()
        .find(|img| img["name"].as_str() == Some("test-image"))
        .expect("test-image not found in oci images output");
    let referrer_count = test_image["referrerCount"]
        .as_u64()
        .expect("expected referrerCount");
    assert!(
        referrer_count > 0,
        "expected referrer_count > 0, got {referrer_count}"
    );

    Ok(())
}
integration_test!(test_seal_and_sign_roundtrip);

fn test_inspect_shows_referrer_info() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let repo_dir = tempfile::tempdir()?;
    let repo = repo_dir.path();
    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;
    let cert_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(cert_dir.path())?;

    pull_oci_image(&sh, &cfsctl, repo, &oci_layout, "test-image")?;

    cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci sign test-image --cert {cert} --key {key}"
    )
    .read()?;

    // Inspect the image and parse JSON output
    let inspect_json = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci inspect test-image"
    )
    .read()?;
    let inspect: serde_json::Value = serde_json::from_str(&inspect_json)?;

    // The "referrers" array should have at least one entry
    let referrers = inspect["referrers"]
        .as_array()
        .expect("expected referrers array in inspect output");
    assert!(
        !referrers.is_empty(),
        "expected at least one referrer after signing"
    );

    // Each referrer should have a digest field and artifactType
    for referrer in referrers {
        let digest = referrer["digest"]
            .as_str()
            .expect("expected digest field in referrer");
        assert!(
            digest.starts_with("sha256:"),
            "referrer digest should start with sha256:, got: {digest}"
        );
        let artifact_type = referrer["artifactType"]
            .as_str()
            .expect("expected artifactType field in referrer");
        assert!(
            !artifact_type.is_empty(),
            "artifactType should not be empty"
        );
    }

    Ok(())
}
integration_test!(test_inspect_shows_referrer_info);
