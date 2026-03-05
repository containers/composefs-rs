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
