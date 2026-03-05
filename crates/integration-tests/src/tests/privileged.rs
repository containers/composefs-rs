//! Privileged integration tests requiring root and fs-verity support.
//!
//! These tests run `cfsctl` without `--insecure` on a real ext4 filesystem
//! with the verity feature enabled. They need root to create loop mounts.
//!
//! When run on the host (not as root), each test automatically re-executes
//! itself inside a bcvk ephemeral VM where it has real root and kernel
//! fs-verity support. The `COMPOSEFS_IN_VM` env var prevents infinite
//! recursion — see [`require_privileged`].

use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Result};
use xshell::{cmd, Shell};

use crate::{cfsctl, create_oci_layout, create_test_rootfs, integration_test};

/// Ensure we're running as root, or re-exec this test inside a VM.
///
/// If already root (e.g. inside a bcvk VM), returns `Ok(None)` and the
/// test proceeds normally.
///
/// If not root and `COMPOSEFS_TEST_IMAGE` is set, spawns
/// `bcvk ephemeral run-ssh <image> -- cfsctl-integration-tests --exact <test>`
/// and returns `Ok(Some(()))` — the caller should return immediately since
/// the test already ran in the VM.
///
/// If not root and no test image is configured, returns an error.
fn require_privileged(test_name: &str) -> Result<Option<()>> {
    if rustix::process::getuid().is_root() {
        return Ok(None);
    }

    // We're on the host without root — delegate to a VM.
    if std::env::var_os("COMPOSEFS_IN_VM").is_some() {
        bail!("COMPOSEFS_IN_VM is set but we're not root — VM setup is broken");
    }

    let image = std::env::var("COMPOSEFS_TEST_IMAGE").map_err(|_| {
        anyhow::anyhow!(
            "not root and COMPOSEFS_TEST_IMAGE not set; \
             run `just build-test-image` or use `just test-integration-vm`"
        )
    })?;

    let sh = Shell::new()?;
    let bcvk = std::env::var("BCVK_PATH").unwrap_or_else(|_| "bcvk".into());
    cmd!(
        sh,
        "{bcvk} ephemeral run-ssh {image} -- cfsctl-integration-tests --exact {test_name}"
    )
    .run()?;
    Ok(Some(()))
}

/// A temporary directory backed by a loopback ext4 filesystem with verity support.
///
/// tmpfs doesn't support fs-verity, so privileged tests that need verity
/// (i.e. running cfsctl without `--insecure`) must use a real filesystem.
/// This creates a sparse file, formats it as ext4 with the verity feature,
/// and loop-mounts it to a temp directory.
struct VerityTempDir {
    mountpoint: PathBuf,
    _backing: tempfile::TempDir,
}

impl VerityTempDir {
    fn new() -> Result<Self> {
        let backing = tempfile::tempdir()?;
        let img = backing.path().join("fs.img");
        let mountpoint = backing.path().join("mnt");
        std::fs::create_dir(&mountpoint)?;

        let sh = Shell::new()?;
        cmd!(sh, "truncate -s 256M {img}").run()?;
        cmd!(sh, "mkfs.ext4 -q -O verity -b 4096 {img}").run()?;
        cmd!(sh, "mount -o loop {img} {mountpoint}").run()?;

        // Create a repo subdirectory (cfsctl needs it to exist)
        std::fs::create_dir(mountpoint.join("repo"))?;

        Ok(Self {
            mountpoint,
            _backing: backing,
        })
    }

    fn path(&self) -> &Path {
        &self.mountpoint
    }
}

impl Drop for VerityTempDir {
    fn drop(&mut self) {
        let _ = std::process::Command::new("umount")
            .arg(&self.mountpoint)
            .status();
    }
}

fn privileged_check_root() -> Result<()> {
    if require_privileged("privileged_check_root")?.is_some() {
        return Ok(());
    }
    Ok(())
}
integration_test!(privileged_check_root);

fn privileged_repo_without_insecure() -> Result<()> {
    if require_privileged("privileged_repo_without_insecure")?.is_some() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;
    let repo = verity_dir.path().join("repo");

    let output = cmd!(sh, "{cfsctl} --repo {repo} gc").read()?;
    ensure!(
        output.contains("Objects: 0 removed"),
        "gc on fresh repo failed: {output}"
    );
    Ok(())
}
integration_test!(privileged_repo_without_insecure);

fn privileged_create_image() -> Result<()> {
    if require_privileged("privileged_create_image")?.is_some() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;
    let repo = verity_dir.path().join("repo");
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    let output = cmd!(sh, "{cfsctl} --repo {repo} create-image {rootfs}").read()?;
    ensure!(
        !output.trim().is_empty(),
        "expected image ID output, got nothing"
    );
    Ok(())
}
integration_test!(privileged_create_image);

fn privileged_create_image_idempotent() -> Result<()> {
    if require_privileged("privileged_create_image_idempotent")?.is_some() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;
    let repo = verity_dir.path().join("repo");
    let fixture_dir = tempfile::tempdir()?;
    let rootfs = create_test_rootfs(fixture_dir.path())?;

    let id1 = cmd!(sh, "{cfsctl} --repo {repo} create-image {rootfs}").read()?;
    let id2 = cmd!(sh, "{cfsctl} --repo {repo} create-image {rootfs}").read()?;
    ensure!(
        id1.trim() == id2.trim(),
        "creating the same image twice should produce the same ID: {id1} vs {id2}"
    );
    Ok(())
}
integration_test!(privileged_create_image_idempotent);

// ---------------------------------------------------------------------------
// OCI signing tests with real fs-verity enforcement
// ---------------------------------------------------------------------------

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

/// Pull a local OCI layout into a verity-enabled repo (no `--insecure`).
fn pull_oci_image_verity(
    sh: &Shell,
    cfsctl: &Path,
    repo: &Path,
    oci_layout: &Path,
    tag_name: &str,
) -> Result<String> {
    let output = cmd!(
        sh,
        "{cfsctl} --repo {repo} oci pull oci:{oci_layout} {tag_name}"
    )
    .read()?;
    Ok(output)
}

/// Sign, then verify an OCI image on a verity-enabled filesystem.
///
/// This exercises the full signing pipeline with real fs-verity enforcement:
/// pull into a verity repo, generate a cert, sign, and verify.
fn privileged_sign_and_verify_with_verity() -> Result<()> {
    if require_privileged("privileged_sign_and_verify_with_verity")?.is_some() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;
    let repo = verity_dir.path().join("repo");

    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;
    pull_oci_image_verity(&sh, &cfsctl, &repo, &oci_layout, "test-image")?;

    let cert_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(cert_dir.path())?;

    let sign_output = cmd!(
        sh,
        "{cfsctl} --repo {repo} oci sign test-image --cert {cert} --key {key}"
    )
    .read()?;
    ensure!(
        sign_output.contains("sha256:"),
        "expected artifact digest in sign output, got: {sign_output}"
    );

    let verify_output = cmd!(
        sh,
        "{cfsctl} --repo {repo} oci verify test-image --cert {cert}"
    )
    .read()?;
    ensure!(
        verify_output.contains("verified"),
        "expected verification success, got: {verify_output}"
    );

    Ok(())
}
integration_test!(privileged_sign_and_verify_with_verity);

/// Seal an OCI image, then sign and verify it on a verity-enabled filesystem.
///
/// Sealing embeds the composefs verity digest into the manifest. This test
/// confirms that signing still works correctly on a sealed image.
fn privileged_seal_then_sign() -> Result<()> {
    if require_privileged("privileged_seal_then_sign")?.is_some() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;
    let repo = verity_dir.path().join("repo");

    let fixture_dir = tempfile::tempdir()?;
    let oci_layout = create_oci_layout(fixture_dir.path())?;
    pull_oci_image_verity(&sh, &cfsctl, &repo, &oci_layout, "test-image")?;

    // Seal the image first
    let seal_output = cmd!(sh, "{cfsctl} --repo {repo} oci seal test-image").read()?;
    ensure!(
        !seal_output.trim().is_empty(),
        "expected seal output with config/verity digests, got nothing"
    );

    // Then sign the sealed image
    let cert_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(cert_dir.path())?;

    let sign_output = cmd!(
        sh,
        "{cfsctl} --repo {repo} oci sign test-image --cert {cert} --key {key}"
    )
    .read()?;
    ensure!(
        sign_output.contains("sha256:"),
        "expected artifact digest in sign output, got: {sign_output}"
    );

    // Verify the sealed+signed image
    let verify_output = cmd!(
        sh,
        "{cfsctl} --repo {repo} oci verify test-image --cert {cert}"
    )
    .read()?;
    ensure!(
        verify_output.contains("verified"),
        "expected verification success on sealed image, got: {verify_output}"
    );

    Ok(())
}
integration_test!(privileged_seal_then_sign);

/// Inject a test certificate into the kernel's `.fs-verity` keyring.
///
/// This modifies kernel state and must run in an ephemeral VM to avoid
/// polluting the host keyring.
fn privileged_keyring_add_cert() -> Result<()> {
    if require_privileged("privileged_keyring_add_cert")?.is_some() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;

    let cert_dir = tempfile::tempdir()?;
    let (cert, _key) = generate_test_cert(cert_dir.path())?;

    let output = cmd!(sh, "{cfsctl} keyring add-cert {cert}").read()?;
    ensure!(
        output.contains("Certificate added"),
        "expected 'Certificate added' confirmation, got: {output}"
    );

    Ok(())
}
integration_test!(privileged_keyring_add_cert);
