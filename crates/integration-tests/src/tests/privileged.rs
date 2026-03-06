//! Privileged integration tests requiring root and fs-verity support.
//!
//! These tests run `cfsctl` without `--insecure` on a real ext4 filesystem
//! with the verity feature enabled. They need root to create loop mounts.
//!
//! When run on the host (not as root), each test automatically re-executes
//! itself inside a bcvk ephemeral VM where it has real root and kernel
//! fs-verity support. The `COMPOSEFS_IN_VM` env var prevents infinite
//! recursion — see [`require_privileged`].
//!
//! Some tests additionally require `CONFIG_FS_VERITY_BUILTIN_SIGNATURES=y`,
//! which is available on Debian/Ubuntu kernels but not on CentOS/Fedora.
//! These are gated with [`require_fsverity_builtin_signatures`] — a kernel
//! capability check that legitimately skips on unsupported kernels.

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

/// Check whether the kernel supports `CONFIG_FS_VERITY_BUILTIN_SIGNATURES`.
///
/// Returns `true` if the feature is available and the test should proceed.
/// Returns `false` and prints a skip message if the kernel doesn't support it.
///
/// This is a legitimate kernel capability check — CentOS/Fedora kernels don't
/// enable this feature, so tests gated on it can only run on Debian/Ubuntu.
fn require_fsverity_builtin_signatures() -> bool {
    if crate::has_fsverity_builtin_signatures() {
        return true;
    }
    // This is a kernel capability, not a missing dependency.
    // CentOS/Fedora kernels don't enable CONFIG_FS_VERITY_BUILTIN_SIGNATURES.
    // These tests only run on Debian/Ubuntu where it's enabled.
    eprintln!("SKIP (kernel capability): CONFIG_FS_VERITY_BUILTIN_SIGNATURES not enabled");
    false
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
/// polluting the host keyring. Requires `CONFIG_FS_VERITY_BUILTIN_SIGNATURES=y`.
fn privileged_keyring_add_cert() -> Result<()> {
    if require_privileged("privileged_keyring_add_cert")?.is_some() {
        return Ok(());
    }

    if !require_fsverity_builtin_signatures() {
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

/// Inject a cert into the kernel keyring, then sign and verify an OCI image
/// on a verity-enabled filesystem.
///
/// This exercises the full kernel-level signature enforcement pipeline:
/// cert injection into `.fs-verity` keyring, pull with real verity, sign,
/// and verify. Requires `CONFIG_FS_VERITY_BUILTIN_SIGNATURES=y`.
fn privileged_keyring_and_verify_with_verity() -> Result<()> {
    if require_privileged("privileged_keyring_and_verify_with_verity")?.is_some() {
        return Ok(());
    }

    if !require_fsverity_builtin_signatures() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;
    let repo = verity_dir.path().join("repo");
    let fixture_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(fixture_dir.path())?;

    // Inject cert into kernel's .fs-verity keyring
    let add_output = cmd!(sh, "{cfsctl} keyring add-cert {cert}").read()?;
    ensure!(
        add_output.contains("Certificate added"),
        "keyring add-cert failed: {add_output}"
    );

    // Pull an image with real verity (no --insecure)
    let oci_layout = create_oci_layout(fixture_dir.path())?;
    pull_oci_image_verity(&sh, &cfsctl, &repo, &oci_layout, "test-image")?;

    // Sign the image
    let sign_output = cmd!(
        sh,
        "{cfsctl} --repo {repo} oci sign test-image --cert {cert} --key {key}"
    )
    .read()?;
    ensure!(
        sign_output.contains("sha256:"),
        "expected artifact digest in sign output, got: {sign_output}"
    );

    // Verify the image with the cert
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
integration_test!(privileged_keyring_and_verify_with_verity);

// ---------------------------------------------------------------------------
// Kernel-level fsverity signature enforcement tests
//
// These tests exercise the kernel's require_signatures sysctl, which forces
// all FS_IOC_ENABLE_VERITY calls to include a valid PKCS#7 signature whose
// cert is in the `.fs-verity` keyring. They only work on kernels with
// CONFIG_FS_VERITY_BUILTIN_SIGNATURES=y (Debian/Ubuntu).
// ---------------------------------------------------------------------------

const REQUIRE_SIGNATURES_PATH: &str = "/proc/sys/fs/verity/require_signatures";

/// RAII guard that restores `require_signatures` to 0 on drop.
///
/// Kernel-level signature enforcement affects ALL verity operations system-wide,
/// so we must restore it even if a test panics — otherwise subsequent tests in
/// the same VM would be broken.
struct RequireSignaturesGuard;

impl RequireSignaturesGuard {
    fn enable() -> Result<Self> {
        std::fs::write(REQUIRE_SIGNATURES_PATH, "1")?;
        Ok(Self)
    }
}

impl Drop for RequireSignaturesGuard {
    fn drop(&mut self) {
        let _ = std::fs::write(REQUIRE_SIGNATURES_PATH, "0");
    }
}

/// Test that the kernel rejects enabling fsverity without a signature when
/// `require_signatures` is enabled.
///
/// Steps:
/// 1. Inject a cert into the kernel keyring (required before enabling require_signatures
///    on some kernel versions)
/// 2. Enable require_signatures
/// 3. Create a file on a verity-capable ext4 filesystem
/// 4. Try to enable fsverity without a signature
/// 5. Assert the kernel rejects it with EKEYREJECTED
fn privileged_kernel_rejects_unsigned_verity() -> Result<()> {
    if require_privileged("privileged_kernel_rejects_unsigned_verity")?.is_some() {
        return Ok(());
    }
    if !require_fsverity_builtin_signatures() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;

    // Generate and inject a cert so the keyring is populated
    let cert_dir = tempfile::tempdir()?;
    let (cert, _key) = generate_test_cert(cert_dir.path())?;
    cmd!(sh, "{cfsctl} keyring add-cert {cert}").run()?;

    // Enable require_signatures — guard restores to 0 on drop
    let _guard = RequireSignaturesGuard::enable()?;

    // Write a test file on the verity-capable filesystem
    let test_file = verity_dir.path().join("testfile");
    std::fs::write(&test_file, "test content for unsigned verity\n")?;

    // Try to enable fsverity without a signature using the fsverity CLI
    let result = cmd!(sh, "fsverity enable {test_file}").run();

    ensure!(
        result.is_err(),
        "expected fsverity enable WITHOUT signature to fail when require_signatures=1, \
         but it succeeded"
    );

    Ok(())
}
integration_test!(privileged_kernel_rejects_unsigned_verity);

/// Test that the kernel rejects a fsverity signature made with a key whose
/// certificate is NOT in the kernel's `.fs-verity` keyring.
///
/// Steps:
/// 1. Generate two cert/key pairs (A and B)
/// 2. Inject only cert A into the kernel keyring
/// 3. Enable require_signatures
/// 4. Create a file, compute its verity digest, sign with key B
/// 5. Try to enable fsverity with key B's signature
/// 6. Assert the kernel rejects it (cert B is not trusted)
fn privileged_kernel_rejects_wrong_signature() -> Result<()> {
    if require_privileged("privileged_kernel_rejects_wrong_signature")?.is_some() {
        return Ok(());
    }
    if !require_fsverity_builtin_signatures() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;

    // Generate two certs — only inject cert_a into the kernel keyring
    let cert_dir_a = tempfile::tempdir()?;
    let (cert_a, _key_a) = generate_test_cert(cert_dir_a.path())?;

    let cert_dir_b = tempfile::tempdir()?;
    let (cert_b, key_b) = generate_test_cert(cert_dir_b.path())?;

    cmd!(sh, "{cfsctl} keyring add-cert {cert_a}").run()?;

    let _guard = RequireSignaturesGuard::enable()?;

    // Write a test file
    let test_file = verity_dir.path().join("testfile");
    std::fs::write(&test_file, "test content for wrong signature\n")?;

    // Sign the file's verity digest with key_b (whose cert is NOT in the keyring)
    let sig_file = verity_dir.path().join("wrong.sig");
    cmd!(
        sh,
        "fsverity sign {test_file} {sig_file} --key {key_b} --cert {cert_b}"
    )
    .run()?;

    // Try to enable verity with the wrong signature — kernel should reject
    let result = cmd!(sh, "fsverity enable {test_file} --signature {sig_file}").run();

    ensure!(
        result.is_err(),
        "expected fsverity enable with WRONG cert's signature to fail, but it succeeded"
    );

    Ok(())
}
integration_test!(privileged_kernel_rejects_wrong_signature);

/// Test the positive case: kernel accepts a fsverity signature made with a
/// key whose certificate IS in the `.fs-verity` keyring.
///
/// Steps:
/// 1. Generate a cert/key pair, inject cert into the kernel keyring
/// 2. Enable require_signatures
/// 3. Create a file, sign its verity digest with the trusted key
/// 4. Enable fsverity with the valid signature
/// 5. Assert success and verify the file's verity digest is measurable
fn privileged_kernel_accepts_valid_signature() -> Result<()> {
    if require_privileged("privileged_kernel_accepts_valid_signature")?.is_some() {
        return Ok(());
    }
    if !require_fsverity_builtin_signatures() {
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let verity_dir = VerityTempDir::new()?;

    // Generate cert and inject into kernel keyring
    let cert_dir = tempfile::tempdir()?;
    let (cert, key) = generate_test_cert(cert_dir.path())?;
    cmd!(sh, "{cfsctl} keyring add-cert {cert}").run()?;

    let _guard = RequireSignaturesGuard::enable()?;

    // Write a test file
    let test_file = verity_dir.path().join("testfile");
    std::fs::write(&test_file, "test content for valid signature\n")?;

    // Sign the file with the trusted key
    let sig_file = verity_dir.path().join("valid.sig");
    cmd!(
        sh,
        "fsverity sign {test_file} {sig_file} --key {key} --cert {cert}"
    )
    .run()?;

    // Enable verity with the valid signature — should succeed
    cmd!(sh, "fsverity enable {test_file} --signature {sig_file}").run()?;

    // Verify the file now has a measurable verity digest
    let digest_output = cmd!(sh, "fsverity measure {test_file}").read()?;
    ensure!(
        !digest_output.trim().is_empty(),
        "expected fsverity measure to return a digest after enabling verity"
    );
    ensure!(
        digest_output.contains("sha256:"),
        "expected sha256 digest in fsverity measure output, got: {digest_output}"
    );

    Ok(())
}
integration_test!(privileged_kernel_accepts_valid_signature);
