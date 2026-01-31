//! Integration test utilities for composefs-rs
//!
//! This library provides utilities for running integration tests.
//! The main test runner is in main.rs.

use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;

use anyhow::{Context, Result};
use composefs::fsverity::Sha256HashValue;
use composefs::repository::Repository;
use tempfile::TempDir;

/// Test label for cleanup
pub const INTEGRATION_TEST_LABEL: &str = "composefs-rs.integration-test=1";

/// Get the path to cfsctl binary
pub fn get_cfsctl_path() -> Result<String> {
    // Check environment first
    if let Ok(path) = std::env::var("CFSCTL_PATH") {
        return Ok(path);
    }
    // Look in common locations
    for path in [
        "./target/release/cfsctl",
        "./target/debug/cfsctl",
        "/usr/bin/cfsctl",
    ] {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }
    anyhow::bail!("cfsctl not found; set CFSCTL_PATH or build with `cargo build --release`")
}

/// Get the primary test image
pub fn get_primary_image() -> String {
    std::env::var("COMPOSEFS_RS_PRIMARY_IMAGE")
        .unwrap_or_else(|_| "quay.io/centos-bootc/centos-bootc:stream10".to_string())
}

/// Get all test images
pub fn get_all_images() -> Vec<String> {
    std::env::var("COMPOSEFS_RS_ALL_IMAGES")
        .unwrap_or_else(|_| get_primary_image())
        .split_whitespace()
        .map(String::from)
        .collect()
}

/// Captured command output
#[derive(Debug)]
pub struct CapturedOutput {
    /// Exit status
    pub status: ExitStatus,
    /// Captured stdout
    pub stdout: String,
    /// Captured stderr
    pub stderr: String,
}

impl CapturedOutput {
    /// Assert the command succeeded
    pub fn assert_success(&self) -> Result<()> {
        if !self.status.success() {
            anyhow::bail!(
                "Command failed with status {}\nstdout: {}\nstderr: {}",
                self.status,
                self.stdout,
                self.stderr
            );
        }
        Ok(())
    }
}

/// Run a command and capture output
pub fn run_command(cmd: &str, args: &[&str]) -> Result<CapturedOutput> {
    let output = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("Failed to execute: {} {:?}", cmd, args))?;

    Ok(CapturedOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

/// Run cfsctl with arguments
pub fn run_cfsctl(args: &[&str]) -> Result<CapturedOutput> {
    let cfsctl = get_cfsctl_path()?;
    run_command(&cfsctl, args)
}

/// Create a test repository in a temporary directory.
///
/// The TempDir is returned alongside the repo to keep it alive.
pub fn create_test_repository(tempdir: &TempDir) -> Result<Arc<Repository<Sha256HashValue>>> {
    let fd = rustix::fs::open(
        tempdir.path(),
        rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::PATH,
        0.into(),
    )?;

    let mut repo = Repository::open_path(&fd, ".")?;
    repo.set_insecure(true);
    Ok(Arc::new(repo))
}

/// Build a minimal test image using podman and return its ID
pub fn build_test_image() -> Result<String> {
    let temp_dir = TempDir::new()?;
    let containerfile = temp_dir.path().join("Containerfile");

    // Create a simple Containerfile with various file sizes to test
    // both inline and external storage paths
    std::fs::write(
        &containerfile,
        r#"FROM busybox:latest
# Small file (should be inlined)
RUN echo "small content" > /small.txt
# Larger file (should be external)
RUN dd if=/dev/zero of=/large.bin bs=1024 count=100 2>/dev/null
# Directory with files
RUN mkdir -p /testdir && echo "file1" > /testdir/a.txt && echo "file2" > /testdir/b.txt
# Symlink
RUN ln -s /small.txt /link.txt
"#,
    )?;

    let iid_file = temp_dir.path().join("image.iid");

    let output = Command::new("podman")
        .args([
            "build",
            "--pull=newer",
            &format!("--iidfile={}", iid_file.display()),
            "-f",
            &containerfile.to_string_lossy(),
            &temp_dir.path().to_string_lossy(),
        ])
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "podman build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let image_id = std::fs::read_to_string(&iid_file)?.trim().to_string();
    Ok(image_id)
}

/// Remove a test image
pub fn cleanup_test_image(image_id: &str) {
    let _ = Command::new("podman")
        .args(["rmi", "-f", image_id])
        .output();
}
