//! Integration test runner for composefs-rs.
//!
//! This binary uses [`libtest_mimic`] as a custom test harness (no `#[test]`).
//! Tests are registered via the [`integration_test!`] macro in submodules
//! and collected from the [`INTEGRATION_TESTS`] distributed slice at startup.

// linkme requires unsafe for distributed slices
#![allow(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use libtest_mimic::{Arguments, Trial};

pub(crate) use integration_tests::{integration_test, INTEGRATION_TESTS};

mod tests;

/// Return the path to the cfsctl binary.
///
/// Resolution order:
/// 1. `CFSCTL_PATH` environment variable
/// 2. `target/{release,debug}/cfsctl` relative to the workspace root
/// 3. `/usr/bin/cfsctl` (for VM-based integration tests)
pub(crate) fn cfsctl() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("CFSCTL_PATH") {
        return Ok(PathBuf::from(p));
    }

    // Walk up from the crate's manifest dir to find the workspace target/
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(Path::new("."));

    for profile in ["release", "debug"] {
        let candidate = workspace.join("target").join(profile).join("cfsctl");
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    // In VM-based tests the binary is baked into the container image
    let system = Path::new("/usr/bin/cfsctl");
    if system.exists() {
        return Ok(system.to_path_buf());
    }

    bail!(
        "cfsctl binary not found; build it with `cargo build -p cfsctl` \
         or set CFSCTL_PATH"
    )
}

/// Create a test rootfs fixture inside `parent` and return its path.
///
/// Includes a file large enough (128 KiB) to avoid erofs inlining so that
/// `image-objects` will report at least one external object.
pub(crate) fn create_test_rootfs(parent: &Path) -> Result<PathBuf> {
    let root = parent.join("rootfs");
    fs::create_dir_all(root.join("usr/bin"))?;
    fs::create_dir_all(root.join("usr/lib"))?;
    fs::create_dir_all(root.join("etc"))?;

    // A large-ish file that won't be inlined into the erofs image
    fs::write(root.join("usr/bin/hello"), "x".repeat(128 * 1024))?;
    fs::write(root.join("usr/lib/readme.txt"), "test fixture\n")?;
    fs::write(root.join("etc/hostname"), "integration-test\n")?;
    Ok(root)
}

/// Creates a minimal OCI image layout directory for testing using the ocidir crate.
///
/// Returns the path to the OCI layout directory.
pub(crate) fn create_oci_layout(parent: &Path) -> Result<PathBuf> {
    use cap_std_ext::cap_std;
    use ocidir::oci_spec::image::{
        ImageConfigurationBuilder, Platform, PlatformBuilder, RootFsBuilder,
    };

    let oci_dir = parent.join("oci-image");
    fs::create_dir_all(&oci_dir)?;

    let dir = cap_std::fs::Dir::open_ambient_dir(&oci_dir, cap_std::ambient_authority())?;
    let ocidir = ocidir::OciDir::ensure(dir)?;

    // Create a new empty manifest
    let mut manifest = ocidir.new_empty_manifest()?.build()?;

    // Create config with architecture and OS
    let rootfs = RootFsBuilder::default()
        .typ("layers")
        .diff_ids(Vec::<String>::new())
        .build()?;
    let mut config = ImageConfigurationBuilder::default()
        .architecture("amd64")
        .os("linux")
        .rootfs(rootfs)
        .build()?;

    // Create a layer with a minimal container rootfs (signing needs /usr to exist)
    let mut layer_builder = ocidir.create_layer(None)?;
    {
        // Directory entries that form a plausible container rootfs
        for dir in ["usr/", "usr/bin/", "etc/"] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(1234567890);
            header.set_cksum();
            layer_builder.append_data(&mut header, dir, &[] as &[u8])?;
        }

        let data = b"hello from test layer\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(1234567890);
        header.set_cksum();
        layer_builder.append_data(&mut header, "usr/bin/hello.txt", &data[..])?;
    }
    let layer = layer_builder.into_inner()?.complete()?;

    // Push the layer to manifest and config
    ocidir.push_layer(&mut manifest, &mut config, layer, "test layer", None);

    // Create platform for the manifest
    let platform: Platform = PlatformBuilder::default()
        .architecture("amd64")
        .os("linux")
        .build()?;

    // Insert manifest and config into the OCI directory
    ocidir.insert_manifest_and_config(manifest, config, None, platform)?;

    Ok(oci_dir)
}

fn main() {
    let args = Arguments::from_args();

    let tests: Vec<Trial> = INTEGRATION_TESTS
        .iter()
        .map(|t| {
            let f = t.f;
            Trial::test(t.name, move || f().map_err(|e| format!("{e:?}").into()))
        })
        .collect();

    libtest_mimic::run(&args, tests).exit();
}
