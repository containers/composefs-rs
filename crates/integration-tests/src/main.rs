//! Integration test runner for composefs-rs
//!
//! This binary runs integration tests using libtest-mimic for nextest compatibility.
//!
//! IMPORTANT: This binary may be re-executed via `podman unshare` to act as a
//! userns helper for rootless containers-storage access. The init_if_helper()
//! call at the start of main() handles this.

use anyhow::Result;
use integration_tests::{
    build_test_image, cleanup_test_image, create_test_repository, get_all_images, run_cfsctl,
};
use libtest_mimic::{Arguments, Failed, Trial};
use tempfile::TempDir;
use xshell::{cmd, Shell};

// ============================================================================
// Test implementations
// ============================================================================

fn test_cfsctl_version() -> Result<()> {
    let output = run_cfsctl(&["--version"])?;
    output.assert_success()?;
    assert!(
        output.stdout.contains("cfsctl") || output.stderr.contains("cfsctl"),
        "Version output should mention cfsctl"
    );
    Ok(())
}

fn test_cfsctl_help() -> Result<()> {
    let output = run_cfsctl(&["--help"])?;
    output.assert_success()?;
    assert!(
        output.stdout.contains("Usage") || output.stdout.contains("USAGE"),
        "Help should show usage"
    );
    Ok(())
}

/// Test that containers-storage import produces identical results to skopeo/tar import.
///
/// This is a critical correctness test: both import paths should produce the
/// exact same splitstream digests because they represent the same content.
fn test_cstor_vs_skopeo_equivalence() -> Result<()> {
    let sh = Shell::new()?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        println!("Building test image...");
        let test_image = build_test_image()?;
        println!("Built test image: {}", test_image);

        // Create two separate repositories for comparison
        let cstor_repo_dir = TempDir::new()?;
        let skopeo_repo_dir = TempDir::new()?;

        let cstor_repo = create_test_repository(&cstor_repo_dir)?;
        let skopeo_repo = create_test_repository(&skopeo_repo_dir)?;

        // Import via containers-storage (reflink path)
        let cstor_image_ref = format!("containers-storage:{}", test_image);
        println!("Importing via containers-storage: {}", cstor_image_ref);
        let cstor_result = composefs_oci::pull(&cstor_repo, &cstor_image_ref, None, None).await?;

        // Import via skopeo (tar streaming path) - copy to OCI directory first
        let oci_dir = TempDir::new()?;
        let oci_path = oci_dir.path().join("image");

        // Use skopeo to copy from containers-storage to oci directory
        // Strip sha256: prefix for skopeo compatibility
        let image_id_for_skopeo = test_image.strip_prefix("sha256:").unwrap_or(&test_image);
        let cstor_ref = format!("containers-storage:{}", image_id_for_skopeo);
        let oci_ref = format!("oci:{}:test", oci_path.display());
        println!("Copying to OCI dir via skopeo...");
        cmd!(sh, "skopeo copy {cstor_ref} {oci_ref}").run()?;

        // Import from the OCI directory via skopeo/tar path
        let skopeo_image_ref = format!("oci:{}:test", oci_path.display());
        println!("Importing via skopeo/OCI: {}", skopeo_image_ref);
        let skopeo_result =
            composefs_oci::pull(&skopeo_repo, &skopeo_image_ref, None, None).await?;

        // Get layer maps from both configs
        let (_cstor_config, cstor_layers) = composefs_oci::open_config(
            &cstor_repo,
            &cstor_result.config_digest,
            Some(&cstor_result.config_verity),
        )?;
        let (_skopeo_config, skopeo_layers) = composefs_oci::open_config(
            &skopeo_repo,
            &skopeo_result.config_digest,
            Some(&skopeo_result.config_verity),
        )?;

        // Compare results
        assert_eq!(
            cstor_result.config_digest, skopeo_result.config_digest,
            "config digests must match"
        );
        assert_eq!(cstor_layers, skopeo_layers, "layer verity IDs must match");
        assert_eq!(
            cstor_result.config_verity, skopeo_result.config_verity,
            "config verity IDs must match"
        );

        println!("SUCCESS: Both import paths produced identical digests");
        println!("  Config digest: {}", cstor_result.config_digest);
        println!("  Layers: {}", cstor_layers.len());

        // Cleanup
        cleanup_test_image(&test_image);

        Ok(())
    })
}

// Parameterized test - runs for each image
fn test_image_pull(image: &str) -> Result<()> {
    println!("Would test pulling image: {}", image);
    // TODO: implement actual image pull test
    Ok(())
}

/// All simple integration tests
fn get_simple_tests() -> Vec<(&'static str, fn() -> Result<()>)> {
    vec![
        ("test_cfsctl_version", test_cfsctl_version),
        ("test_cfsctl_help", test_cfsctl_help),
        (
            "test_cstor_vs_skopeo_equivalence",
            test_cstor_vs_skopeo_equivalence,
        ),
    ]
}

/// All parameterized tests (run for each image)
fn get_parameterized_tests() -> Vec<(&'static str, fn(&str) -> Result<()>)> {
    vec![("test_image_pull", test_image_pull)]
}

// ============================================================================
// Test harness main
// ============================================================================

fn main() {
    // CRITICAL: Handle userns helper re-execution.
    // When running rootless, this binary may be re-executed via `podman unshare`
    // to act as a helper process for containers-storage access.
    cstorage::init_if_helper();

    let args = Arguments::from_args();

    let mut trials = Vec::new();

    // Register simple tests
    for (name, test_fn) in get_simple_tests() {
        trials.push(Trial::test(name, move || {
            test_fn().map_err(|e| Failed::from(format!("{:?}", e)))
        }));
    }

    // Register parameterized tests
    let images = get_all_images();
    for (name, test_fn) in get_parameterized_tests() {
        for image in &images {
            let test_name = format!("{}::{}", name, image.rsplit('/').next().unwrap_or(image));
            let image = image.clone();
            trials.push(Trial::test(test_name, move || {
                test_fn(&image).map_err(|e| Failed::from(format!("{:?}", e)))
            }));
        }
    }

    libtest_mimic::run(&args, trials).exit();
}
