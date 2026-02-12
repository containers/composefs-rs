//! Command-line control utility for composefs repositories and images.
//!
//! `cfsctl` provides a comprehensive interface for managing composefs repositories,
//! creating and mounting filesystem images, handling OCI containers, and performing
//! repository maintenance operations like garbage collection.

use std::{
    fs::create_dir_all,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};

use rustix::fs::CWD;

use composefs_boot::{write_boot, BootOps};

use composefs::{
    fsverity::{FsVerityHashValue, Sha256HashValue, Sha512HashValue},
    repository::Repository,
};

/// cfsctl
#[derive(Debug, Parser)]
#[clap(name = "cfsctl", version)]
pub struct App {
    /// Operate on repo at path
    #[clap(long, group = "repopath")]
    repo: Option<PathBuf>,
    /// Operate on repo at standard user location $HOME/.var/lib/composefs
    #[clap(long, group = "repopath")]
    user: bool,
    /// Operate on repo at standard system location /sysroot/composefs
    #[clap(long, group = "repopath")]
    system: bool,

    /// What hash digest type to use for composefs repo
    #[clap(long, value_enum, default_value_t = HashType::Sha512)]
    hash: HashType,

    /// Sets the repository to insecure before running any operation and
    /// prepend '?' to the composefs kernel command line when writing
    /// boot entry.
    #[clap(long)]
    insecure: bool,

    /// Run in unprivileged mode (use FUSE mounting instead of kernel EROFS).
    /// Automatically enabled when running as non-root without CAP_SYS_ADMIN.
    #[clap(long)]
    unprivileged: bool,

    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum, Default)]
enum HashType {
    Sha256,
    #[default]
    Sha512,
}

/// Common options for operations using OCI config manifest streams that may transform the image rootfs
#[derive(Debug, Parser)]
struct OCIConfigFilesystemOptions {
    #[clap(flatten)]
    base_config: OCIConfigOptions,
    /// Whether bootable transformation should be performed on the image rootfs
    #[clap(long)]
    bootable: bool,
}

/// Common options for operations using OCI config manifest streams
#[derive(Debug, Parser)]
struct OCIConfigOptions {
    /// the name of the target OCI manifest stream, either a stream ID in format oci-config-<hash_type>:<hash_digest> or a reference in 'ref/'
    config_name: String,
    /// verity digest for the manifest stream to be verified against
    config_verity: Option<String>,
}

#[cfg(feature = "oci")]
#[derive(Debug, Subcommand)]
enum OciCommand {
    /// Stores a tar layer file as a splitstream in the repository.
    ImportLayer {
        digest: String,
        name: Option<String>,
    },
    /// Lists the contents of a tar stream
    LsLayer {
        /// the name of the stream to list, either a stream ID in format oci-config-<hash_type>:<hash_digest> or a reference in 'ref/'
        name: String,
    },
    /// Dump full content of the rootfs of a stored OCI image to a composefs dumpfile and write to stdout
    Dump {
        #[clap(flatten)]
        config_opts: OCIConfigFilesystemOptions,
    },
    /// Pull an OCI image to be stored in repo then prints the stream and verity digest of its manifest
    Pull {
        /// source image reference, as accepted by skopeo
        image: String,
        /// optional reference name for the manifest, use as 'ref/<name>' elsewhere
        name: Option<String>,
        /// Require a valid signature artifact for the pulled image
        #[clap(long)]
        require_signature: bool,
        /// Path to PEM-encoded trusted certificate for signature verification (required with --require-signature)
        #[clap(long)]
        trust_cert: Option<PathBuf>,
    },
    /// List all tagged OCI images in the repository
    #[clap(name = "images")]
    ListImages,
    /// Show information about an OCI image
    #[clap(name = "inspect")]
    Inspect {
        /// Image reference (tag name or manifest digest)
        image: String,
    },
    /// Tag an image with a new name
    Tag {
        /// Manifest digest (sha256:...)
        manifest_digest: String,
        /// Tag name to assign
        name: String,
    },
    /// Remove a tag from an image
    Untag {
        /// Tag name to remove
        name: String,
    },
    /// Compute the composefs image object id of the rootfs of a stored OCI image
    ComputeId {
        #[clap(flatten)]
        config_opts: OCIConfigFilesystemOptions,
    },
    /// Create the composefs image of the rootfs of a stored OCI image, commit it to the repo, and print its image object ID
    CreateImage {
        #[clap(flatten)]
        config_opts: OCIConfigFilesystemOptions,
        /// optional reference name for the image, use as 'ref/<name>' elsewhere
        #[clap(long)]
        image_name: Option<String>,
    },

    /// Create a composefs signature artifact for a sealed image
    Sign {
        /// Image reference (tag name)
        image: String,
        /// Path to PEM-encoded signing certificate
        #[clap(long)]
        cert: PathBuf,
        /// Path to PEM-encoded private key
        #[clap(long)]
        key: PathBuf,
    },
    /// Verify composefs signature artifacts for an image
    Verify {
        /// Image reference (tag name)
        image: String,
        /// Path to PEM-encoded trusted certificate for verification
        #[clap(long)]
        cert: Option<PathBuf>,
    },
    /// Export signature artifacts for an image to an OCI layout directory.
    /// This enables signature discovery when pulling from the OCI layout.
    ExportSignatures {
        /// Image reference (tag name)
        image: String,
        /// Path to the OCI layout directory (must already exist)
        oci_layout_path: PathBuf,
    },
    /// Mounts a stored and sealed OCI image by looking up its composefs image. Note that the composefs image must be built
    /// and committed to the repo first
    Mount {
        /// the name of the target OCI manifest stream, either a stream ID in format oci-config-<hash_type>:<hash_digest> or a reference in 'ref/'
        name: String,
        /// the mountpoint
        mountpoint: String,
    },
    /// Create the composefs image of the rootfs of a stored OCI image, perform bootable transformation, commit it to the repo,
    /// then configure boot for the image by writing new boot resources and bootloader entries to boot partition. Performs
    /// state preparation for composefs-setup-root consumption as well. Note that state preparation here is not suitable for
    /// consumption by bootc.
    PrepareBoot {
        #[clap(flatten)]
        config_opts: OCIConfigOptions,
        /// boot partition mount point
        #[clap(long, default_value = "/boot")]
        bootdir: PathBuf,
        /// Boot entry identifier to use. By default uses ID provided by the image or kernel version
        #[clap(long)]
        entry_id: Option<String>,
        /// additional kernel command line
        #[clap(long)]
        cmdline: Vec<String>,
    },
}

/// Common options for reading a filesystem from a path
#[derive(Debug, Parser)]
struct FsReadOptions {
    /// The path to the filesystem
    path: PathBuf,
    /// Transform the filesystem for boot (SELinux labels, empty /boot and /sysroot)
    #[clap(long)]
    bootable: bool,
    /// Don't copy /usr metadata to root directory (use if root already has well-defined metadata)
    #[clap(long)]
    no_propagate_usr_to_root: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Take a transaction lock on the repository.
    /// This prevents garbage collection from occurring.
    Transaction,
    /// Reconstitutes a split stream and writes it to stdout
    Cat {
        /// the name of the stream to cat, either a content identifier or prefixed with 'ref/'
        name: String,
    },
    /// Perform garbage collection
    GC {
        /// Additional roots to keep (image or stream names)
        #[clap(long, short = 'r')]
        root: Vec<String>,
        /// Preview what would be deleted without actually deleting
        #[clap(long, short = 'n')]
        dry_run: bool,
    },
    /// Imports a composefs image (unsafe!)
    ImportImage { reference: String },
    /// Commands for dealing with OCI images and layers
    #[cfg(feature = "oci")]
    Oci {
        #[clap(subcommand)]
        cmd: OciCommand,
    },
    /// Mounts a composefs image, possibly enforcing fsverity of the image
    Mount {
        /// the name of the image to mount, either an fs-verity hash or prefixed with 'ref/'
        name: String,
        /// the mountpoint
        mountpoint: String,
    },
    /// Read rootfs located at a path, add all files to the repo, then create the composefs image of the rootfs,
    /// commit it to the repo, and print its image object ID
    CreateImage {
        #[clap(flatten)]
        fs_opts: FsReadOptions,
        /// optional reference name for the image, use as 'ref/<name>' elsewhere
        image_name: Option<String>,
    },
    /// Read rootfs located at a path, add all files to the repo, then compute the composefs image object id of the rootfs.
    /// Note that this does not create or commit the composefs image itself.
    ComputeId {
        #[clap(flatten)]
        fs_opts: FsReadOptions,
    },
    /// Read rootfs located at a path, add all files to the repo, then dump full content of the rootfs to a composefs dumpfile
    /// and write to stdout.
    CreateDumpfile {
        #[clap(flatten)]
        fs_opts: FsReadOptions,
    },
    /// Lists all object IDs referenced by an image
    ImageObjects {
        /// the name of the image to read, either an object ID digest or prefixed with 'ref/'
        name: String,
    },
    #[cfg(feature = "http")]
    Fetch { url: String, name: String },
    /// Commands for managing the kernel keyring (requires root)
    Keyring {
        #[clap(subcommand)]
        cmd: KeyringCommand,
    },
}

#[derive(Debug, Subcommand)]
enum KeyringCommand {
    /// Add a CA certificate to the kernel's .fs-verity keyring
    ///
    /// This allows the kernel to require valid PKCS#7 signatures when enabling
    /// fs-verity on files. Requires CAP_SYS_ADMIN (root).
    AddCert {
        /// Path to a PEM-encoded X.509 certificate file
        cert: PathBuf,
    },
}

fn verity_opt<ObjectID>(opt: &Option<String>) -> Result<Option<ObjectID>>
where
    ObjectID: FsVerityHashValue,
{
    Ok(match opt {
        Some(value) => Some(FsVerityHashValue::from_hex(value)?),
        None => None,
    })
}

fn open_repo<ObjectID>(args: &App) -> Result<Repository<ObjectID>>
where
    ObjectID: FsVerityHashValue,
{
    let mut repo = (if let Some(path) = &args.repo {
        Repository::open_path(CWD, path)
    } else if args.system {
        Repository::open_system()
    } else if args.user {
        Repository::open_user()
    } else if rustix::process::getuid().is_root() {
        Repository::open_system()
    } else {
        Repository::open_user()
    })?;

    repo.set_insecure(args.insecure);

    // Auto-detect privilege level if not explicitly set
    if args.unprivileged {
        repo.set_privileged(false);
    } else {
        repo.set_privileged(rustix::process::getuid().is_root());
    }

    Ok(repo)
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = App::parse();

    // Handle commands that don't need a repository first
    if let Command::Keyring { ref cmd } = args.cmd {
        return run_keyring_cmd(cmd);
    }

    match args.hash {
        HashType::Sha256 => run_cmd_with_repo(open_repo::<Sha256HashValue>(&args)?, args).await,
        HashType::Sha512 => run_cmd_with_repo(open_repo::<Sha512HashValue>(&args)?, args).await,
    }
}

fn run_keyring_cmd(cmd: &KeyringCommand) -> Result<()> {
    match cmd {
        KeyringCommand::AddCert { cert } => {
            use anyhow::Context;
            let cert_pem = std::fs::read(cert).context("failed to read certificate file")?;
            composefs::fsverity::inject_fsverity_cert(&cert_pem)?;
            println!("Certificate added to .fs-verity keyring");
        }
    }
    Ok(())
}

async fn run_cmd_with_repo<ObjectID>(repo: Repository<ObjectID>, args: App) -> Result<()>
where
    ObjectID: FsVerityHashValue,
{
    match args.cmd {
        Command::Transaction => {
            // just wait for ^C
            loop {
                std::thread::park();
            }
        }
        Command::Cat { name } => {
            repo.merge_splitstream(&name, None, None, &mut std::io::stdout())?;
        }
        Command::ImportImage { reference } => {
            let image_id = repo.import_image(&reference, &mut std::io::stdin())?;
            println!("{}", image_id.to_id());
        }
        #[cfg(feature = "oci")]
        Command::Oci { cmd: oci_cmd } => match oci_cmd {
            OciCommand::ImportLayer { name, digest } => {
                let object_id = composefs_oci::import_layer(
                    &Arc::new(repo),
                    &digest,
                    name.as_deref(),
                    &mut std::io::stdin(),
                )?;
                println!("{}", object_id.to_id());
            }
            OciCommand::LsLayer { name } => {
                composefs_oci::ls_layer(&repo, &name)?;
            }
            OciCommand::Dump {
                config_opts:
                    OCIConfigFilesystemOptions {
                        base_config:
                            OCIConfigOptions {
                                ref config_name,
                                ref config_verity,
                            },
                        bootable,
                    },
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(&repo, config_name, verity.as_ref())?;
                if bootable {
                    fs.transform_for_boot(&repo)?;
                }
                fs.print_dumpfile()?;
            }
            OciCommand::ComputeId {
                config_opts:
                    OCIConfigFilesystemOptions {
                        base_config:
                            OCIConfigOptions {
                                ref config_name,
                                ref config_verity,
                            },
                        bootable,
                    },
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(&repo, config_name, verity.as_ref())?;
                if bootable {
                    fs.transform_for_boot(&repo)?;
                }
                let id = fs.compute_image_id();
                println!("{}", id.to_hex());
            }
            OciCommand::CreateImage {
                config_opts:
                    OCIConfigFilesystemOptions {
                        base_config:
                            OCIConfigOptions {
                                ref config_name,
                                ref config_verity,
                            },
                        bootable,
                    },
                ref image_name,
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(&repo, config_name, verity.as_ref())?;
                if bootable {
                    fs.transform_for_boot(&repo)?;
                }
                let image_id = fs.commit_image(&repo, image_name.as_deref())?;
                println!("{}", image_id.to_id());
            }
            OciCommand::Pull {
                ref image,
                name,
                require_signature,
                ref trust_cert,
            } => {
                use anyhow::Context;

                // If requiring signature, we must have a trust cert
                if require_signature && trust_cert.is_none() {
                    anyhow::bail!(
                        "--require-signature requires --trust-cert to specify the trusted certificate"
                    );
                }

                // If no explicit name provided, use the image reference as the tag
                let tag_name = name.as_deref().unwrap_or(image);
                let repo = Arc::new(repo);
                let result =
                    composefs_oci::pull_image(&repo, image, Some(tag_name), None).await?;

                println!("manifest {}", result.manifest_digest);
                println!("config   {}", result.config_digest);
                println!("verity   {}", result.manifest_verity.to_hex());
                println!("tagged   {tag_name}");

                // Verify signature if required
                if require_signature {
                    let cert_path = trust_cert.as_ref().unwrap();
                    let cert_pem = std::fs::read(cert_path)
                        .with_context(|| format!("failed to read certificate file: {cert_path:?}"))?;
                    let verifier = composefs_oci::signing::FsVeritySignatureVerifier::from_pem(&cert_pem)?;

                    let img = composefs_oci::OciImage::open_ref(&repo, tag_name)?;
                    let manifest_digest = img.manifest_digest().to_string();

                    // If pulling from an OCI layout, import signature artifacts from there first
                    if let Some(oci_path) = image.strip_prefix("oci:") {
                        // Parse the path:tag format (e.g., "/path/to/layout:latest")
                        let layout_path = if let Some(colon_idx) = oci_path.rfind(':') {
                            &oci_path[..colon_idx]
                        } else {
                            oci_path
                        };

                        let imported = composefs_oci::oci_image::import_referrers_from_oci_layout(
                            &repo,
                            std::path::Path::new(layout_path),
                            &manifest_digest,
                            composefs_oci::signature::ARTIFACT_TYPE,
                        )?;

                        if imported > 0 {
                            // Silently imported signatures
                        }
                    }

                    // Find signature artifact manifests via the referrer index
                    let referrers =
                        composefs_oci::oci_image::list_referrers(&repo, &manifest_digest)?;

                    if referrers.is_empty() {
                        anyhow::bail!(
                            "no signature artifacts found for {image}; --require-signature was specified"
                        );
                    }

                    // Recompute expected digests for verification
                    let config_digest = img.config_digest().to_string();
                    let per_layer_digests =
                        composefs_oci::compute_per_layer_digests(&repo, &config_digest, None)?;
                    let merged_digest: ObjectID =
                        composefs_oci::compute_merged_digest(&repo, &config_digest, None)?;
                    let merged_hex = merged_digest.to_hex();

                    // Determine algorithm from ObjectID
                    let algorithm = ObjectID::ALGORITHM;

                    let mut verified_count = 0usize;
                    let mut any_verification_failed = false;
                    let mut found_composefs_artifact = false;

                    for (artifact_digest, artifact_verity) in &referrers {
                        // Open the artifact as an OciImage to access layer blobs
                        let artifact_image = composefs_oci::OciImage::open(&repo, artifact_digest, Some(artifact_verity))
                            .with_context(|| format!("opening referrer artifact {artifact_digest}"))?;

                        // Check if this is a composefs signature artifact
                        let artifact_manifest = artifact_image.manifest();
                        match artifact_manifest.artifact_type() {
                            Some(oci_spec::image::MediaType::Other(t))
                                if t == composefs_oci::signature::ARTIFACT_TYPE => {}
                            _ => continue, // Skip non-composefs artifacts
                        }

                        found_composefs_artifact = true;

                        // Parse the artifact manifest to get entry metadata
                        let parsed = composefs_oci::signature::parse_signature_artifact(artifact_manifest)
                            .with_context(|| format!("parsing signature artifact {artifact_digest}"))?;

                        println!("\nVerifying signature artifact (algorithm: {})", parsed.algorithm);

                        // Iterate over layers and entries together
                        let layer_descriptors = artifact_image.layer_descriptors();
                        let mut layer_idx = 0usize;

                        for (entry_idx, entry) in parsed.entries.iter().enumerate() {
                            let (label, expected_hex) = match entry.sig_type {
                                composefs_oci::signature::SignatureType::Layer => {
                                    let lbl = format!("  layer[{layer_idx}]:");
                                    let expected = per_layer_digests.get(layer_idx).map(|d| d.to_hex());
                                    layer_idx += 1;
                                    (lbl, expected)
                                }
                                composefs_oci::signature::SignatureType::Merged => {
                                    ("  merged:  ".to_string(), Some(merged_hex.clone()))
                                }
                                other => {
                                    println!("  {other}: skipped (not verified)");
                                    continue;
                                }
                            };

                            // Check digest matches
                            let digest_ok = match &expected_hex {
                                Some(expected) => *expected == entry.digest,
                                None => {
                                    println!("{label} no expected digest to compare - SKIP");
                                    continue;
                                }
                            };

                            if !digest_ok {
                                println!("{label} digest MISMATCH");
                                any_verification_failed = true;
                                continue;
                            }

                            // Get the layer descriptor for this entry to fetch signature blob
                            let layer_desc = layer_descriptors.get(entry_idx).context(
                                "layer descriptor index out of bounds",
                            )?;
                            let blob_digest = layer_desc.digest().to_string();

                            // Check if there's actually a signature (non-zero size)
                            if layer_desc.size() == 0 {
                                println!("{label} digest matches but no signature blob");
                                any_verification_failed = true;
                                continue;
                            }

                            // Fetch the signature blob
                            let blob_verity = artifact_image.layer_verity(&blob_digest)
                                .ok_or_else(|| anyhow::anyhow!("layer verity not found for {blob_digest}"))?;
                            let signature_blob = composefs_oci::oci_image::open_blob(
                                &repo,
                                &blob_digest,
                                Some(blob_verity),
                            )?;

                            // Verify the signature
                            let digest_bytes = hex::decode(&entry.digest)
                                .context("invalid hex digest in signature entry")?;

                            match verifier.verify_raw(&signature_blob, algorithm, &digest_bytes) {
                                Ok(()) => {
                                    println!("{label} signature verified ✓");
                                    verified_count += 1;
                                }
                                Err(e) => {
                                    println!("{label} signature INVALID: {e}");
                                    any_verification_failed = true;
                                }
                            }
                        }
                    }

                    if !found_composefs_artifact {
                        anyhow::bail!(
                            "no composefs signature artifacts found for {image}; --require-signature was specified"
                        );
                    }

                    if any_verification_failed || verified_count == 0 {
                        anyhow::bail!(
                            "signature verification failed; verified {} signatures",
                            verified_count
                        );
                    }

                    println!("\nSignature verification passed ({verified_count} signatures verified)");
                }
            }
            OciCommand::ListImages => {
                let images = composefs_oci::oci_image::list_images(&repo)?;

                if images.is_empty() {
                    println!("No images found");
                } else {
                    println!(
                        "{:<30} {:<12} {:<10} {:<6}",
                        "NAME", "DIGEST", "ARCH", "LAYERS"
                    );
                    for img in images {
                        let digest_short = img
                            .manifest_digest
                            .strip_prefix("sha256:")
                            .unwrap_or(&img.manifest_digest);
                        let digest_display = if digest_short.len() > 12 {
                            &digest_short[..12]
                        } else {
                            digest_short
                        };
                        println!(
                            "{:<30} {:<12} {:<10} {:<6}",
                            img.name,
                            digest_display,
                            if img.architecture.is_empty() {
                                "artifact"
                            } else {
                                &img.architecture
                            },
                            img.layer_count
                        );
                    }
                }
            }
            OciCommand::Inspect { ref image } => {
                let img = if image.starts_with("sha256:") {
                    composefs_oci::oci_image::OciImage::open(&repo, image, None)?
                } else {
                    composefs_oci::oci_image::OciImage::open_ref(&repo, image)?
                };

                println!("Manifest:     {}", img.manifest_digest());
                println!("Config:       {}", img.config_digest());
                println!(
                    "Type:         {}",
                    if img.is_container_image() {
                        "container"
                    } else {
                        "artifact"
                    }
                );

                if img.is_container_image() {
                    println!("Architecture: {}", img.architecture());
                    println!("OS:           {}", img.os());
                }

                if let Some(created) = img.created() {
                    println!("Created:      {created}");
                }

                println!("Layers:       {}", img.layer_descriptors().len());
                for (i, layer) in img.layer_descriptors().iter().enumerate() {
                    println!("  [{i}] {} ({} bytes)", layer.digest(), layer.size());
                }

                if let Some(labels) = img.labels() {
                    if !labels.is_empty() {
                        println!("Labels:");
                        for (k, v) in labels {
                            println!("  {k}: {v}");
                        }
                    }
                }
            }
            OciCommand::Tag {
                ref manifest_digest,
                ref name,
            } => {
                composefs_oci::oci_image::tag_image(&repo, manifest_digest, name)?;
                println!("Tagged {manifest_digest} as {name}");
            }
            OciCommand::Untag { ref name } => {
                composefs_oci::oci_image::untag_image(&repo, name)?;
                println!("Removed tag {name}");
            }

            OciCommand::Sign {
                ref image,
                ref cert,
                ref key,
            } => {
                use anyhow::Context;
                use std::str::FromStr;

                let repo = Arc::new(repo);
                let img = composefs_oci::OciImage::open_ref(&repo, image)?;

                anyhow::ensure!(
                    img.is_container_image(),
                    "can only sign container images, not artifacts"
                );

                let config_digest = img.config_digest().to_string();

                // Compute merged digest directly from the image layers
                let merged_digest: ObjectID =
                    composefs_oci::compute_merged_digest(&repo, &config_digest, None)?;

                // Determine the composefs algorithm from ObjectID::ALGORITHM
                let algorithm = match ObjectID::ALGORITHM {
                    1 => composefs::fsverity::algorithm::SHA256_12,
                    2 => composefs::fsverity::algorithm::SHA512_12,
                    _ => anyhow::bail!("unsupported hash algorithm {}", ObjectID::ALGORITHM),
                };

                // Compute per-layer digests (verifies content hashes since we don't
                // have the config verity readily available from OciImage)
                let per_layer_digests =
                    composefs_oci::compute_per_layer_digests(&repo, &config_digest, None)?;

                // Load signing key
                let cert_pem = std::fs::read(cert).context("failed to read certificate file")?;
                let key_pem = std::fs::read(key).context("failed to read private key file")?;
                let signing_key =
                    composefs_oci::signing::FsVeritySigningKey::from_pem(&cert_pem, &key_pem)?;

                // Build subject descriptor from the source image's manifest
                let manifest_json = img.manifest().to_string()?;
                let subject = oci_spec::image::DescriptorBuilder::default()
                    .media_type(oci_spec::image::MediaType::ImageManifest)
                    .digest(
                        oci_spec::image::Digest::from_str(img.manifest_digest())
                            .context("parsing manifest digest")?,
                    )
                    .size(manifest_json.len() as u64)
                    .build()
                    .context("building subject descriptor")?;

                let mut builder =
                    composefs_oci::signature::SignatureArtifactBuilder::new(algorithm, subject);

                // Sign and add each per-layer digest
                for digest in &per_layer_digests {
                    let sig = signing_key.sign(digest)?;
                    builder.add_entry(composefs_oci::signature::SignatureEntry {
                        sig_type: composefs_oci::signature::SignatureType::Layer,
                        digest: digest.to_hex(),
                        signature: Some(sig),
                    })?;
                }

                // Sign and add the merged digest
                let merged_sig = signing_key.sign(&merged_digest)?;
                builder.add_entry(composefs_oci::signature::SignatureEntry {
                    sig_type: composefs_oci::signature::SignatureType::Merged,
                    digest: merged_digest.to_hex(),
                    signature: Some(merged_sig),
                })?;

                let artifact = builder.build()?;
                let (artifact_digest, _) =
                    composefs_oci::signature::store_signature_artifact(&repo, artifact)?;

                println!("{artifact_digest}");
            }
            OciCommand::Verify {
                ref image,
                ref cert,
            } => {
                use anyhow::Context;

                let img = composefs_oci::OciImage::open_ref(&repo, image)?;
                let manifest_digest = img.manifest_digest().to_string();

                // Find signature artifact manifests via the referrer index
                let referrers =
                    composefs_oci::oci_image::list_referrers(&repo, &manifest_digest)?;

                if referrers.is_empty() {
                    anyhow::bail!("no signature artifacts found for {image}");
                }

                // Load verifier if cert is provided
                let verifier = match cert {
                    Some(cert_path) => {
                        let cert_pem = std::fs::read(cert_path)
                            .with_context(|| format!("failed to read certificate file: {cert_path:?}"))?;
                        Some(composefs_oci::signing::FsVeritySignatureVerifier::from_pem(&cert_pem)?)
                    }
                    None => None,
                };

                // Recompute expected digests
                let config_digest = img.config_digest().to_string();
                let per_layer_digests =
                    composefs_oci::compute_per_layer_digests(&repo, &config_digest, None)?;
                let merged_digest: ObjectID =
                    composefs_oci::compute_merged_digest(&repo, &config_digest, None)?;
                let merged_hex = merged_digest.to_hex();

                // Determine algorithm from ObjectID
                let algorithm = ObjectID::ALGORITHM;

                let mut all_ok = true;
                let mut found_composefs_artifact = false;
                let mut verified_count = 0usize;

                for (artifact_digest, artifact_verity) in &referrers {
                    // Open the artifact as an OciImage to access layer blobs
                    let artifact_image = composefs_oci::OciImage::open(&repo, artifact_digest, Some(artifact_verity))
                        .with_context(|| format!("opening referrer artifact {artifact_digest}"))?;

                    // Check if this is a composefs signature artifact
                    let artifact_manifest = artifact_image.manifest();
                    match artifact_manifest.artifact_type() {
                        Some(oci_spec::image::MediaType::Other(t))
                            if t == composefs_oci::signature::ARTIFACT_TYPE => {}
                        _ => continue, // Skip non-composefs artifacts
                    }

                    found_composefs_artifact = true;

                    // Parse the artifact manifest to get entry metadata
                    let parsed = composefs_oci::signature::parse_signature_artifact(artifact_manifest)
                        .with_context(|| format!("parsing signature artifact {artifact_digest}"))?;

                    println!("Signature artifact (algorithm: {})", parsed.algorithm);

                    // Iterate over layers and entries together
                    let layer_descriptors = artifact_image.layer_descriptors();
                    let mut layer_idx = 0usize;

                    for (entry_idx, entry) in parsed.entries.iter().enumerate() {
                        let (label, expected_hex) = match entry.sig_type {
                            composefs_oci::signature::SignatureType::Layer => {
                                let lbl = format!("  layer[{layer_idx}]:");
                                let expected = per_layer_digests.get(layer_idx).map(|d| d.to_hex());
                                layer_idx += 1;
                                (lbl, expected)
                            }
                            composefs_oci::signature::SignatureType::Merged => {
                                ("  merged:  ".to_string(), Some(merged_hex.clone()))
                            }
                            other => {
                                println!("  {other}: skipped (not verified by this tool)");
                                continue;
                            }
                        };

                        let digest_ok = match &expected_hex {
                            Some(expected) => *expected == entry.digest,
                            None => {
                                print!("{label} no expected digest to compare");
                                println!(" SKIP");
                                all_ok = false;
                                continue;
                            }
                        };

                        if !digest_ok {
                            println!("{label} digest MISMATCH");
                            all_ok = false;
                            continue;
                        }

                        // If verifier is available, fetch the signature blob and verify
                        if let Some(ref verifier) = verifier {
                            // Get the layer descriptor for this entry
                            let layer_desc = layer_descriptors.get(entry_idx).context(
                                "layer descriptor index out of bounds",
                            )?;
                            let blob_digest = layer_desc.digest().to_string();

                            // Check if there's actually a signature (non-zero size)
                            if layer_desc.size() == 0 {
                                println!("{label} digest matches but no signature blob");
                                all_ok = false;
                                continue;
                            }

                            // Fetch the signature blob
                            let blob_verity = artifact_image.layer_verity(&blob_digest)
                                .ok_or_else(|| anyhow::anyhow!("layer verity not found for {blob_digest}"))?;
                            let signature_blob = composefs_oci::oci_image::open_blob(
                                &repo,
                                &blob_digest,
                                Some(blob_verity),
                            )?;

                            // Verify the signature
                            let digest_bytes = hex::decode(&entry.digest)
                                .context("invalid hex digest in signature entry")?;

                            match verifier.verify_raw(&signature_blob, algorithm, &digest_bytes) {
                                Ok(()) => {
                                    println!("{label} signature verified ✓");
                                    verified_count += 1;
                                }
                                Err(e) => {
                                    println!("{label} signature INVALID: {e}");
                                    all_ok = false;
                                }
                            }
                        } else {
                            // No verifier - just report digest match
                            println!("{label} digest matches ✓");
                        }
                    }
                }

                if !found_composefs_artifact {
                    anyhow::bail!("no composefs signature artifacts found for {image}");
                }

                if !all_ok {
                    std::process::exit(1);
                }

                if verifier.is_some() {
                    println!("\nSignature verification passed ({verified_count} signatures verified)");
                }
            }
            OciCommand::ExportSignatures {
                ref image,
                ref oci_layout_path,
            } => {
                use anyhow::Context;

                let img = composefs_oci::OciImage::open_ref(&repo, image)?;
                let manifest_digest = img.manifest_digest();

                let count = composefs_oci::export_referrers_to_oci_layout(
                    &repo,
                    manifest_digest,
                    oci_layout_path,
                )
                .context("exporting signatures to OCI layout")?;

                if count == 0 {
                    println!("No signature artifacts found for {image}");
                } else {
                    println!(
                        "Exported {count} signature artifact(s) to {}",
                        oci_layout_path.display()
                    );
                }
            }
            OciCommand::Mount {
                ref name,
                ref mountpoint,
            } => {
                composefs_oci::mount(&repo, name, mountpoint, None)?;
            }
            OciCommand::PrepareBoot {
                config_opts:
                    OCIConfigOptions {
                        ref config_name,
                        ref config_verity,
                    },
                ref bootdir,
                ref entry_id,
                ref cmdline,
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(&repo, config_name, verity.as_ref())?;
                let entries = fs.transform_for_boot(&repo)?;
                let id = fs.commit_image(&repo, None)?;

                let Some(entry) = entries.into_iter().next() else {
                    anyhow::bail!("No boot entries!");
                };

                let cmdline_refs: Vec<&str> = cmdline.iter().map(String::as_str).collect();
                write_boot::write_boot_simple(
                    &repo,
                    entry,
                    &id,
                    args.insecure,
                    bootdir,
                    None,
                    entry_id.as_deref(),
                    &cmdline_refs,
                )?;

                let state = args
                    .repo
                    .as_ref()
                    .map(|p: &PathBuf| p.parent().unwrap())
                    .unwrap_or(Path::new("/sysroot"))
                    .join("state/deploy")
                    .join(id.to_hex());

                create_dir_all(state.join("var"))?;
                create_dir_all(state.join("etc/upper"))?;
                create_dir_all(state.join("etc/work"))?;
            }
        },
        Command::ComputeId { fs_opts } => {
            let mut fs = if fs_opts.no_propagate_usr_to_root {
                composefs::fs::read_filesystem(CWD, &fs_opts.path, Some(&repo))?
            } else {
                composefs::fs::read_container_root(CWD, &fs_opts.path, Some(&repo))?
            };
            if fs_opts.bootable {
                fs.transform_for_boot(&repo)?;
            }
            let id = fs.compute_image_id();
            println!("{}", id.to_hex());
        }
        Command::CreateImage {
            fs_opts,
            ref image_name,
        } => {
            let mut fs = if fs_opts.no_propagate_usr_to_root {
                composefs::fs::read_filesystem(CWD, &fs_opts.path, Some(&repo))?
            } else {
                composefs::fs::read_container_root(CWD, &fs_opts.path, Some(&repo))?
            };
            if fs_opts.bootable {
                fs.transform_for_boot(&repo)?;
            }
            let id = fs.commit_image(&repo, image_name.as_deref())?;
            println!("{}", id.to_id());
        }
        Command::CreateDumpfile { fs_opts } => {
            let mut fs = if fs_opts.no_propagate_usr_to_root {
                composefs::fs::read_filesystem(CWD, &fs_opts.path, Some(&repo))?
            } else {
                composefs::fs::read_container_root(CWD, &fs_opts.path, Some(&repo))?
            };
            if fs_opts.bootable {
                fs.transform_for_boot(&repo)?;
            }
            fs.print_dumpfile()?;
        }
        Command::Mount { name, mountpoint } => {
            repo.mount_at(&name, &mountpoint)?;
        }
        Command::ImageObjects { name } => {
            let objects = repo.objects_for_image(&name)?;
            for object in objects {
                println!("{}", object.to_id());
            }
        }
        Command::GC { root, dry_run } => {
            let roots: Vec<&str> = root.iter().map(|s| s.as_str()).collect();
            let result = if dry_run {
                repo.gc_dry_run(&roots)?
            } else {
                repo.gc(&roots)?
            };
            if dry_run {
                println!("Dry run (no files deleted):");
            }
            println!(
                "Objects: {} removed ({} bytes)",
                result.objects_removed, result.objects_bytes
            );
            if result.images_pruned > 0 || result.streams_pruned > 0 {
                println!(
                    "Pruned symlinks: {} images, {} streams",
                    result.images_pruned, result.streams_pruned
                );
            }
        }
        Command::Keyring { .. } => {
            // Handled in main() before opening the repository
            unreachable!("Keyring command should be handled before opening repo");
        }
        #[cfg(feature = "http")]
        Command::Fetch { url, name } => {
            let (digest, verity) = composefs_http::download(&url, &name, Arc::new(repo)).await?;
            println!("content {digest}");
            println!("verity {}", verity.to_hex());
        }
    }
    Ok(())
}
