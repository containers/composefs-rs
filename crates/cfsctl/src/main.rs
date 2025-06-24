use std::{
    fs::create_dir_all,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;
use clap::{Parser, Subcommand};

use rustix::fs::CWD;

use composefs_boot::{write_boot, BootOps};

use composefs::{
    fsverity::{FsVerityHashValue, Sha256HashValue},
    repository::Repository,
};

/// cfsctl
#[derive(Debug, Parser)]
#[clap(name = "cfsctl", version)]
pub struct App {
    #[clap(long, group = "repopath")]
    repo: Option<PathBuf>,
    #[clap(long, group = "repopath")]
    user: bool,
    #[clap(long, group = "repopath")]
    system: bool,

    /// Sets the repository to insecure before running any operation and
    /// prepend '?' to the composefs kernel command line when writing
    /// boot entry.
    #[clap(long)]
    insecure: bool,

    #[clap(subcommand)]
    cmd: Command,
}

#[cfg(feature = "oci")]
#[derive(Debug, Subcommand)]
enum OciCommand {
    /// Stores a tar file as a splitstream in the repository.
    ImportLayer {
        sha256: String,
        name: Option<String>,
    },
    /// Lists the contents of a tar stream
    LsLayer {
        /// the name of the stream
        name: String,
    },
    Dump {
        config_name: String,
        config_verity: Option<String>,
    },
    Pull {
        image: String,
        name: Option<String>,
    },
    ComputeId {
        config_name: String,
        config_verity: Option<String>,
        #[clap(long)]
        bootable: bool,
    },
    CreateImage {
        config_name: String,
        config_verity: Option<String>,
        #[clap(long)]
        bootable: bool,
        #[clap(long)]
        image_name: Option<String>,
    },
    Seal {
        config_name: String,
        config_verity: Option<String>,
    },
    Mount {
        name: String,
        mountpoint: String,
    },
    PrepareBoot {
        config_name: String,
        config_verity: Option<String>,
        #[clap(long, default_value = "/boot")]
        bootdir: PathBuf,
        #[clap(long)]
        entry_id: Option<String>,
        #[clap(long)]
        cmdline: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Take a transaction lock on the repository.
    /// This prevents garbage collection from occurring.
    Transaction,
    /// Reconstitutes a split stream and writes it to stdout
    Cat {
        /// the name of the stream to cat, either a sha256 digest or prefixed with 'ref/'
        name: String,
    },
    /// Perform garbage collection
    GC,
    /// Imports a composefs image (unsafe!)
    ImportImage {
        reference: String,
    },
    /// Commands for dealing with OCI layers
    #[cfg(feature = "oci")]
    Oci {
        #[clap(subcommand)]
        cmd: OciCommand,
    },
    /// Mounts a composefs, possibly enforcing fsverity of the image
    Mount {
        /// the name of the image to mount, either a sha256 digest or prefixed with 'ref/'
        name: String,
        /// the mountpoint
        mountpoint: String,
    },
    CreateImage {
        path: PathBuf,
        #[clap(long)]
        bootable: bool,
        #[clap(long)]
        stat_root: bool,
        image_name: Option<String>,
    },
    ComputeId {
        path: PathBuf,
        #[clap(long)]
        bootable: bool,
        #[clap(long)]
        stat_root: bool,
    },
    CreateDumpfile {
        path: PathBuf,
        #[clap(long)]
        bootable: bool,
        #[clap(long)]
        stat_root: bool,
    },
    ImageObjects {
        name: String,
    },
    #[cfg(feature = "http")]
    Fetch {
        url: String,
        name: String,
    },
}

fn verity_opt(opt: &Option<String>) -> Result<Option<Sha256HashValue>> {
    Ok(match opt {
        Some(value) => Some(FsVerityHashValue::from_hex(value)?),
        None => None,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = App::parse();

    let mut repo: Repository<Sha256HashValue> = (if let Some(path) = &args.repo {
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

    match args.cmd {
        Command::Transaction => {
            // just wait for ^C
            loop {
                std::thread::park();
            }
        }
        Command::Cat { name } => {
            repo.merge_splitstream(&name, None, &mut std::io::stdout())?;
        }
        Command::ImportImage { reference } => {
            let image_id = repo.import_image(&reference, &mut std::io::stdin())?;
            println!("{}", image_id.to_id());
        }
        #[cfg(feature = "oci")]
        Command::Oci { cmd: oci_cmd } => match oci_cmd {
            OciCommand::ImportLayer { name, sha256 } => {
                let object_id = composefs_oci::import_layer(
                    &Arc::new(repo),
                    &composefs::util::parse_sha256(sha256)?,
                    name.as_deref(),
                    &mut std::io::stdin(),
                )?;
                println!("{}", object_id.to_id());
            }
            OciCommand::LsLayer { name } => {
                composefs_oci::ls_layer(&repo, &name)?;
            }
            OciCommand::Dump {
                ref config_name,
                ref config_verity,
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(&repo, config_name, verity.as_ref())?;
                fs.print_dumpfile()?;
            }
            OciCommand::ComputeId {
                ref config_name,
                ref config_verity,
                bootable,
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
                ref config_name,
                ref config_verity,
                bootable,
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
            OciCommand::Pull { ref image, name } => {
                let (sha256, verity) =
                    composefs_oci::pull(&Arc::new(repo), image, name.as_deref()).await?;

                println!("sha256 {}", hex::encode(sha256));
                println!("verity {}", verity.to_hex());
            }
            OciCommand::Seal {
                ref config_name,
                ref config_verity,
            } => {
                let verity = verity_opt(config_verity)?;
                let (sha256, verity) =
                    composefs_oci::seal(&Arc::new(repo), config_name, verity.as_ref())?;
                println!("sha256 {}", hex::encode(sha256));
                println!("verity {}", verity.to_id());
            }
            OciCommand::Mount {
                ref name,
                ref mountpoint,
            } => {
                composefs_oci::mount(&repo, name, mountpoint, None)?;
            }
            OciCommand::PrepareBoot {
                ref config_name,
                ref config_verity,
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
                    .join("state")
                    .join(id.to_hex());

                create_dir_all(state.join("var"))?;
                create_dir_all(state.join("etc/upper"))?;
                create_dir_all(state.join("etc/work"))?;
            }
        },
        Command::ComputeId {
            ref path,
            bootable,
            stat_root,
        } => {
            let mut fs = composefs::fs::read_filesystem(CWD, path, Some(&repo), stat_root)?;
            if bootable {
                fs.transform_for_boot(&repo)?;
            }
            let id = fs.compute_image_id();
            println!("{}", id.to_hex());
        }
        Command::CreateImage {
            ref path,
            bootable,
            stat_root,
            ref image_name,
        } => {
            let mut fs = composefs::fs::read_filesystem(CWD, path, Some(&repo), stat_root)?;
            if bootable {
                fs.transform_for_boot(&repo)?;
            }
            let id = fs.commit_image(&repo, image_name.as_deref())?;
            println!("{}", id.to_id());
        }
        Command::CreateDumpfile {
            ref path,
            bootable,
            stat_root,
        } => {
            let mut fs = composefs::fs::read_filesystem(CWD, path, Some(&repo), stat_root)?;
            if bootable {
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
        Command::GC => {
            repo.gc()?;
        }
        #[cfg(feature = "http")]
        Command::Fetch { url, name } => {
            let (sha256, verity) = composefs_http::download(&url, &name, Arc::new(repo)).await?;
            println!("sha256 {}", hex::encode(sha256));
            println!("verity {}", verity.to_hex());
        }
    }
    Ok(())
}
