use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use composefs_experiments::repository::Repository;


/// cfsctl
#[derive(Debug, Parser)]
#[clap(name = "cfsctl", version)]
pub struct App {
    #[clap(long, group="repopath")]
    repo: Option<String>,
    #[clap(long, group="repopath")]
    user: bool,
    #[clap(long, group="repopath")]
    system: bool,

    #[clap(subcommand)]
    cmd: Command,
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
    /// Stores a tar file as a splitstream in the repository.
    ImportTar {
        reference: String,
        tarfile: Option<PathBuf>,
    },
    /// Lists the contents of a tar stream
    Ls {
        /// the name of the stream
        name: String,
    },
    /// Mounts a composefs, possibly enforcing fsverity of the image
    Mount {
        /// the name of the image to mount, either a sha256 digest or prefixed with 'ref/'
        name: String,
        /// the mountpoint
        mountpoint: String,
    },
}

fn main() -> Result<()> {
    let args = App::parse();

    let repo = (
        if let Some(path) = args.repo {
            Repository::open_path(path)
        } else if args.system {
            Repository::open_system()
        } else if args.user {
            Repository::open_user()
        } else if rustix::process::getuid().is_root() {
            Repository::open_system()
        } else {
            Repository::open_user()
        }
    )?;

    match args.cmd {
        Command::Transaction => {
            // just wait for ^C
            loop {
                std::thread::park();
            }
        },
        Command::Cat { name } => {
            repo.merge_splitstream(&name, &mut std::io::stdout())
        },
        Command::ImportImage { reference, } => {
            repo.import_image(&reference, &mut std::io::stdin())
        },
        Command::ImportTar { reference, tarfile: _ } => {
            repo.import_tar(&reference, &mut std::io::stdin())
        },
        Command::Ls { name } => {
            repo.ls(&name)
        },
        Command::Mount { name, mountpoint } => {
            repo.mount(&name, &mountpoint)
        },
        Command::GC => {
            repo.gc()
        }
    }
}