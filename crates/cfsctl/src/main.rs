//! Command-line control utility for composefs repositories and images.
//!
//! `cfsctl` is a multi-call binary: when invoked as `mkcomposefs` or
//! `composefs-info` (via symlink or hardlink), it dispatches to the
//! corresponding tool. Otherwise it runs the normal `cfsctl` interface.

use std::path::Path;

use anyhow::Result;

mod composefs_info;
mod mkcomposefs;

/// Extract the binary name from argv[0], stripping any directory prefix.
fn binary_name() -> Option<String> {
    std::env::args_os().next().and_then(|arg0| {
        Path::new(&arg0)
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
    })
}

fn main() -> Result<()> {
    match binary_name().as_deref() {
        Some("mkcomposefs") => mkcomposefs::run(),
        Some("composefs-info") => composefs_info::run(),
        _ => {
            use cfsctl::{open_repo, run_cmd_with_repo, App, HashType};
            use clap::Parser;
            use composefs::fsverity::{Sha256HashValue, Sha512HashValue};

            env_logger::init();

            let rt = tokio::runtime::Runtime::new()?;
            let args = App::parse();
            rt.block_on(async {
                match args.hash {
                    HashType::Sha256 => {
                        run_cmd_with_repo(open_repo::<Sha256HashValue>(&args)?, args).await
                    }
                    HashType::Sha512 => {
                        run_cmd_with_repo(open_repo::<Sha512HashValue>(&args)?, args).await
                    }
                }
            })
        }
    }
}
