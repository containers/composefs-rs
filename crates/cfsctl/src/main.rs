//! Command-line control utility for composefs repositories and images.
//!
//! `cfsctl` provides a comprehensive interface for managing composefs repositories,
//! creating and mounting filesystem images, handling OCI containers, and performing
//! repository maintenance operations like garbage collection.

use cfsctl::App;

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = App::parse();
    cfsctl::run_app(args).await
}
