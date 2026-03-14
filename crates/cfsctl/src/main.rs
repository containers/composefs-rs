//! Command-line control utility for composefs repositories and images.
//!
//! `cfsctl` provides a comprehensive interface for managing composefs repositories,
//! creating and mounting filesystem images, handling OCI containers, and performing
//! repository maintenance operations like garbage collection.

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    cfsctl::run_from_args().await
}
