use anyhow::Result;
use rustix::fs::CWD;
use std::{path::Path, sync::Arc};

use composefs::{fsverity::FsVerityHashValue, repository::Repository, tree::FileSystem};

pub mod commit;
pub mod objmap;
pub mod repo;

use crate::commit::{OstreeCommit, PullOperation};
use crate::repo::{LocalRepo, RemoteRepo};

pub async fn pull_local<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    path: &Path,
    ostree_ref: &str,
    reference: Option<&str>,
    base_reference: Option<&str>,
) -> Result<ObjectID> {
    let ostree_repo = LocalRepo::open_path(repo, CWD, path)?;

    let commit_checksum = ostree_repo.read_ref(ostree_ref)?;

    let mut op = PullOperation::<ObjectID, LocalRepo<ObjectID>>::new(repo, ostree_repo);
    if let Some(base_name) = base_reference {
        op.add_base(base_name)?;
    }

    // If we're giving the new image a new, use any existing image
    // with that name as a potential base
    if let Some(reference) = reference {
        if repo.has_named_stream(&reference)? {
            let reference_path = format!("refs/{reference}");
            op.add_base(&reference_path)?;
        }
    }

    let (sha256, objid) = op.pull_commit(&commit_checksum).await?;

    if let Some(name) = reference {
        repo.name_stream(sha256, name)?;
    }

    Ok(objid)
}

pub async fn pull<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    url: &str,
    ostree_ref: &str,
    reference: Option<&str>,
    base_reference: Option<&str>,
) -> Result<ObjectID> {
    let ostree_repo = RemoteRepo::new(repo, url)?;

    let commit_checksum = ostree_repo.resolve_ref(ostree_ref).await?;

    let mut op = PullOperation::<ObjectID, RemoteRepo<ObjectID>>::new(repo, ostree_repo);
    if let Some(base_name) = base_reference {
        op.add_base(base_name)?;
    }

    // If we're giving the new image a new, use any existing image
    // with that name as a potential base
    if let Some(reference) = reference {
        if repo.has_named_stream(&reference)? {
            let reference_path = format!("refs/{reference}");
            op.add_base(&reference_path)?;
        }
    }

    let (sha256, objid) = op.pull_commit(&commit_checksum).await?;

    if let Some(name) = reference {
        repo.name_stream(sha256, name)?;
    }

    Ok(objid)
}

/// Creates a filesystem from the given OSTree commit.
pub fn create_filesystem<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    commit_name: &str,
) -> Result<FileSystem<ObjectID>> {
    let image = OstreeCommit::<ObjectID>::load(repo, commit_name)?;
    let fs = image.create_filesystem()?;

    Ok(fs)
}

/// Creates a filesystem from the given OSTree commit.
pub fn inspect<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    commit_name: &str,
) -> Result<()> {
    let image = OstreeCommit::<ObjectID>::load(repo, commit_name)?;
    image.inspect();

    Ok(())
}
