#![deny(missing_debug_implementations)]

pub mod bootloader;
pub mod cmdline;
pub mod os_release;
pub mod selabel;
pub mod uki;
pub mod write_boot;

use anyhow::Result;

use composefs::{fsverity::FsVerityHashValue, repository::Repository, tree::FileSystem};

use crate::bootloader::{get_boot_resources, BootEntry};

pub trait BootOps<ObjectID: FsVerityHashValue> {
    fn transform_for_boot(
        &mut self,
        repo: &Repository<ObjectID>,
    ) -> Result<Vec<BootEntry<ObjectID>>>;
}

impl<ObjectID: FsVerityHashValue> BootOps<ObjectID> for FileSystem<ObjectID> {
    fn transform_for_boot(
        &mut self,
        repo: &Repository<ObjectID>,
    ) -> Result<Vec<BootEntry<ObjectID>>> {
        let boot_entries = get_boot_resources(self, repo)?;
        let boot = self.root.get_directory_mut("boot".as_ref())?;
        boot.stat.st_mtim_sec = 0;
        boot.clear();

        selabel::selabel(self, repo)?;

        Ok(boot_entries)
    }
}
