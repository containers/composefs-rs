use anyhow::Result;

use crate::{
    bootloader::{get_boot_resources, BootEntry},
    dumpfile::write_dumpfile,
    erofs::writer::mkfs_erofs,
    fsverity::{compute_verity, FsVerityHashValue},
    repository::Repository,
    selabel::selabel,
    tree::FileSystem,
};

impl<ObjectID: FsVerityHashValue> FileSystem<ObjectID> {
    pub fn transform_for_boot(
        &mut self,
        repo: &Repository<ObjectID>,
    ) -> Result<Vec<BootEntry<ObjectID>>> {
        let boot_entries = get_boot_resources(self, repo)?;
        let boot = self.root.get_directory_mut("boot".as_ref())?;
        boot.stat.st_mtim_sec = 0;
        boot.clear();

        selabel(self, repo)?;

        Ok(boot_entries)
    }

    pub fn commit_image(
        &mut self,
        repository: &Repository<ObjectID>,
        image_name: Option<&str>,
    ) -> Result<ObjectID> {
        self.ensure_root_stat();
        repository.write_image(image_name, &mkfs_erofs(self))
    }

    pub fn compute_image_id(&mut self) -> ObjectID {
        self.ensure_root_stat();
        compute_verity(&mkfs_erofs(self))
    }

    pub fn print_dumpfile(&mut self) -> Result<()> {
        self.ensure_root_stat();
        write_dumpfile(&mut std::io::stdout(), self)
    }
}
