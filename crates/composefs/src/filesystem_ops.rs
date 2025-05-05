use anyhow::Result;

use crate::{
    dumpfile::write_dumpfile,
    erofs::writer::mkfs_erofs,
    fsverity::{compute_verity, FsVerityHashValue},
    repository::Repository,
    tree::FileSystem,
};

impl<ObjectID: FsVerityHashValue> FileSystem<ObjectID> {
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
