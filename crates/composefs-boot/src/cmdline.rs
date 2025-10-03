use anyhow::Result;
pub(crate) use bootc_kernel_cmdline::utf8::{Cmdline, Parameter};
use composefs::fsverity::FsVerityHashValue;

pub fn get_cmdline_composefs<ObjectID: FsVerityHashValue>(
    cmdline: &str,
) -> Result<(ObjectID, bool)> {
    let cmdline = Cmdline::from(cmdline);
    let id = cmdline.require_value_of("composefs")?;
    if let Some(stripped) = id.strip_prefix('?') {
        Ok((ObjectID::from_hex(stripped)?, true))
    } else {
        Ok((ObjectID::from_hex(id)?, false))
    }
}
