use std::path::Path;

use anyhow::{bail, Result};

use composefs_experiments::{fsverity::Sha256HashValue, repository::Repository};

fn parse_composefs_cmdline(cmdline: &[u8]) -> Result<Sha256HashValue> {
    // TODO?: officially we need to understand quoting with double-quotes...
    for part in cmdline.split(|c| c.is_ascii_whitespace()) {
        if let Some(digest) = part.strip_prefix(b"composefs=") {
            let mut value = [0; 32];
            hex::decode_to_slice(digest, &mut value)?;
            return Ok(value);
        }
    }
    bail!("Unable to find composefs= cmdline parameter");
}

fn main() -> Result<()> {
    let repo = Repository::open_system()?;
    let cmdline = std::fs::read("/proc/cmdline")?;
    let image = parse_composefs_cmdline(&cmdline)?;
    repo.pivot_sysroot(&hex::encode(image), Path::new("/sysroot"))?;

    Ok(())
}

#[test]
fn test_parse() {
    let failing = ["", "foo", "composefs", "composefs=foo"];
    for case in failing {
        assert!(parse_composefs_cmdline(case.as_bytes()).is_err());
    }
    let digest = "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52";
    let digest_bytes = hex::decode(&digest).unwrap();
    assert_eq!(
        parse_composefs_cmdline(format!("composefs={digest}").as_bytes())
            .unwrap()
            .as_slice(),
        &digest_bytes
    );
}
