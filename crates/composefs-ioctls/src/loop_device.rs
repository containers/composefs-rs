//! Loop device ioctl wrappers.
//!
//! This module provides safe wrappers for creating loop devices,
//! primarily used for mounting composefs images on older kernels.

#![allow(unsafe_code)]

use std::{
    fs::OpenOptions,
    io::{Error, Result},
    os::fd::{AsFd, AsRawFd, OwnedFd},
};

use rustix::ioctl::{ioctl, opcode, Opcode, Setter};

/// Flags for loop device configuration.
pub mod flags {
    /// Read-only loop device.
    pub const LO_FLAGS_READ_ONLY: u32 = 1;
    /// Automatically detach on last close.
    pub const LO_FLAGS_AUTOCLEAR: u32 = 4;
    /// Allow partition scanning.
    pub const LO_FLAGS_PARTSCAN: u32 = 8;
    /// Use direct I/O.
    pub const LO_FLAGS_DIRECT_IO: u32 = 16;
}

const LO_NAME_SIZE: usize = 64;
const LO_KEY_SIZE: usize = 32;

// Loop device ioctl structures
#[repr(C)]
#[derive(Default)]
struct LoopConfig {
    fd: u32,
    block_size: u32,
    info: LoopInfo64,
    reserved: [u64; 8],
}

#[repr(C)]
struct LoopInfo64 {
    lo_device: u64,
    lo_inode: u64,
    lo_rdevice: u64,
    lo_offset: u64,
    lo_sizelimit: u64,
    lo_number: u32,
    lo_encrypt_type: u32,
    lo_encrypt_key_size: u32,
    lo_flags: u32,
    // HACK: default trait is only implemented up to [u8; 32]
    lo_file_name: ([u8; LO_NAME_SIZE / 2], [u8; LO_NAME_SIZE / 2]),
    lo_crypt_name: ([u8; LO_NAME_SIZE / 2], [u8; LO_NAME_SIZE / 2]),
    lo_encrypt_key: [u8; LO_KEY_SIZE],
    lo_init: [u64; 2],
}

impl Default for LoopInfo64 {
    fn default() -> Self {
        Self {
            lo_device: 0,
            lo_inode: 0,
            lo_rdevice: 0,
            lo_offset: 0,
            lo_sizelimit: 0,
            lo_number: 0,
            lo_encrypt_type: 0,
            lo_encrypt_key_size: 0,
            lo_flags: 0,
            lo_file_name: ([0; LO_NAME_SIZE / 2], [0; LO_NAME_SIZE / 2]),
            lo_crypt_name: ([0; LO_NAME_SIZE / 2], [0; LO_NAME_SIZE / 2]),
            lo_encrypt_key: [0; LO_KEY_SIZE],
            lo_init: [0; 2],
        }
    }
}

// Custom ioctl for LOOP_CTL_GET_FREE which returns data in the return value
struct LoopCtlGetFree;

// Rustix seems to lack a built-in pattern for an ioctl that returns data by the syscall return
// value instead of the usual return-by-reference on the args parameter.  Bake our own.
unsafe impl rustix::ioctl::Ioctl for LoopCtlGetFree {
    type Output = std::ffi::c_int;

    const IS_MUTATING: bool = false;

    fn opcode(&self) -> rustix::ioctl::Opcode {
        LOOP_CTL_GET_FREE
    }

    fn as_ptr(&mut self) -> *mut std::ffi::c_void {
        std::ptr::null_mut()
    }

    unsafe fn output_from_ptr(
        out: rustix::ioctl::IoctlOutput,
        _ptr: *mut std::ffi::c_void,
    ) -> rustix::io::Result<std::ffi::c_int> {
        Ok(out)
    }
}

const LOOP_CTL_GET_FREE: Opcode = opcode::none(0x4C, 0x82);
// #define LOOP_CONFIGURE         0x4C0A
const LOOP_CONFIGURE: Opcode = opcode::write::<LoopConfig>(0x4C, 0x0A);

/// Creates a loop device backed by the given file.
///
/// Returns an owned file descriptor for the loop device.
/// Uses default flags: read-only, autoclear, and direct I/O.
pub fn loopify(fd: impl AsFd) -> Result<OwnedFd> {
    loopify_with_flags(
        fd,
        flags::LO_FLAGS_READ_ONLY | flags::LO_FLAGS_AUTOCLEAR | flags::LO_FLAGS_DIRECT_IO,
    )
}

/// Creates a loop device with custom flags.
///
/// # Arguments
/// * `fd` - File descriptor of the backing file
/// * `lo_flags` - Loop device flags (see `flags` module)
pub fn loopify_with_flags(fd: impl AsFd, lo_flags: u32) -> Result<OwnedFd> {
    let control = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/loop-control")?;

    // Get a free loop device number
    let free: i32 = unsafe { ioctl(&control, LoopCtlGetFree) }.map_err(Error::other)?;

    if free < 0 {
        return Err(Error::other("no free loop device"));
    }

    // Open the loop device
    let loop_path = format!("/dev/loop{free}");
    let loop_dev = OpenOptions::new().read(true).write(true).open(&loop_path)?;

    // Configure the loop device
    let config = LoopConfig {
        fd: fd.as_fd().as_raw_fd() as u32,
        block_size: 4096,
        info: LoopInfo64 {
            lo_flags,
            ..Default::default()
        },
        reserved: [0; 8],
    };

    unsafe {
        ioctl(
            &loop_dev,
            Setter::<{ LOOP_CONFIGURE }, LoopConfig>::new(config),
        )
        .map_err(Error::other)?;
    }

    Ok(loop_dev.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_loopify_not_root() {
        // This test just verifies the code compiles and runs
        // It will fail without root, but shouldn't panic
        let mut tf = NamedTempFile::new().unwrap();
        tf.write_all(&[0u8; 4096]).unwrap();
        tf.flush().unwrap();

        let file = std::fs::File::open(tf.path()).unwrap();
        let result = loopify(&file);

        // Without root, we expect permission denied
        if !rustix::process::getuid().is_root() {
            assert!(result.is_err());
        }
    }
}
