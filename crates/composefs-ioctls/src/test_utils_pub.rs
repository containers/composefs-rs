//! Test utilities that require unsafe code.
//!
//! This module provides helpers for tests that need unsafe operations,
//! allowing dependent crates to remain `#![forbid(unsafe_code)]`.

#![allow(unsafe_code)]

use std::os::unix::process::CommandExt as _;
use std::process::Command;
use std::time::Duration;

/// Extension trait for Command that adds a pre-exec sleep.
pub trait CommandExt {
    /// Sleep for the given duration before exec.
    ///
    /// This is useful for introducing random delays in fork tests,
    /// simulating scenarios where forked processes hold file descriptors
    /// briefly before exec.
    ///
    /// # Safety
    ///
    /// This uses `pre_exec` internally which requires unsafe. The sleep
    /// operation itself is safe, but `pre_exec` callbacks run in a
    /// delicate state between fork and exec.
    fn pre_exec_sleep(&mut self, delay: Duration) -> &mut Self;
}

impl CommandExt for Command {
    fn pre_exec_sleep(&mut self, delay: Duration) -> &mut Self {
        unsafe {
            self.pre_exec(move || {
                std::thread::sleep(delay);
                Ok(())
            })
        };
        self
    }
}
