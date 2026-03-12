//! Fuzz target: feed arbitrary bytes into the EROFS debug_img function.
//!
//! Invariants under test:
//! - `debug_img()` must never panic on any input.
//! - Output is written to a sink to avoid noise; we only care about panics.

#![no_main]

use std::io;

use libfuzzer_sys::fuzz_target;

use composefs::erofs::debug::debug_img;

fuzz_target!(|data: &[u8]| {
    // Write to a sink — we don't care about the output, only about panics.
    let _ = debug_img(&mut io::sink(), data);
});
