use std::{fs::File, io::Read, path::PathBuf};

use clap::Parser;

use composefs::erofs::debug::debug_img;

/// Produce a detailed dump of an entire erofs image
///
/// The output is in a diff-friendly format, such that every distinct image produces a distinct
/// output (ie: an injective mapping).  This is useful for determining the exact ways in which two
/// different images are different.
#[derive(Parser)]
struct Args {
    /// The path to the image file to dump
    image: PathBuf,
}

fn main() {
    let args = Args::parse();
    let mut image = File::open(args.image).expect("Opening file");

    let mut data = vec![];
    image.read_to_end(&mut data).expect("read_to_end() failed");
    debug_img(&data);
}
