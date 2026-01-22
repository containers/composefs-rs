# Justfile for composefs-rs
# Run `just --list` to see available targets.
#
# Submodules:
#   bootc/ - bootc reverse dependency testing (just bootc/build, etc.)
# --------------------------------------------------------------------

# Build all crates
build:
    cargo build --workspace

# Build in release mode
build-release:
    cargo build --workspace --release

# Run all tests
test:
    cargo test --workspace

# Run clippy lints
clippy:
    cargo clippy --workspace -- -D warnings

# Run rustfmt check
fmt-check:
    cargo fmt --all -- --check

# Format code
fmt:
    cargo fmt --all

# Run all checks (clippy + fmt + test)
check: clippy fmt-check test

# Clean build artifacts
clean:
    cargo clean
