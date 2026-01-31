# Justfile for composefs-rs
# Run `just --list` to see available targets.
# --------------------------------------------------------------------

mod bootc

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

# Run all tests with all features enabled
test-all:
    cargo test --workspace --all-features

# Build with containers-storage feature
build-cstorage:
    cargo build --workspace --features containers-storage

# Run integration tests (requires podman and skopeo)
integration-test: build-release
    cargo run --release -p integration-tests --bin integration-tests

# Clean build artifacts
clean:
    cargo clean
