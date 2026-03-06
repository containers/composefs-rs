# Justfile for composefs-rs
# Run `just --list` to see available targets.
#
# Quick-start for new developers:
#   just check              — fmt + clippy + unit tests
#   just test-integration   — unprivileged integration tests against cfsctl
#   just test-integration-vm — full suite including privileged VM tests
#   just ci                 — everything above
# --------------------------------------------------------------------

mod bootc

# Build all crates
build:
    cargo build --workspace

# Build in release mode
build-release:
    cargo build --workspace --release

# Run unit tests (excludes integration-tests crate)
test:
    cargo test --workspace --exclude integration-tests

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

# Base image for test container builds.
# Override to test on a different distro, e.g.:
#   just base_image=quay.io/centos-bootc/centos-bootc:stream10 test-integration
base_image := env("COMPOSEFS_BASE_IMAGE", "ghcr.io/bootcrew/debian-bootc:latest")

# Derive test image name from base_image
_test_image := if base_image =~ "debian" { "localhost/composefs-rs-test-debian:latest" } else { "localhost/composefs-rs-test:latest" }

# Run unprivileged integration tests against the cfsctl binary (no root, no VM)
test-integration: build
    CFSCTL_PATH=$(pwd)/target/debug/cfsctl cargo run -p integration-tests -- --skip privileged_

# Build the test container image for VM-based integration tests
_integration-container-build:
    podman build --build-arg base_image={{base_image}} -t {{_test_image}} .

# Run all integration tests including privileged VM tests (requires podman + libvirt)
test-integration-vm: build _integration-container-build
    COMPOSEFS_TEST_IMAGE={{_test_image}} \
        CFSCTL_PATH=$(pwd)/target/debug/cfsctl \
        cargo run -p integration-tests

# Run everything: checks + full integration tests including VM
ci: check test-integration-vm

# Clean build artifacts
clean:
    cargo clean
