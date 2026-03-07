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
# Override to test on different distros:
#   just base_image=ghcr.io/bootcrew/debian-bootc:latest integration-container
base_image := env("COMPOSEFS_BASE_IMAGE", "quay.io/centos-bootc/centos-bootc:stream10")

# Derive test image name from base_image
_test_image := if base_image =~ "debian" { "localhost/composefs-rs-test-debian:latest" } else { "localhost/composefs-rs-test:latest" }

# Run integration tests (builds cfsctl first); pass extra args to the harness
test-integration *ARGS: build
    CFSCTL_PATH=$(pwd)/target/debug/cfsctl cargo run -p integration-tests -- {{ ARGS }}

# Run only the fast unprivileged integration tests (no root, no VM)
integration-unprivileged: build
    CFSCTL_PATH=$(pwd)/target/debug/cfsctl cargo run -p integration-tests -- --skip privileged_

# Build the test container image for VM-based integration tests
integration-container-build:
    podman build --build-arg base_image={{base_image}} -t {{_test_image}} .

# Run all integration tests; privileged tests dispatch to a bcvk VM
integration-container: build integration-container-build
    COMPOSEFS_TEST_IMAGE={{_test_image}} \
        CFSCTL_PATH=$(pwd)/target/debug/cfsctl \
        cargo run -p integration-tests

# Run a specific erofs fuzz target (e.g., `just fuzz read_image -- -max_total_time=60`)
fuzz target *ARGS:
    cd crates/composefs-erofs && cargo +nightly fuzz run {{target}} {{ARGS}}

# Run all erofs fuzz targets for a given duration each (default: 120 seconds)
fuzz-all seconds="120":
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p target/fuzz-logs
    for target in $(cd crates/composefs-erofs && cargo +nightly fuzz list); do
        echo "--- Fuzzing $target for {{seconds}}s ---"
        log="target/fuzz-logs/$target.log"
        if (cd crates/composefs-erofs && cargo +nightly fuzz run "$target" -- -max_total_time={{seconds}}) > "$log" 2>&1; then
            echo "  $target: OK"
            tail -1 "$log"
        else
            echo "  $target: FAILED"
            cat "$log"
            exit 1
        fi
    done

# List available fuzz targets
fuzz-list:
    cd crates/composefs-erofs && cargo +nightly fuzz list

# Clean build artifacts
clean:
    cargo clean
