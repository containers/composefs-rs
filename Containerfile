# Containerfile for composefs-rs
#
# Builds cfsctl and integration test binaries, then produces a bootable
# (bootc-compatible) container image suitable for privileged integration
# testing via `bcvk ephemeral run-ssh`.
#
# Build:
#   podman build --tag composefs-rs-test -f Containerfile .
#
# Uses BuildKit-style cache mounts for fast incremental Rust builds.

# -- source snapshot (keeps layer graph clean) --
FROM scratch AS src
COPY . /src

# -- build stage --
FROM quay.io/centos-bootc/centos-bootc:stream10 AS build

RUN dnf install -y \
        rust cargo clippy rustfmt \
        openssl-devel \
        gcc \
        composefs \
    && dnf clean all

COPY --from=src /src /src
WORKDIR /src

# Fetch dependencies (network-intensive, cached separately)
RUN --mount=type=cache,target=/src/target \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    cargo fetch

# Build cfsctl and integration test binary
RUN --network=none \
    --mount=type=cache,target=/src/target \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    cargo build --release -p cfsctl -p integration-tests && \
    cp /src/target/release/cfsctl /usr/bin/cfsctl && \
    cp /src/target/release/cfsctl-integration-tests /usr/bin/cfsctl-integration-tests

# -- final bootable image --
FROM quay.io/centos-bootc/centos-bootc:stream10

RUN dnf install -y composefs openssl && dnf clean all

COPY --from=build /usr/bin/cfsctl /usr/bin/cfsctl
COPY --from=build /usr/bin/cfsctl-integration-tests /usr/bin/cfsctl-integration-tests
