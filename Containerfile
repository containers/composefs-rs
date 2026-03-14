# Containerfile for composefs-rs integration testing
#
# Builds cfsctl and integration test binaries, then produces a bootable
# (bootc-compatible) container image suitable for privileged integration
# testing via `bcvk ephemeral run-ssh`.
#
# Build:
#   podman build --tag composefs-rs-test .
#   podman build --build-arg base_image=ghcr.io/bootcrew/debian-bootc:latest --tag composefs-rs-test-debian .
#
# Uses BuildKit-style cache mounts for fast incremental Rust builds.
# Note: when switching between base images locally, run
#   podman system prune --volumes
# to clear stale build caches that may be incompatible across distros.

ARG base_image=quay.io/centos-bootc/centos-bootc:stream10

# -- source snapshot (keeps layer graph clean) --
FROM scratch AS src
COPY . /src

# -- build stage --
FROM ${base_image} AS build

COPY --from=src /src/contrib /src/contrib
RUN /src/contrib/packaging/install-build-deps.sh

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
    cargo build --release -p cfsctl --features=pre-6.15 -p integration-tests && \
    cp /src/target/release/cfsctl /usr/bin/cfsctl && \
    cp /src/target/release/cfsctl-integration-tests /usr/bin/cfsctl-integration-tests

# -- final bootable image --
FROM ${base_image}

COPY --from=src /src/contrib /src/contrib
RUN /src/contrib/packaging/install-test-deps.sh && rm -rf /src

COPY --from=build /usr/bin/cfsctl /usr/bin/cfsctl
COPY --from=build /usr/bin/cfsctl-integration-tests /usr/bin/cfsctl-integration-tests
