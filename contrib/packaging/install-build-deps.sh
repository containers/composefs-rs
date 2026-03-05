#!/bin/bash
# Install build-time dependencies for composefs-rs.
#
# This script detects the OS via /etc/os-release and installs the
# appropriate compiler toolchain and development libraries needed to
# build cfsctl and the integration test binary.
set -euo pipefail

# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

case "${ID}" in
    centos|fedora|rhel)
        pkg_install \
            rust cargo \
            openssl-devel \
            gcc
        ;;
    debian|ubuntu)
        pkg_install \
            rustc cargo \
            libssl-dev zlib1g-dev pkg-config \
            gcc libc6-dev

        # /var/roothome is needed because /root is an OSTree symlink to
        # it, and cargo/rustup need a writable home directory.
        mkdir -p /var/roothome
        ;;
    *)
        echo "Unsupported distro: ${ID}" >&2
        exit 1
        ;;
esac
