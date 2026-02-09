# composefs-rs integration tests

Integration tests for `cfsctl` that exercise the CLI as a subprocess.
Unlike the workspace's unit tests, these run the actual binary against
real repositories and (optionally) real kernels with fs-verity.

The test binary uses `libtest-mimic` with `linkme` distributed slices
instead of `#[test]`, following the same pattern as
[bcvk](https://github.com/bootc-dev/bcvk).

## Test tiers

**CLI tests** (`test_*`) run on the host without root. They pass
`--insecure` to skip fs-verity and use temp dirs for repositories.
These are fast and need no special setup.

**Privileged tests** (`privileged_*`) need root and real fs-verity
support. They create loopback ext4 filesystems with the verity feature
and run `cfsctl` without `--insecure`. When run on the host (not as
root), each test automatically re-executes itself inside a
[bcvk](https://github.com/bootc-dev/bcvk) ephemeral VM — no separate
wrapper functions needed. Set `COMPOSEFS_TEST_IMAGE` to enable this.

## Running

```sh
# Fast CLI tests only (no root, no VM)
just integration-unprivileged

# Everything, privileged tests auto-dispatch to bcvk VM
just integration-container
```

The container image is built from the repo's `Containerfile` and
includes both `cfsctl` and `cfsctl-integration-tests` at `/usr/bin/`.
It's based on `centos-bootc:stream10` so bcvk can boot it as a VM.

## Running privileged tests without bcvk

If you have root and a kernel with fs-verity support (5.4+), you can
skip the VM dispatch entirely. The tests create loopback ext4
filesystems with the verity feature, so you need `mkfs.ext4` and
`mount` available.

**Direct execution as root** (e.g. inside a VM, a privileged
container, or a test machine):

```sh
cfsctl-integration-tests privileged_
```

Or from the workspace:

```sh
sudo CFSCTL_PATH=$(pwd)/target/debug/cfsctl cargo run -p integration-tests -- privileged_
```

**Inside a privileged container** — useful on hosts without native
fs-verity or when you don't want to install dependencies locally:

```sh
podman run --privileged -v $(pwd):/src:Z -w /src \
  quay.io/fedora/fedora:41 \
  bash -c 'dnf -y install cargo composefs e2fsprogs && \
           cargo build -p cfsctl -p integration-tests && \
           CFSCTL_PATH=$(pwd)/target/debug/cfsctl \
           cargo run -p integration-tests -- privileged_'
```

### Environment variables

| Variable | Purpose |
|---|---|
| `CFSCTL_PATH` | Path to `cfsctl` binary. Auto-detected if not set. |
| `COMPOSEFS_TEST_IMAGE` | Container image for VM dispatch. Setting this triggers bcvk auto-dispatch for privileged tests. |
| `BCVK_PATH` | Path to `bcvk` binary. Found in `PATH` if not set. |
| `COMPOSEFS_IN_VM` | Set automatically inside VMs to prevent recursive dispatch. |

## Adding tests

Define a function returning `anyhow::Result<()>` and register it:

```rust
fn test_my_feature() -> Result<()> {
    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    // ...
    Ok(())
}
integration_test!(test_my_feature);
```

For privileged tests, call `require_privileged()` at the top. This
handles both execution paths — running directly as root, or
re-dispatching into a VM:

```rust
fn privileged_my_feature() -> Result<()> {
    if require_privileged("privileged_my_feature")?.is_some() {
        return Ok(());
    }
    // ... test body runs as root with fs-verity ...
    Ok(())
}
integration_test!(privileged_my_feature);
```
