you# CI Failure Investigation - composefs-rs Examples

## Problem Statement

CI examples workflow failing for three Fedora jobs (unified, uki, unified-secureboot) starting around Oct 13, 2025. VMs fail to boot with empty console logs and SSH connection failures.

## Timeline

- **Last passing**: Oct 3, 2025
- **First failure**: Oct 13+ 2025
- **Package changes identified**: systemd 257.9-2 → 257.10-1, kernel 6.16.9 → 6.16.11+

## Root Cause Analysis

### Investigation Steps

1. **Added comprehensive logging infrastructure**
   - QEMU stdout/stderr capture to `qemu.log`
   - Serial console logging to `serial.log`
   - Modified `IpcDirectory` to preserve logs on test failures
   - Added kernel cmdline parameters for verbose logging

2. **Discovered QEMU parameter parsing issues**

   **Issue #1**: Initial kernel cmdline `earlyprintk=serial,ttyS0,115200` was being rejected by QEMU
   ```
   kvm: Invalid parameter 'ttyS0'
   ```
   - QEMU's SMBIOS parser treats commas as parameter delimiters
   - `ttyS0` was interpreted as a QEMU parameter, not part of kernel cmdline

   **Issue #2**: After fixing #1, `console=ttyS0,115200` still caused errors
   ```
   kvm: Invalid parameter '115200 debug loglevel'
   ```
   - Same comma parsing issue with QEMU SMBIOS

   **Issue #3**: SSH public key credential with spaces failed
   - QEMU SMBIOS parsing stricter with spaces in credential values
   - SSH public keys contain spaces between algorithm, key data, and comment

### Fixes Applied

#### 1. Kernel Command Line (commit 2ba8188)
**File**: `examples/testthing.py:648`

Removed problematic serial console parameters from SMBIOS kernel cmdline:
```python
# BEFORE
"type=11,value=io.systemd.boot.kernel-cmdline-extra=console=hvc0 earlyprintk=serial,ttyS0,115200 debug loglevel=7"

# AFTER
"type=11,value=io.systemd.boot.kernel-cmdline-extra=console=hvc0 debug loglevel=7"
```

Rationale: We already have `-serial file:{path}/serial.log` device configured separately, so serial console parameters in kernel cmdline were redundant and causing QEMU parsing errors.

#### 2. SMBIOS Credentials Base64 Encoding (commit 1ccdee4)
**File**: `examples/testthing.py:669-677`

Added automatic base64 encoding for credential values containing spaces:
```python
# Import base64 module
import base64

# Modified credential passing
*(
    (
        "-smbios",
        f"type=11,value=io.systemd.credential.binary:{k}={base64.b64encode(v.encode()).decode()}"
        if " " in v
        else f"type=11,value=io.systemd.credential:{k}={v}",
    )
    for k, v in creds.items()
),
```

Uses `io.systemd.credential.binary:` prefix with base64 encoding for values with spaces (particularly SSH public keys) to avoid QEMU SMBIOS parsing ambiguities.

Reference: https://systemd.io/CREDENTIALS/

#### 3. Enhanced Logging (commits 5a8f8b9, 4add586, 1c15f88, 80f1146)
**Files**: `examples/testthing.py`, `.github/workflows/examples.yml`

- Added QEMU log capture with `stdout`/`stderr` to `qemu.log`
- Added serial port logging: `("-serial", f"file:{self._ipc}/serial.log")`
- Modified `IpcDirectory.__exit__()` to skip cleanup on exceptions using `finalizer.detach()`
- Updated CI workflow to dump all log files on failure

## Current Status

### ✅ Fixed
- QEMU parameter parsing errors resolved
- QEMU now starts successfully
- Serial console logging now captures full boot sequence
- Console configuration: `console=ttyS0,115200n8` in UKI, SMBIOS only adds `debug loglevel=7`

### ✅ VM Boot Success Confirmed
- VM boots completely through to multi-user.target
- sshd.service starts successfully
- Full kernel boot messages visible in serial.log
- Example from serial.log:
  ```
  Command line: composefs=<digest> rw console=ttyS0,115200n8 systemd.machine_id=<id>
  [boot messages...]
  OK Started sshd.service - OpenSSH server daemon.
  OK Reached target multi-user.target - Multi-User System.
  ```

### ❌ Outstanding Issue: SSH Connection Failure

**Symptom**: VM boots successfully, sshd starts, but test SSH connection fails

**Error**:
```
testthing.SubprocessError: Subprocess exited unexpectedly with return code 255
ssh_dispatch_run_fatal: Connection to UNKNOWN port 0: Broken pipe
```

**Boot sequence**:
```
UEFI/OVMF starts            ✓
systemd-boot menu appears   ✓
EFI stub loads initrd       ✓
Kernel boot complete        ✓
systemd startup             ✓
sshd.service starts         ✓
multi-user.target reached   ✓
SSH connection (vsock)      ✗ (broken pipe)
```

**Configuration verified**:
- Pinned versions correctly installed: kernel 6.16.9-200.fc42, systemd 257.9-2.fc42
- Kernel cmdline (baked into UKI): `composefs=<fsverity-digest> rw console=ttyS0,115200n8`
- Additional cmdline (via SMBIOS): `debug loglevel=7`
- Composefs image digest calculated correctly during container build
- Serial console captures all output to serial.log

## Hypothesis

**Package versions are NOT the root cause**:
- We're already pinning kernel 6.16.9-200.fc42 and systemd 257.9-2.fc42 (Oct 3 working versions)
- VM boots successfully with these versions as confirmed by serial.log
- sshd starts and reaches multi-user.target

**SSH/vsock connection is the actual problem**:
- VM boot is working correctly
- SSH connection over vsock fails with "Broken pipe"
- This suggests the issue is NOT in the guest, but in:
  - vsock device communication between host/guest
  - GitHub Actions runner environment changes (QEMU version, kernel module)
  - systemd-ssh-proxy or SSH connection timing
  - vhost-vsock-pci device configuration

**Possible GitHub Actions runner changes**:
- QEMU version update affecting vsock implementation
- Host kernel vsock module changes
- vhost-vsock driver updates
- Network/socket permissions in runner environment

## Package Change Investigation

### Kernel 6.16.x Known Issues (from web research)
Multiple Fedora Discussion threads report kernel 6.16.x boot failures:
- Versions affected: 6.16.3, 6.16.5, 6.16.6, 6.16.7
- Symptoms: Boot hangs, stuck at Fedora logo, ACPI errors
- Workaround: Boot with kernel 6.15.10 or 6.17.x

**However**: We're already pinned to 6.16.9 (from Oct 3 when tests passed), and serial.log confirms the VM boots successfully. This suggests kernel 6.16.9 itself is not the issue.

### systemd Changes
- 257.9-2.fc42 (working) → 257.10-1.fc42 (Oct 13-14)
- Timing matches failure window, but we're pinned to 257.9-2
- VM boots successfully with 257.9-2, so not the cause

### Other Packages (not pinned)
- selinux-policy-targeted: 41.24 → 41.26 (no boot-related changes found)
- dracut: 105-2.fc42 (stable, no updates in Oct)
- composefs: Not pinned, could have changed
- btrfs-progs: Not pinned, could have changed

## Possible Causes for SSH Failure

1. **vsock device/driver issue**
   - vhost-vsock kernel module on GitHub Actions runner changed
   - QEMU vhost-vsock-pci implementation updated
   - Try: Add vsock debug logging, test with different guest-cid

2. **SSH timing issue**
   - Test attempts connection before sshd fully ready
   - vsock socket not properly established
   - Try: Add delay before SSH connection attempt

3. **Unpinned package regression**
   - composefs version changed, affecting boot timing
   - openssh-server version changed
   - Try: Pin all packages to Oct 3 versions

4. **GitHub Actions runner environment**
   - QEMU version on runners updated
   - Host kernel vsock support changed
   - Runner security policy blocking vsock
   - Try: Test locally with same QEMU parameters

## Files Modified

### Primary Changes
- `examples/testthing.py` - QEMU invocation, credential handling, logging
- `.github/workflows/examples.yml` - Log dumping steps, disabled non-failing jobs

### Supporting Files (pinned versions from earlier work)
- `examples/uki/Containerfile`
- `examples/unified/Containerfile`
- `examples/unified-secureboot/Containerfile`

## Testing Status

**Branch**: `debug-ci`
**PR**: https://github.com/containers/composefs-rs/pull/190
**Test fork**: https://github.com/cgwalters/composefs-rs

Latest test runs:
- Run 18624189103 (commit 5efbd1f): Fixed baud rate 114800→115200, removed console=hvc0 from SMBIOS
  - QEMU starts: ✓
  - VM boots to kernel: ✓
  - Kernel completes boot: ✓
  - sshd starts: ✓ (visible in serial.log)
  - multi-user.target: ✓
  - SSH connection: ✗ (broken pipe on vsock connection)

- Run 18624093309 (commit 4a3e1f9): Wrong baud rate 114800, no console=hvc0
  - Same results as above
  - Confirms baud rate fix was cosmetic, not functional

**Key finding**: VM boots completely and all services start, but SSH over vsock fails to connect

## Next Steps

### High Priority - SSH/vsock Debugging

1. **Add vsock/SSH debug logging**
   - Add `-device vhost-vsock-pci,id=...,debug=on` or similar QEMU flags
   - Add verbose SSH logging in testthing.py
   - Check if vsock device is actually available in guest (`ls /dev/vsock`)

2. **Test with timing delay**
   - Add sleep/retry logic before SSH connection attempt
   - Check if sshd needs more time to become ready

3. **Pin all packages to Oct 3 versions**
   - Capture exact package versions from successful Oct 3 build
   - Pin composefs, openssh-server, btrfs-progs, selinux-policy-targeted

4. **Test locally**
   - Run the same QEMU command locally to see if issue is runner-specific
   - Compare local QEMU/kernel versions with GitHub Actions runner

### Lower Priority - Alternative Approaches

5. **Try different connection method**
   - Test with network instead of vsock
   - Try serial console connection instead of SSH

6. **Test with kernel 6.15.10**
   - Pin to kernel-6.15.10-200.fc42 as absolute fallback
   - Confirm if earlier kernel works in current environment

## Testing Instructions

### Running Tests Locally

To reproduce the issue locally:

```bash
# Build the UKI container image
cd examples/uki
podman build -t localhost/uki-test .

# Run the test
cd ../..
python3 examples/testthing.py examples/uki

# Check logs on failure
ls -la /tmp/test.thing/*/  # or wherever IpcDirectory creates temp dir
cat /tmp/test.thing/*/serial.log  # Kernel boot log
cat /tmp/test.thing/*/console     # Console output
cat /tmp/test.thing/*/qemu.log    # QEMU stdout/stderr
```

### Testing in CI (cgwalters fork)

**CRITICAL: ONLY push to cgwalters fork, NEVER push to debug-ci branch or create PRs**

The debug-ci branch has PR #190 open to main composefs-rs repo. Any commits to debug-ci will update that PR and create noise for everyone else.

**ONLY USE THIS WORKFLOW**:
```bash
# Make changes, commit locally on ANY branch (NOT debug-ci)
git add -A
git commit -m "test: Description of change"

# Push ONLY to cgwalters fork main branch
git push -f cgwalters HEAD:main

# Monitor workflow on cgwalters fork ONLY
gh run list --repo cgwalters/composefs-rs
gh run watch <run-id> --repo cgwalters/composefs-rs

# Download artifacts after failure
gh run download <run-id> --repo cgwalters/composefs-rs
```

**DO NOT**:
- Push to debug-ci branch
- Push to containers/composefs-rs repo
- Create or update pull requests
- Use `git push origin` without being very careful about branch

### Analyzing Logs

Key files in artifacts:
- `serial.log` - Serial console (ttyS0) output, shows kernel boot and early systemd
- `console` - virtconsole (hvc0) output, shows login getty
- `qemu.log` - QEMU process stdout/stderr, shows QEMU errors

Look for:
- Kernel command line in serial.log
- sshd.service start messages
- vsock device initialization
- Any errors or warnings during boot
- SSH connection attempt output

### Key Configuration Files

- `examples/uki/Containerfile` - UKI image build, sets console in /etc/kernel/cmdline
- `examples/testthing.py` - Test harness, QEMU invocation and SSH connection (lines 640-677)
- `.github/workflows/examples.yml` - CI workflow

## References

- systemd credentials: https://systemd.io/CREDENTIALS/
- QEMU SMBIOS documentation: https://www.qemu.org/docs/master/system/i386/pc.html
- QEMU vsock: https://wiki.qemu.org/Features/VirtioVsock
- Fedora kernel 6.16.x boot issues: https://discussion.fedoraproject.org/t/fedora-42-latest-kernel-update-6-16-6-and-6-16-7-have-crashed-the-system-not-able-to-boot/164682
- Debug branch: https://github.com/containers/composefs-rs/tree/debug-ci
- Test fork: https://github.com/cgwalters/composefs-rs
