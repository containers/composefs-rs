# OCI Sealing Implementation in composefs-rs

Implementation plan for [oci-sealing-spec.md](oci-sealing-spec.md) in composefs-rs.

## Current State

The `composefs-oci` crate has basic sealing: `seal()` in `lib.rs` computes the fsverity digest of the merged EROFS via `compute_image_id()`, stores it in the container runtime config labels under `containers.composefs.fsverity`, and `mount()` verifies it by looking up the image by digest and comparing against the kernel's fsverity measurement.

All repository objects have fsverity enabled by default (controlled by `Repository.insecure`).

Key limitations of the current implementation:
- Only one flattened digest (no per-layer digests)
- Digest stored in the config label, which modifies the image
- Config stored as splitstream; manifest not persisted at all
- Registry interaction is pull-only via `containers-image-proxy`/skopeo — no push, no referrers API

**Key dependency**: [#216](https://github.com/containers/composefs-rs/pull/216) extends composefs-oci to store manifests natively, handle OCI artifacts (non-tar layers), and adds `OciImage` type with manifest/config access. Most of the work below depends on #216 landing first.

## What Needs to Change

### 1. Algorithm string format

The spec defines `${DIGEST}-${BLOCKSIZEBITS}` identifiers (e.g. `sha512-12`). Need to implement parsing and mapping to kernel constants (`FS_VERITY_HASH_ALG_SHA512`, 4096-byte blocks, no salt). This is a prerequisite for everything else.

### 2. Per-layer composefs digests

Currently `seal()` produces one digest for the merged filesystem. The spec defines per-layer digests (`composefs.layer.<algo>`) and optional rolling merged digests (`composefs.merged.<algo>`).

After importing each layer via `import_layer()`, compute the composefs digest of that individual layer's EROFS. Optionally compute rolling merged digests (`composefs.merged.<algo>`) at each layer boundary. Note: `import_layer()` currently stores layers as splitstreams, not EROFS images. Need to either generate a per-layer EROFS to compute its digest, or compute the digest without persisting the intermediate EROFS.

Also note: `transform_for_oci()` normalizes root metadata by copying from `/usr` and only applies to the merged filesystem. Per-layer digests need a separate normalization strategy or none at all.

### 3. Persist manifest and config as regular files

The manifest is currently not persisted at all (fetched, parsed, discarded in `skopeo.rs`). The config is stored as splitstream via `write_config()`. Both need to be stored as regular files so `FS_IOC_ENABLE_VERITY` can be called on them.

#216 adds manifest storage and `OciImage` type with access to stored manifests and configs. The remaining work is ensuring these are stored as regular verity-capable files rather than splitstreams, so that `FS_IOC_ENABLE_VERITY` can be applied directly.

### 4. Signature artifact creation

The core new feature. Given an OCI image (possibly unmodified), produce a separate OCI artifact containing PKCS#7 fsverity signatures per the spec.

Concrete steps:
- Compute composefs digests for manifest JSON, config JSON, and each layer
- Sign each digest: construct `fsverity_formatted_digest` struct (magic `"FSVerity"`, little-endian algorithm ID, digest bytes), produce PKCS#7
- Build the OCI artifact manifest:
  - `artifactType`: `application/vnd.composefs.signature.v1`
  - Empty config: `application/vnd.oci.empty.v1+json`, digest of `{}`, size 2
  - Layers: one per signed object, media type `application/vnd.composefs.signature.v1+pkcs7`
  - Each layer annotated with `composefs.signature.type` (`manifest`, `config`, `layer`, or `merged`) and `composefs.digest` (the fsverity digest being signed)
  - `subject` pointing to the source image manifest descriptor
  - `composefs.algorithm` annotation on the artifact manifest (e.g. `sha512-12`)
- Layers ordered: manifest, config, then layer entries (one per source manifest layer, in order), then merged entries (one per layer with a merged digest, in order)
- Not all groups are required; the `layer` group MUST always be present. Other groups may be omitted entirely.
- Push artifact to registry

This requires:
- PKCS#7 signing capability
- OCI artifact manifest construction (#216 adds OCI artifact support)
- Registry push support (does not exist today)

Reference example using [fsverity-utils](https://git.kernel.org/pub/scm/fs/fsverity/fsverity-utils.git) and openssl:

```bash
# Generate a key pair (once)
openssl req -newkey rsa:4096 -nodes -keyout key.pem -x509 -out cert.pem

# Compute the fsverity digest and sign it in one step
fsverity sign layer.erofs layer.sig --key=key.pem --cert=cert.pem

# Or, compute the digest separately and sign with openssl directly:
# (--for-builtin-sig outputs the fsverity_formatted_digest structure)
fsverity digest layer.erofs --compact --for-builtin-sig \
  | xxd -p -r \
  | openssl smime -sign -noattr -binary -inkey key.pem -signer cert.pem \
      -outform der -out layer.sig

# The resulting layer.sig is the raw PKCS#7 DER blob
# that becomes a layer in the signature artifact.

# To load the certificate into the kernel for verification:
openssl x509 -in cert.pem -out cert.der -outform der
keyctl padd asymmetric '' %keyring:.fs-verity < cert.der
```

### 5. Signature artifact verification

Given an image manifest digest, discover and verify composefs signature artifacts.

- Query `/referrers` API: `GET /v2/<name>/referrers/<digest>?artifactType=application/vnd.composefs.signature.v1`
- Fetch artifact, validate `subject` matches expected manifest digest
- Read `composefs.algorithm` from artifact annotations
- Extract layers in order, match to source objects by position within each group
- For each layer: read `composefs.digest` annotation, fetch PKCS#7 blob, apply via `FS_IOC_ENABLE_VERITY` when enabling verity on the corresponding file
- If source manifest also has composefs digest annotations, verify they agree with the artifact's `composefs.digest` values

Digest-only verification (alternative path): verify composefs digests against EROFS blobs without kernel PKCS#7 signatures, relying on external trust in the manifest (e.g. cosign). This is a fundamentally different code path — the digests are authoritative, no `FS_IOC_ENABLE_VERITY` call with a signature.

### 6. Deprecate config label

The `containers.composefs.fsverity` config label should be kept for backward compatibility but is no longer the primary path. New code should produce/consume signature artifacts instead.

## Implementation Order

0. **Land #216** — manifest storage, OCI artifact support, `OciImage` type. Prerequisite for most of the below.
1. **Algorithm string format** — parse `sha512-12`, map to kernel constants
2. **Per-layer digests** — compute per-layer composefs digests during import
3. **Manifest/config as regular files** — extend #216's storage to use regular files with fsverity
4. **Signature artifact creation** — PKCS#7 signing, artifact construction, registry push
5. **Signature artifact verification** — referrer discovery, signature application

Steps 4-5 should naturally support signing existing unmodified images as a test/validation milestone.

## Open Questions

- **PKCS#7 signing**: Kernel keyring (`/proc/keys`) or Rust crypto library? Kernel aligns with verification path but is harder to use in build environments without root.
- **Registry push**: `containers-image-proxy`/skopeo is pull-only as used today. Need either direct OCI registry HTTP client or skopeo push support for artifacts and referrers.
- **Per-layer EROFS**: Compute digest without persisting the intermediate image, or store per-layer EROFS images too?
- **Backward compatibility**: Timeline for deprecating the config label path.
