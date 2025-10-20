# OCI Sealing Specification for Composefs

This document defines how composefs integrates with OCI container images to provide cryptographic verification of complete filesystem trees. The specification is based on original design discussion in [composefs/composefs#294](https://github.com/composefs/composefs/issues/294).

## Problem Statement

Container images need cryptographic verification that efficiently covers the entire filesystem tree without requiring re-hashing of all content. Current OCI signature mechanisms (cosign, GPG) can sign manifests, but verifying the complete filesystem tree at runtime is extremely expensive because the only known digests are those of the tar layers.

Hence verifying the integrity of an individual file would require re-synthesizing the entire tarball (using tar-split or equivalent) and computing its digest.

## Solution

The core primitive of composefs is fsverity, which allows incremental online verification of individual files. The complete filesystem tree metadata is itself stored as a file which can be verified in the same way. The critical design question is how to embed the composefs digest within OCI image metadata such that external signatures can efficiently cover the entire filesystem tree.

## Design Goals

The OCI sealing specification aims to provide efficient verification where a signature on an OCI manifest cryptographically covers the entire filesystem tree without re-hashing content. The specification defines standardized metadata locations for composefs digests and supports future format evolution without breaking existing images.

Incremental verification must be supported, enabling verification of individual layers or the complete flattened filesystem. The design accommodates both registry-provided sealed images and client-side sealing workflows while maintaining backward compatibility with existing OCI tooling and registries.

## Core Design

### Composefs Digest Storage

The composefs fsverity digest is stored as a label in the OCI image config:

```json
{
  "config": {
    "Labels": {
      "containers.composefs.fsverity": "sha256:a3b2c1d4e5f6..."
    }
  }
}
```

The config represents the container's identity rather than transport metadata. Manifests are transport artifacts that can vary across different distribution mechanisms. Adding the composefs label creates a new config and thus a new manifest, establishing the sealed image as a distinct artifact. This means sealing an image produces a new image with a different config digest, where the original unsealed image and sealed image coexist as separate artifacts that registries treat as distinct versions.

### Digest Type

The primary digest is the fs-verity digest of the EROFS image containing the merged, flattened filesystem. This digest provides fast verification at mount time through kernel fs-verity checks and is deterministic: the same input layers always produce the same EROFS digest. The digest covers the complete filesystem tree including all metadata such as permissions, timestamps, and extended attributes.

### Merged Filesystem Representation

The config label contains the digest of the merged, flattened filesystem. This represents the final filesystem state after extracting all layers in order, applying whiteouts (`.wh.` files), merging directories where the most-derived layer wins for metadata, and building the final composefs EROFS image.

### Per-Layer Digests (Future Extension)

Per-layer composefs digests may be added as manifest annotations:

```json
{
  "manifests": [
    {
      "layers": [
        {
          "digest": "sha256:...",
          "annotations": {
            "containers.composefs.layer.fsverity": "sha256:..."
          }
        }
      ]
    }
  ]
}
```

Per-layer digests enable incremental verification during pull, create caching opportunities where shared layers have known composefs digests, and enable runtime choice between flattened versus layered mounting strategies.

### Trust Chain

The trust chain for composefs-verified OCI images flows from external signatures through the manifest to the complete filesystem:

```
External signature (cosign/sigstore/GPG)
  ↓ signs
OCI Manifest (includes config descriptor)
  ↓ digest reference
OCI Config (includes containers.composefs.fsverity label)
  ↓ fsverity digest
Composefs EROFS image
  ↓ contains
Complete merged filesystem tree
```

## Verification Process

Verification begins by fetching the manifest from the registry and verifying the external signature on the manifest. The config descriptor is extracted from the manifest, and the config is fetched and verified to match the descriptor digest. The `containers.composefs.fsverity` label is extracted from the config, and the composefs image is mounted with fsverity verification. The kernel verifies the EROFS matches the expected fsverity digest.

The security property is that signature verification happens once, while filesystem verification is delegated to kernel fs-verity with lazy or eager verification depending on mount options.

## Metadata Schema

### Config Labels

The image config contains the following labels:

The `containers.composefs.fsverity` label (string) contains the fsverity digest of the merged composefs EROFS in the format `<algorithm>:<digest>` where algorithm is `sha256` or `sha512`.

The `containers.composefs.version` label (string, optional) contains the seal format version such as `1.0`.

### Descriptor Annotations

A descriptor may have the following annotation:

The `containers.composefs.layer.fsverity` annotation (string, optional) contains the fsverity digest of that individual layer.

### Label versus Annotation Semantics

Config labels store the authoritative digest because the config represents container identity while the manifest is a transport artifact. Labels are part of the container specification and create a new artifact (sealed image) rather than mutating metadata. Manifest annotations are retained for discovery purposes, allowing registries to identify sealed images without parsing configs and enabling clients to optimize pull strategies.

## Verification Modes

### Eager Verification

Eager verification occurs during image pull. The composefs image is immediately created and its digest is verified against the config label. This makes the container ready to mount immediately after pull and is suitable for boot scenarios where operations should be read-only.

### Lazy Verification

Lazy verification defers composefs creation until first mount. The pull operation stores layers and config but doesn't build the composefs image. On mount, the composefs image is built and verified against the label. This mode is suitable for application containers where many images may be pulled but only some are actually used.

## Security Model

### Registry-Provided Sealed Images

For images sealed by the registry or vendor, the seal is computed during the build process and the seal label is embedded in the published config. An external signature covers the manifest. Clients verify the chain: signature → manifest → config → composefs. Trust is placed in the image producer and the signature key.

### Client-Sealed Images

For images sealed locally by the client, the client pulls an image that may be unsigned and computes the seal locally. The client stores the sealed config in its local repository. On boot or mount, the client can re-fetch the manifest from the network to verify freshness. Trust is placed in the network fetch (TLS) and local verification.

## Attack Mitigation

### Digest Mismatch

If a config label doesn't match the actual EROFS, the mount operation fails the fsverity check. Verification APIs can detect this condition before mounting.

### Signature Bypass

Any attempt to modify the config label without updating the signature fails because the signature covers the manifest, which covers the config digest. Any config change produces a new digest, breaking the signature chain.

### Rollback Attack

For application containers, re-fetching the manifest on boot checks for freshness. For host systems, embedding the manifest in the boot artifact prevents rollback.

### Layer Confusion

Per-layer fsverity annotations allow verification before merging. Implementations that maintain digest maps can link layer SHA256 digests to fsverity digests.

## Relationship to Booting with composefs

OCI sealing is independent from but complementary to composefs boot verification (UKI, BLS, etc.). These are separate mechanisms operating at different stages of the system lifecycle with different trust models.

OCI sealing provides runtime verification of container images distributed through registries. The trust chain typically flows from external signatures (cosign, GPG) through OCI manifests to composefs digests.

Boot verification is designed to be rooted in extant hardware mechanisms such as Secure Boot. The composefs digest is embedded directly in boot artifacts (UKI `.cmdline` section, BLS entry `options` field) and verified during early boot by the initramfs.

These mechanisms work together in a complete workflow where a sealed OCI image can be pulled from a registry, verified through OCI sealing, and then used to build a boot artifact with the composefs digest embedded for boot verification. However, each mechanism operates independently with its own trust anchor and threat model.

## Future Directions

### Dumpfile Digest as Canonical Identifier

The fsverity digest ties implementations to a specific EROFS format. A dumpfile digest (SHA256 of the composefs dumpfile format) would enable format evolution. This would be stored as an additional label `containers.composefs.dumpfile.sha256` alongside the fsverity digest.

The dumpfile format is format-agnostic, meaning the same dumpfile can generate different EROFS versions. This simplifies standardization since the dumpfile format is simpler than EROFS and provides future-proofing to migrate to composefs-over-squashfs or other formats.

The challenge is that verification becomes slower as it requires parsing a saved EROFS from disk to dumpfile format. Caching the dumpfile digest to fsverity digest mapping introduces complexity and security implications. A use case split might apply dumpfile digests to application containers (for format flexibility) while using fsverity digests for host boot (for speed with minimal skew).

### Integration with zstd:chunked

Both zstd:chunked and composefs add new digests to OCI images. The zstd:chunked table-of-contents (TOC) has high overlap with the composefs dumpfile format, as both are metadata about filesystem structure that identify files and their content. The TOC currently uses SHA256 while composefs requires fsverity.

Adding fsverity to zstd:chunked TOC entries would allow using the TOC digest as a canonical composefs identifier. This would support a direct TOC → dumpfile → composefs pipeline, with a single metadata format serving both zstd:chunked and composefs use cases.

### Three-Digest Model

To support both flattened and layered mounting strategies, three digests could be stored per image: a base image digest, a derived layers digest, and a flattened digest. This would enable mounting a single flattened composefs for speed, mounting base and derived separately to avoid metadata amplification, or verifying the base from upstream while only rebuilding derived layers. This aligns with the existing `org.opencontainers.image.base.digest` standard.

## References

**Design discussion**: [composefs/composefs#294](https://github.com/composefs/composefs/issues/294)

**Experimental implementations**:
- [composefs_experiments](https://github.com/allisonkarlitskaya/composefs_experiments)
- [composefs-oci-experimental](https://github.com/cgwalters/composefs-oci-experimental)

**Related issues**:
- [containers/container-libs#108](https://github.com/containers/container-libs/issues/108) - fsverity in zstd:chunked TOC
- [containers/container-libs#112](https://github.com/containers/container-libs/issues/112) - per-layer vs flattened
- [composefs/composefs#409](https://github.com/composefs/composefs/issues/409) - non-root mounting

**Standards**:
- [OCI Image Specification](https://github.com/opencontainers/image-spec)
- [Canonical JSON](https://wiki.laptop.org/go/Canonical_JSON)

## Contributors

This specification synthesizes ideas from Colin Walters (original design proposals and iteration), Allison Karlitskaya (implementation and practical refinements), and Alexander Larsson (security model and non-root mounting insights). Significant assistance from Claude Sonnet 4.5 was used in synthesis.
