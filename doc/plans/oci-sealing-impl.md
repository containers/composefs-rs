# OCI Sealing Implementation in composefs-rs

This document describes the implementation of OCI sealing in composefs-rs. For the generic specification applicable to any composefs implementation, see [oci-sealing-spec.md](oci-sealing-spec.md).

<!-- This document was generated primarily by Claude Sonnet 4.5. Human review level: low-medium -->

## Current Implementation Status

### What Exists

The `composefs-oci` crate at `crates/composefs-oci/src/image.rs` already implements the core sealing mechanism. The `seal()` function computes the fsverity digest via `compute_image_id()`, creates an EROFS image from merged layers with whiteouts applied, and stores the digest in `config.labels["containers.composefs.fsverity"]`. A new config with updated labels is written via `write_config()`, returning both the SHA256 config digest and fsverity image digest.

The implementation includes fsverity computation and verification through the `composefs` crate's fsverity module. Config label storage follows the OCI specification with digest mapping from SHA256 to fsverity maintained in split streams. Repository-level integrity verification is provided through `check_stream()` and `check_image()`. Mount operations check for the seal label and use fsverity verification when present.

All objects in the repository are fsverity-enabled by default, with digests stored using the generic `ObjectID` type parameterized over `FsVerityHashValue`. Images are tracked separately in the `images/` directory, distinct from general objects due to the kernel security model that restricts non-root filesystem mounting.

### Current Workflow

The sealing workflow in composefs-rs begins with `create_filesystem()` building the filesystem from OCI layers. Layer tar streams are imported via `import_layer()`, converting them to composefs split streams. Files 64 bytes or smaller are stored inline in the split stream, while larger files are stored in the object store with fsverity digests. Layers are processed in order, applying overlayfs semantics including whiteout handling (`.wh.` files). Hardlinks are tracked properly across layers to maintain filesystem semantics.

After building the filesystem, `compute_image_id()` generates the EROFS image and computes its fsverity digest. The digest is stored in the config label `containers.composefs.fsverity`. The `write_config()` function writes the new config to the repository with the digest mapping, and both the SHA256 config digest and fsverity image digest are returned.

For mounting, the `mount()` operation requires the `containers.composefs.fsverity` label to be present. It extracts the image ID from the label and mounts at the specified path with kernel fsverity verification.

## Repository Architecture

The composefs-rs repository architecture at `crates/composefs/src/repository.rs` supports sealing without major changes. Objects are stored in a content-addressed layout under `objects/XX/YYY...` where `XX` is the first byte of the fsverity digest and `YYY` are the remaining 62 hex characters. All files in `objects/` must have fsverity enabled, enforced via `ensure_verity_equal()`.

Images are tracked separately in the `images/` directory as symlinks to objects, with refs providing named references and garbage collection roots. Split streams are stored in the `streams/` directory, also as symlinks to objects. The repository has an "insecure" mode for development without fsverity filesystem support, but sealing operations should explicitly fail in this mode.

Two-level naming allows access by fsverity digest (verified) or by ref name (unverified). The `ensure_stream()` method provides idempotent stream creation with SHA256-based deduplication. Streams can reference other streams via digest maps stored in split stream headers, enabling the layer→config relationship tracking.

## Required Enhancements

### Manifest Annotations

Manifest annotations should be added to indicate sealed images and enable discovery without parsing configs. The sealing operation should add `containers.composefs.sealed` set to `"true"` and optionally `containers.composefs.image.fsverity` containing the image digest. This allows registries to discover sealed images and clients to optimize pull strategies.

### Per-Layer Digest Annotations

Per-layer digests enable incremental verification and caching. A `SealedImageInfo` structure should track the image fsverity digest, config SHA256 digest, optional config fsverity digest, and a list of layer seal information. Each `LayerSealInfo` entry should contain the original tar layer digest, the composefs fsverity of the layer, and the split stream digest in the repository.

During sealing, layer descriptors should be annotated with `containers.composefs.layer.fsverity` after processing each layer. This allows verification of individual layers before merging and enables caching where shared layers have known composefs digests.

### Verification API

A standalone verification API separate from mounting should be implemented. The verification function should check manifest annotations for the seal flag, fetch and verify the config against the manifest's config descriptor, extract the fsverity digest from the config label, verify annotated layers if present, and optionally verify the image exists in the repository.

This enables verification before mounting and provides detailed seal information without building the filesystem. The returned `SealedImageInfo` structure contains all digest relationships and layer details.

### Pull Integration

The `pull()` function in `crates/composefs-oci/src/image.rs` should be enhanced to handle sealed images. When a verify_seal flag is enabled, the pull operation should check manifest annotations for the sealed flag and verify the seal during pull if present. If the image is sealed and verification passes, some integrity checks can be skipped since the composefs digests are trusted.

An optimization is that sealed images don't require re-computing digests during import if verification already passed. The pull result should include optional seal information alongside the manifest and config.

### Push Integration

Support for pushing sealed images back to registries requires preserving seal annotations through the registry round-trip. The push operation should construct the manifest with seal annotations, push the config with the composefs label, push layers optionally with layer annotations, and push the manifest with seal annotations.

The challenge is maintaining digest mappings through the registry round-trip, as registries may re-compress or re-package layers while preserving content digests.

### Insecure Mode Handling

Repository sealing operations should explicitly fail when the repository is in insecure mode. The rationale is that if the repository doesn't enforce fsverity, sealing provides no security benefit. The check should be performed at the beginning of seal operations, returning an error if `repo.is_insecure()` is true.

## Implementation Phases

### Phase 1: Core Sealing (Completed)

Phase 1 is complete with basic `seal()` implementation in `composefs-oci`, fsverity computation and storage, config label with digest, and mount with seal verification.

### Phase 2: Manifest Annotations (Planned)

Phase 2 will add manifest annotation support to `seal()`, create the `SealedImageInfo` type, implement the `verify_seal()` API, document the label/annotation schema, and add tests for sealed image workflows.

Deliverables include `seal()` emitting manifests with annotations, standalone verification without mounting, and updated documentation in `doc/oci.md`.

### Phase 3: Per-Layer Digests (Planned)

Phase 3 will record per-layer fsverity during sealing, add layer annotations to manifests, implement incremental verification, and optimize pull for sealed images.

Deliverables include full `SealedImageInfo` with layer details, layer-by-layer verification API, and performance improvements for sealed pulls.

### Phase 4: Push/Registry Integration (Planned)

Phase 4 will implement push support for sealed images, preserve annotations through registry round-trip, test with standard OCI registries, and document registry compatibility.

Deliverables include bidirectional registry support, a registry compatibility matrix, and integration tests with real registries.

### Phase 5: Advanced Features (Future)

Future work includes dumpfile digest support, eager/lazy verification modes, zstd:chunked integration, the three-digest model, and signature integration.

## API Design Considerations

### Type Safety

The generic `ObjectID` type parameterized over `FsVerityHashValue` provides type safety for digest handling. Both `Sha256HashValue` and `Sha512HashValue` implement the `FsVerityHashValue` trait with hex encoding/decoding, object pathname format, and algorithm ID constants.

### Async/Await

Operations like `seal()` and `pull()` are async to support parallel layer fetching with semaphore-based concurrency control. The repository is wrapped in `Arc` to enable sharing across async contexts.

### Error Handling

The codebase uses `anyhow::Result` for error handling with context. Seal operations should provide clear error messages distinguishing between fsverity failures, missing labels, and repository integrity issues.

### Verification Modes

Supporting both eager and lazy verification requires a configuration option, potentially as an enum `SealVerificationMode` with variants `Eager`, `Lazy`, and `Never`. Different defaults may apply for user versus system repositories.

## Integration Points

### Split Streams

Split streams at `crates/composefs/src/splitstream.rs` are the intermediate format between OCI tar layers and composefs EROFS images. They contain inline data for small files and references to objects for large files. Split stream headers include digest maps linking SHA256 layer digests to fsverity digests.

Per-layer sealing should leverage split streams to maintain the digest mapping. The split stream format doesn't need changes but seal metadata should reference split stream digests.

### EROFS Generation

EROFS image generation via `mkfs_erofs()` in `crates/composefs/src/erofs/` creates reproducible images from filesystem trees. The EROFS writer handles inline data, shared data, and metadata blocks with deterministic layout. The same input filesystem produces the same EROFS digest.

Sealing relies on this determinism for verification. The EROFS format version may evolve, which is why dumpfile digests are being considered as a format-agnostic alternative.

### Fsverity Module

The fsverity module at `crates/composefs/src/fsverity/` provides userspace computation matching kernel behavior and ioctl wrappers for kernel interaction. Digest computation uses a hardcoded 4096-byte block size with no salt support, matching kernel fs-verity defaults.

Sealing uses `compute_verity()` for userspace digest computation during EROFS generation and `enable_verity_maybe_copy()` to handle ETXTBSY by copying files if needed. Verification uses `measure_verity()` to get kernel-measured digests and `ensure_verity_equal()` to compare against expected values.

## Open Implementation Questions

### Config Annotation Method

The current code calls `config.get_config_annotation()` which actually reads from labels, not annotations. This naming suggests potential confusion between OCI label and annotation semantics. Clarification is needed whether storing in labels is intentional or if annotations should be used for the digest.

### Sealed Config Mutability

Sealing modifies config content by adding the label, creating a new SHA256 for the config and breaking existing references to the old config digest. This may be acceptable since the sealed config is a new artifact, but it needs clear documentation about the relationship between sealed and unsealed images.

### Performance at Scale

Computing fsverity for large images is expensive as `compute_image_id()` builds the entire EROFS in memory. Streaming approaches or caching strategies should be considered for multi-GB images. The EROFS writer could be enhanced to support streaming output with incremental digest computation.

### Seal Metadata Persistence

Optionally persisting `SealedImageInfo` as `<fsverity-digest>.seal.json` alongside images in the repository could enable faster seal information retrieval without re-parsing configs. This metadata cache would need invalidation strategies and shouldn't be security-critical.

### Repository Ref Strategy

Sealed images have different config digests than unsealed images. The ref strategy for managing variants should avoid keeping both sealed and unsealed versions indefinitely. Garbage collection should understand the relationship between sealed and unsealed images, potentially tracking seal derivation relationships.

## Testing Strategy

Testing should cover sealing unsealed images and verifying the config label is added correctly with the expected fsverity digest. Mounting sealed images should verify that fsverity is checked by the kernel. Verification API tests should check correct extraction of seal information from manifest and config.

Per-layer annotation tests should verify layer digests are computed and annotated correctly. Pull integration tests should verify detection and verification of sealed images during pull. Push integration tests should verify seal metadata is preserved through registry round-trip.

Negative tests should verify that seal operations fail in insecure mode, mounting fails with incorrect fsverity digest, and verification fails with missing or incorrect labels.

Performance tests should measure sealing time for various image sizes and verify parallel layer processing performance.

## Compatibility Considerations

### OCI Registry Compatibility

Standard OCI registries should store and serve sealed images without special handling. Unknown labels and annotations are preserved by spec-compliant registries. Testing should verify round-trip through common registries like Docker Hub, Quay, and GitHub Container Registry.

### Existing Composefs-rs Versions

The seal format version label enables detection of format changes. Forward compatibility means newer implementations can read older seals. Backward compatibility means older implementations should gracefully ignore newer seal formats they don't understand.

### C Composefs Compatibility

While composefs-rs aims to become the reference implementation, compatibility with the C composefs implementation should be maintained where feasible. EROFS images and dumpfiles should be interchangeable. Digest computation must match exactly between implementations.

## Future Implementation Work

### Dumpfile Digest Support

Supporting dumpfile digests requires adding `containers.composefs.dumpfile.sha256` label computation during sealing. Verification should support parsing EROFS back to dumpfile format and verifying the digest. Caching the dumpfile→fsverity mapping requires careful security consideration to avoid cache poisoning.

### zstd:chunked Integration

Integration with zstd:chunked requires reading and writing TOC metadata with fsverity digests added to entries. The TOC format from the estargz/stargz-snapshotter projects would need extension for fsverity. Direct TOC→dumpfile conversion would enable unified metadata handling.

### Non-Root Mounting Helper

A separate composefs-mount-helper service would accept dumpfiles from unprivileged users, generate EROFS images, validate fsverity, and return mount file descriptors. This requires privileged service implementation with careful input validation on the dumpfile format.

### Signature Integration

Integrating with cosign or sigstore requires fetching and verifying signatures during pull, associating signatures with sealed images in the repository, and potentially storing signature references in seal metadata. The signature verification should happen before seal verification in the trust chain.

## References

See [oci-sealing-spec.md](oci-sealing-spec.md) for the generic specification and complete reference list.

**Implementation references**:
- `crates/composefs-oci/src/image.rs` - OCI image operations including seal()
- `crates/composefs/src/repository.rs` - Repository management
- `crates/composefs/src/fsverity/` - Fsverity computation and verification
- `crates/composefs/src/splitstream.rs` - Split stream format
- `crates/composefs/src/erofs/` - EROFS generation

**Related composefs-rs issues**:
- Check for existing issues about OCI sealing enhancements
- File new issues for specific implementation work items
