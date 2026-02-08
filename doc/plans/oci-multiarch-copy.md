# Multi-Architecture Image Support

This document sketches the design for storing multi-arch (manifest list / OCI index) images in the composefs repository.

## Problem

The composefs repository currently stores only single-platform images. When pulling via the skopeo proxy, manifest lists are resolved to the native platform before we ever see them — we receive a single-platform manifest and its layers. This is fine for running containers locally, but insufficient for mirroring and local caching use cases where the goal is to preserve all platforms in a single logical image.

Round-trip fidelity matters here: if a user pulls a multi-arch image from a registry, stores it locally, and later pushes it back, the result should be identical to the original. That requires storing the index and all per-platform manifests with their original JSON bytes intact.

## Import Path

The skopeo proxy resolves platform at the transport level, so we can't use it to obtain the raw index. Instead, the import path for multi-arch images uses OCI layout directories directly. The workflow is:

```
skopeo copy docker://registry/image:tag oci:local-dir:tag
cfsctl import-oci local-dir --all-platforms
```

The `skopeo copy` to an `oci:` destination preserves the full manifest list in the layout's `index.json`. We then read the layout ourselves: parse `index.json`, walk descriptors, and fetch blobs by digest from `blobs/sha256/`. This is straightforward — an OCI layout is just a directory of content-addressed blobs plus a small index.

We'll add a dep on `ocidir` for this.

## Storage Model

### Index Splitstreams

An OCI index gets a new content type `"ociindx"` (i.e. `u64::from_le_bytes(*b"ociindx\0")`), stored alongside the existing `ocimanif` and `ociconfg` types. The stream identifier follows the same pattern: `oci-index-sha256:<digest>`.

Like manifests and configs, the index JSON is stored as an external object — the splitstream holds a single object reference plus named refs to each per-platform manifest. This reuses the existing `read_external_splitstream` / `write_external_splitstream` pattern unchanged.

The named refs in the index splitstream point to manifest streams (`oci-manifest-sha256:...`), which in turn point to their configs and layers. GC reachability works transitively through this chain with no changes to the collector.

### Tags and Resolution

Today, tags are symlinks pointing at manifest streams. With index support, a tag may point at either an `oci-index-sha256:...` or an `oci-manifest-sha256:...` stream. The `resolve_ref` function needs to distinguish these cases.

The cleanest approach is an `OciRef` enum:

```rust
pub enum OciRef<ObjectID> {
    Manifest { digest: Sha256HashValue, verity: Option<ObjectID> },
    Index { digest: Sha256HashValue, verity: Option<ObjectID> },
}
```

Callers that only work with single-platform manifests (like `mount`) would call a convenience method that resolves through the index to the native platform. Callers that care about the full index (like mirror/export) use the enum directly. `list_images` returns both kinds, possibly with a flag or filter.

### Layer Storage: Copy vs Pull

A manifest list copy is a pure storage operation — no layers are splitstreamed, not even for the native architecture. All layer blobs are stored as-is in their original compressed form (gzip, zstd, etc.) via `write_blob`. This keeps the copy fast and preserves bit-identical round-trip fidelity for push-back to registries.

When a user later explicitly pulls a specific per-arch image (e.g. `cfsctl pull`), the pull logic can detect that the compressed layer blobs already exist locally (they were stored during the manifest list copy). Instead of re-fetching from the registry, it decompresses them locally and imports them as splitstreams. This is an optimization — the normal pull path still works, it just avoids redundant network transfer.

This two-phase approach (copy stores compressed blobs, pull splitstreams them on demand) cleanly separates mirroring from mounting. OCI artifacts follow the same pattern: manifest → blob, always flat (no artifact → artifact chaining in the spec), so a manifest list is the only real case of multi-level indirection.

Cross-platform layer dedup happens automatically via content addressing — if two platforms share a layer, the blob is stored once.

## Key Design Decisions

**Content hash fidelity.** Index and manifest JSON must be stored as raw bytes, never re-serialized. OCI registries compute digests over the exact byte sequence; re-serialization would break signatures and digest references. The external object pattern already handles this correctly.

**Nested indexes.** The OCI spec allows indexes to reference other indexes. This is rare in practice (mostly theoretical). The initial implementation should handle one level of index → manifest. Nested indexes can be added later by making `write_index` recursive. Not worth the complexity up front.

**Tag ambiguity.** The `OciRef` enum described above is the primary mechanism. An alternative is separate tag namespaces, but that fragments the user-facing model unnecessarily. A single tag pointing to either type is simpler.

**`ocidir` dependency.** We'll use the `ocidir` crate for OCI layout reading and eventually writing (push-to-OCI-layout).

## Rough Change List

`crates/composefs-oci/src/skopeo.rs` — add `OCI_INDEX_CONTENT_TYPE` constant alongside the existing content types.

`crates/composefs-oci/src/oci_image.rs` — add `OciIndex` type mirroring `OciImage`, with `write_index()` and `has_index()` functions following the `write_manifest()` / `has_manifest()` pattern. Update `resolve_ref` to return `OciRef` enum. Update `list_images` for index awareness.

`crates/composefs-oci/src/oci_layout.rs` (new) — OCI layout directory reading: parse `index.json`, resolve descriptors to blobs, iterate manifests within an index.

`crates/composefs-oci/src/import.rs` or extend `skopeo.rs` — multi-arch import logic: walk the index, store all layers as compressed blobs. On per-arch pull, detect locally-available compressed blobs and decompress/splitstream them instead of re-fetching.

`crates/cfsctl/src/main.rs` — `--all-platforms` flag on import, `--platform` selector on mount, display index metadata in `list`.

## Open Questions

How should `cfsctl list` display multi-arch images? One row per index with a platform count, or expanded per-platform rows? Probably the former by default with a `--all-platforms` flag to expand.

Should we support partial platform import (e.g. `--platform linux/amd64,linux/arm64`)? Useful for constrained mirrors. Straightforward to implement as a filter during import.

What's the mount behavior when a tag points to an index? Resolve to native platform automatically, or require explicit `--platform`? Automatic resolution with a warning if ambiguous seems right.
