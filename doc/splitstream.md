# Split Stream

Split Stream is a trivial way of storing file formats (like tar) with the "data
blocks" stored in the composefs object tree with the goal that it's possible to
bit-for-bit recreate the entire file.  It's something like the idea behind
[tar-split](https://github.com/vbatts/tar-split), with some important differences:

 - although it's designed with `tar` files in mind, it's not specific to `tar`,
   or even to the idea of an archive file: any file format can be stored as a
   splitstream, and it might make sense to do so for any file format that
   contains large chunks of embedded data

 - it's based on storing external objects in the composefs object store

 - it's based on a trivial binary format

It is expected that the splitstream will be compressed before being stored on
disk.  In composefs, this is done using zstd.  The main reason for this is
that, after removing the actual file data, the remaining `tar` metadata
contains a very large amount of padding and empty space and compresses
extremely well.

## File format

The file format consists of a header, followed by a set of data blocks.

### Header

The header format looks like this, where all fields are little endian:

```
pub const SPLITSTREAM_MAGIC : [u8; 7] = [b'S', b'p', b'l', b't', b'S', b't', b'r'];

struct MappingEntry {
    pub body: Sha256Digest,
    pub reference_idx: u64, // index into references table
}

struct SplitstreamHeader {
    magic: [u8; 7], // Contains SPLITSTREAM_MAGIC
    algorithm: u8,  // The fs-verity algorithm used, 1 == sha256, 2 == sha512
    total_size: u64, // total size of inline chunks and external chunks
    n_refs: u64,
    n_mappings: u64,
    refs: [ObjectID; n_refs]    // sorted
    mappings: [MappingEntry; n_mappings] // sorted by body
}
```

The table of references are used to allow splitstreams to refer to
other splitstreams or regular file content, either because it is
included in the stream, or just indirectly referenced. This is primarily
used to keep these objects alive during garbage collection.

Examples of references are:
 * OCI manifests reference splitstreams for tar layer split streams.
 * External objects embedded in a splitstream, such as a tar layer
   splitstream
 * External objects indirectly references in a splitstream, such as
   references from an ostree commit splitstream

The mapping table provides a mechanismn to map the sha256 digest of a
split stream to a fs-verity digest. This allows checking of the target
fs-verity digest before use. The primary example here is OCI manifests
which reference the tar layer splitstreams. We could look up such
streams by the sha256 in the streams/ directory, but then we will not
have trusted information about what expected fs-verity the layers
would have.

### Data blocks

After the header comes a number of data blocks.  Each block starts with a u64
le "size" field followed by some amount of data.

```
     64bit    variable-sized
   +--------+---------------....
   | size   | data...
   +--------+---------------....
```

There are two kinds of blocks:

  - "Inline" blocks (`size != 0`): in this case the length of the data is equal
    to the size.  This is "inline data" and is usually used for the metadata
    and padding present in the source file.  The Split Stream format itself
    doesn't have any padding, which implies that the size fields after the
    first may be unaligned.  This decision was taken to keep the format simple,
    and because the data is compressed before being stored, which removes the
    main advantages of aligned data.

  - "External" blocks (`size == 0`): in this case the length of the data is 32
    bytes.  This is the binary form of a sha256 hash value and is a reference
    to an object in the composefs repository (by its fs-verity digest).
    Note that these references are *also* in the header, so there is no need
    to read the entire file to find what objects are referenced.

That's it, really.  There's no header.  The stream is over when there are no
more blocks.
