# erofs: the missing manual

## Introduction

This is an attempt to document the format of erofs (or at least the subsets of
it that we use in composefs).

It probably makes sense to have `erofs_fs.h` open when reading this.

## Overall concepts

All integers (including all offsets) are stored in little-endian byte order.

The file layout is fairly free-form.  You can freely mix inodes, data blocks,
and shared xattr entries.  inodes are 64-bit values based on file offsets
rather than integer indexes into a fixed table, so they can be anywhere at all.
xattrs are 32-bit values based on offsets, so they're a bit more limited (but
not in filesystems of reasonable size).

## The first 1024 bytes (pre-superblock)

The first 1024 bytes of an erofs have no particular meaning.  You can put
anything you want there, like partition tables or boot sectors or anything
else.  composefs puts its own header inside of this area, at the start.

## The superblock (at 1024 bytes, 128 bytes long)

The superblock is defined by `struct erofs_super_block`.

Here's some notes about some of the fields.  Anything not mentioned is left as
0 by us. There's some pretty wild features in here, but we don't use them all
(and I don't understand them, either) so they're not all documented.

*   `magic`: set that to `EROFS_SUPER_MAGIC_V1` (`0xE0F5E1E2`)
*   `checksum`: only meaningful of the `SB_CHKSUM` feature is enabled.  This is
    a crc32c over a block-sized-chunk of data starting from the superblock,
    with this field set to 0.  That's pretty weird.  Maybe don't use this.
*   `feature_compat`: a flags field.  The filesystem will still mount even if
    the kernel doesn't know about any features which might be present.  The
    flags:
    -   `SB_CHKSUM` (`0x0001`): set if the checksum field in the superblock is
        populated.  Otherwise, the checksum is ignored.
    -   `MTIME` (`0x0002`): at first, erofs named the timestamp fields `ctime`
        instead of `mtime`.  That got changed a long time ago, and this flag
        got added to indicate filesystems that were created with the new
        semantics. This flag has absolutely zero impact at run time: the kernel
        ignores it.
    -   `XATTR_FILTER` (`0x0004`): set if the xattr bloom filter should be
        used.  Read about this in the inode section.
*   `blkszbits`: log2 of the block size.  Better set this to 12 (4096).
*   `root_nid`: the reference to the root inode.  See the inodes section for
    what that means.  Normally inodes are stored in u64, but this is somewhat
    randomly a u16, which means that you're gonna need to put the root
    directory near the start.
*   `inos`: the total number of inodes defined.  This is only used for
    `statfs()` purposes.
*   `build_time`, `build_time_nsec`: this is something like a compression
    feature if you want all (or many) files in your filesystem to have the same
    mtime.  Then you can use the "compact" inode layout, which doesn't have its
    own `mtime` field, and this one will be used instead.  If you don't have
    compact inodes then this is meaningless.
*   `blocks`: total filesystem block size.  This is only used for `statfs()`.
*   `meta_blkaddr`: the start of the "metadata area".  This is where the inodes
    are.  This is a block address, so it gets multiplied by the block size to
    determine the actual offset.
*   `xattr_blkaddr`: the start of the "shared xattr area".  See the "Shared
    xattr" and "Inodes" sections for more info.

## Extended attributes

There are two options for storing xattr data in a erofs:
*   inline with the inode itself
*   in a "shared xattr" struct somewhere

The format of both of these is the same.

The inline thing is nice and simple, but it might be space-inefficient for
cases where the same (key, value) pair appears over and over again (which might
be the case for things like security labels and acls and the like).

### Prefix indexes

A rudimentary form of compression is supported on xattr names.  There are a
number of hardcoded "common prefixes" defined with the `EROFS_XATTR_INDEX_`
constants in `erofs_fs.h`.  Confusingly, although `LUSTRE` is present, it's not
wired up in the kernel.  Don't use that one.

The basic idea is that you find the prefix for your xattr from the list (like
`user.` or `security.`) and then you store only the "suffix" part, along with
the prefix index.  If you can't find a prefix, you use 0 (which is conceptually
a prefix of "").  If the prefix matches the entire name then the suffix is `""`.

Note: you really need to do this "compression" step, because it's assumed
during the lookup phase.  ie: if we're looking for an xattr `"user.xyz"` then
we'll only consider the entries that have the prefix index for `user.` set on
them.  If you didn't properly "compress" your xattr names, they won't be found.

There's support in the erofs format for custom prefixes.  That's when the high
bit of the prefix index is set.  These got added circa kernel version 6.4 with
a patch series ending with `6a318ccd7e08` ("erofs: enable long extended
attribute name prefixes") but aren't documented here because we don't use them.

### On-disk format

All extended attributes (both shared and inode-inline) are stored in a
simple format with a small header.  That's `struct erofs_xattr_entry`.  It's just 4 bytes:
*   u8: the suffix length (in bytes, no nul)
*   u8: the prefix index (see above)
*   u16: the value length (in bytes, no nul)

The header must start at an offset with an alignment of 4.

Immediately following the header is the suffix (name with prefix removed),
immediately followed by the value.  There's no nul after the name (which is OK,
since we know the length from the header).

### Shared xattrs

This is basically just an xattr stored somewhere in the filesystem image, using
the format mentioned above.  It is referred to by a 32-bit identifier:
*   start at the `xattr_blkaddr` mentioned in the super block.  That's a block
    address, so remember to multiply that by the block size.
*   add 4 times the shared xattr identifier (since the header must be 4-aligned)
*   that's the xattr header (mentioned above)

If your filesystem image is going to be smaller than 16GB then you can probably
just leave the `xattr_blkaddr` set to 0 to make your life easier.

### Inode-inline xattrs

We talk about those in the Inode section.  Speaking of which, let's talk about...

## Inodes

Here's where things get complicated.

First, the easy part: similar to shared xattrs, inodes are just a structure
stored somewhere in the filesystem image.  There's no "inode table".  This
works because the way that you refer to inodes is with an "nid":
*   start at the `meta_blkaddr` mentioned in the super block.  That's a block
    address, so remember to multiply that by the block size.
*   add 32 times the nid (since inodes must be 32-aligned)
*   that's the inode header

### On-disk formats

The very first thing in the inode is the format field.  This is a mix of two
things, but the most important thing to talk about first is the low-order bit:
it's set to 0 if this is a "compact" inode and 1 if it's a "extended" inode.

We don't use compact inodes, so I'm not going to document them, but you can get
a pretty good idea of what they're capable of by reading the headers.  The rest
of this section discusses extended inodes.

The extended inode header (`struct erofs_inode_extended`) has a size of 64 and
needs to be 32-aligned.  It has these interesting fields:
*   `format`:
    -   first bit: as mentioned above, for an extended inode the low order bit
        will always be set
    -   the rest: the "data layout" (which is complicated enough to get its own
        section)
*   `xattr_icount`: this is also complicated enough that we want to talk about
    it elsewhere.  See the "Extended attributes" section below (not the one
    above!).  The main thing to know is that this will be 0 if there are none.
*   `mode`: that's the same like you'd find in `.st_mode` from `stat()`
*   `size`: ditto, except `.st_size`
*   `i_u`: you'd better look at the "data layout" section about this one...
*   `ino`: a compatibility shim for cases where we need to report `st_ino` in
    32-bits.  For 64-bit userlands, we use the nid directly as the `.st_ino`.
    You can do what you want with this (as long as it's unique), but for
    filesystems smaller than 128GB you can probably just use the nid.
*   `uid`, `gid`: those are fairly obvious, I guess
*   `mtime`, `mtime_nsec`: those too
*   `nlink`: try to set this correctly: some things might get upset if it's not
    right.  For non-directories, that's the number of hardlinks (ie: 1 for
    non-hardlinked files).  For directories, that's 2 plus the number of
    subdirectories.

Directly following the inode header is the extended attribute header (if
`xattr_icount` is non-zero).  Then comes any inline data (as per the "data
layout" section).

### Extended attributes

If the `xattr_icount` field in the inode header is set to 0 then this section
is skipped entirely.  Otherwise we write out the inode xattr header (`struct
erofs_xattr_ibody_header`).  This has:
*   `name_filter` (`u32`): a bloom filter for which xattrs are present.  This
    needs its own section.
*   `shared_count` (`u8`): the number of shared xattrs
*   some reserved bytes to pad things up to 12

Immediately following the header come the shared xattr references.  They're in
the format mentioned in the "Shared xattrs" section above, simply encoded as
little-endian u32s.  So: the first `4 * shared_count` bytes after the header
are those.

Then the inline xattrs are next.  Those are stored in the format mentioned in
the "On-disk format" sub-section in the "Extended attributes" section.  They're
just written here one after another, with padding added so that each header is
4-aligned.  There is also padding after the last one, which is important if
inline data is to follow (as per the "data layout" section).

#### About `xattr_icount`

So, if there's no xattrs then this is zero.

Otherwise this is basically the size of the extended attributes area divided by
4, with the exception that the 12-byte header counts for only 4 bytes.  Put
another way: you remove the size of the header, divide by 4, then add 1 back
again.

A value of 1 would be pretty suspicious, since that would indicate the presence
of a header, but no xattrs (shared or inline), and in that case normally we'd
omit the header.

The kernel basically uses this to know how many bytes it needs to skip over
before it can find the inline file data.  It will remove the 1, multiply by 4,
then add 12 (the header).  See `erofs_xattr_ibody_size()`.

#### About `name_filter`

This is a 32-bit bloom filter used to quickly determine if a given xattr is not present.

The hash algorithm is xxh32.  The thing that gets hashed is not the name, but
the "suffix" that's left after removing the prefix.  The seed is
`EROFS_XATTR_FILTER_SEED` plus the prefix index.  The lower 5 bits of the hash
value (0..31) are used to determine which bit is used.

For some reason a bit value of 1 here indicates the absence of a particular
xattr, which is opposite to the usual arrangement.  You'd think it was for
compatibility, but the filter is only engaged if the feature bit is present in
the superblock.

This feature got added in kernel commits:
*   `3f339920175c` ("erofs: update on-disk format for xattr name filter")
*   `fd73a4395d47` ("erofs: boost negative xattr lookup with bloom filter")

### Data layout

erofs has a bunch of different ways to represent the actual content associated
with an inode (regular file content, directory entries, symlink target).

We describe three of them here:
*   plain
*   inline
*   chunked

The data layout is chosen using some of the bits of the `format` field in the
inode header.

#### `EROFS_INODE_FLAT_PLAIN`

In this case there's never any inline data.  The inode content is stored
entirely as a series of contiguous blocks.  The offset of the first block is
what goes in the `i_u` field (measured in blocks, not bytes).

The number of blocks is determined by the `.size` field (divided by block size,
rounded up).

If the content is not a multiple of the blocksize then the last block should be
0-padded.

#### `EROFS_INODE_FLAT_INLINE`

This is similar to `EROFS_INODE_FLAT_PLAIN` except if the content is not a
multiple of the blocksize.  In that case, instead of 0-padding the last block
to fill up a block, the content of the last block is stored directly inline
with the inode, without padding.

So, imagining the content is 2.5 blocks worth of data:
*   the first block is the one pointed to by `i_u`
*   the second block is the one immediately following it
*   the last block is stored at the end of the inode

The number of blocks is determined by the `.size` field, divided by block size,
rounded down.  The remainder is the number of bytes of inline data.

The inline data must be written in such a way that it does not cross a block
boundary.  It is theoretically permitted for the inline data to be in a
separate block (ie: the block directly following the inode data).  It is also
permitted for the inode data itself to cross block boundaries.  There are a
couple of caveats to be aware of, however:
*   the alignment of inodes is 32 bytes, but the size of an extended inode is 64
    bytes.  `mkfs.erofs` tries to ensure that extended inodes headers land
    entirely within on disk block (for efficiency), but this isn't required by
    the kernel.
*   `mkfs.erofs` also tries to ensure that the inline data ends in the same
    disk block as the last byte of the inode metadata (ie: inode header plus
    xattrs).  This is theoretically not required by the kernel.
*   A bug present in the kernel before 6.12 meant that this was required for
    inline symlink targets. This was fixed by `9ed50b8231e3` ("erofs: fix
    incorrect symlink detection in fast symlink").
*   In general, when faced with the task of writing out an inode with inline
    data present, you may need to add padding bytes before the start of the
    inode in order to ensure that the inline data falls within a single block.
    If you allow inlining of large amounts of data (approaching the block size)
    then you'll almost always need to add padding to get the correct alignment
    (and often a large amount of it), which is wasteful.  On the other hand, if
    you only inline very small amounts of data then you are wasting space by
    padding out filesystem blocks with zeros. There is a balance to be struck,
    and `mkcomposefs` uses a "heuristic" of half a block size as the inlining
    limit.  I've performed simulations which show that this value is fairly
    close to ideal for a random distribution of file sizes, starting inode
    alignment and xattr content sizes.

#### `EROFS_INODE_FLAT_CHUNK_BASED`

In this case, the `i_u` field isn't a block reference but is instead split into
sub-fields.  The main gist of it, though, is that this stores the log2 of the
number of blocks per chunk (maximum of 31).

So if you write 4 here, then there are 16 blocks in each chunk.

The references to the chunks are then written as the inline data, 4 bytes per
chunk, as block indexes (to the starting block).  I'm not sure if that's
measured in blocks or in chunks, because the only reason we use this feature is
for a special purpose: null chunks.

If a chunk index is written as -1 (ie: 0xffffffff) then it refers to a "null"
chunk of the given size.  This effectively gets you support for sparse files.

For the sparse file use-case there's no benefit to choosing anything other than
the maximum chunk format of 31 for the `-i_u` field.  The number of chunks you
need to write is determined by the file size, but for a 4096 byte block size
and a chunk format of 31 all files less than 8TB can be handled with a single
"chunk".

#### Character and block devices

If the `mode` field of the inode indicates that this is a device, then the data
layout isn't relevant, and the `i_u` field gets the `rdev` of the device.  Note
that this is a 32-bit field, so 32-bit rdev.  `size` is zero.


#### Fifos and sockets

These have no storage at all.  `i_u` is ignored and there is never inline data.
`size` should always be 0.

## Directories

The final thing that needs describing is how a directory gets stored.  erofs
directories are the classical mapping from names to inodes, with the extra
'file type' field that gets returned via the `d_type` field in `struct dirent`
(to avoid needing to `stat()` the inode).

The dirent structure has a size of 12 (and an alignment of 4) and looks like:
*   `nid` (`u64`): the inode referred to by this entry
*   `nameoff` (`u16`): an offset to the name (inside of this block).  See below.
*   `file_type` (`u8`): the filetype field for `d_type`

The directory needs to explicitly include the `.` and `..` entries.  All
entries (including `.` and `..`) are sorted in asciibetical order.  Note: the
`.` and `..` are not handled specially and are not necessarily at the start:
they're in asciibetical order too.

The directory entries are taken in their sorted order and split into blocks.
However many entries will fit into the first block go into the first block, and
so on.  All blocks except for the last one are padded with zeros.  A directory
has a specific encoded size (which ends up in the `size` field of the inode).
It is made from a number of complete blocks, times the blocksize, plus the size
of the (possible) trailing partial block (which might be inlined, depending on
the selected data layout).

Each block is a number of dirent structs packed at the start, plus the entry
names referred to from those structs.  The entry names must immediately follow
the structs, and each entry name must immediately follow the previous (with no
nul).  The reason for that will become clear with our example:

Let's consider an example directory with entries `.`, `..`,
`someverylongfilename`, `subdir`. To keep things interesting, let's further
imagine that our filesystem block size is 32 bytes.

We segment into blocks by taking entries until no more entries fit.  Each entry
is the 12 byte dirent struct, plus the name, so:
*   `.`: (12 + 1) = 13 → 13 total bytes
*   `..`: (12 + 2) = 14 → 27 total bytes
*   `file`: (12 + 4) = 16 → too big, won't fit.

So we know that the first directory block will contain `.` and `..`.  It looks like:
*   offset `0`: the dirent struct for `.`, `nameoff` is `24`.
*   offset `12`: the dirent struct for `..`, `nameoff` is `25`.
*   offset `24`: `.`
*   offset `25`: `..`
*   offset `27`: padded with `nul`

The `nameoff` fields are more important here than they seem.  If we look at the
first `nameoff` field, it's `24`.  That tells us that there are two entries in
this block (since the entry size is 12).  We also know the length of the name
of the first entry because the name of the second entry starts right after it.

How do we know the name of the last entry?  One of three ways:
*   if this is the final block of the directory, then the overall size of the
    directory (in the inode `size` field) will indicate where the final name
    must surely terminate
*   if this is a non-final block, it might be that the name fits exactly into
    the block size.  In that case, the end of the name is the end of the block.
*   if this is a non-final block, and the name doesn't fit exactly into the
    block size then it means we'll have added some padding.  In this case the
    name is `nul`-terminated.  That's the case for our `..` entry here.

Now let's do our next block:
*   `someverylongfilename` (12 + 20) = 32 → 32 total bytes
*   `subdir` (12 + 6) = 18 → too big, won't fit.

So we only get one entry in this block.  The layout is:
*   offset `0`: the dirent struct for `someverylongfilename`, `nameoff` is `12`.
*   offset `12`: `someverylongfilename`
*   no padding, since we're already at 32 bytes.

In this case we look at the `nameoff` of the first entry (`12`) and know that
there must only be one entry in this block.  And in this case, the name fills
the block exactly, so we won't find a `nul` terminator, and we know the name
must have a length of `12`.

Finally, `subdir` gets put in the last partial block:
*   offset `0`: the dirent struct, `nameoff` is `12`
*   offset `12`: `subdir`
*   offset `18`: that's the end of the directory

What comes at offset `18`?  Nothing.  The `size` field of the directory is 2
blocks (`2 * 32` = `64`) plus the `18` bytes from this block, so a total of
`82`.

Of course, if we're storing the directory as "flat plain" or "chunk based" then
we need to pad this out to a complete block size (and we'll do that with
`nul`s), but those padding bytes are not conceptually part of the directory
content.  But what if we stored it "flat inline"?  We might have the next inode
directly following.  In that case, we effectively depend on the inode `size` to
know that the final filename has a length of `6`.
