# Canonical composefs file format

## Prelude

We expect the process of creating an erofs from a filesystem image to be
deterministic.  `erofs` is very free-form and there are many ways things could
be organized.

Here's where we try to document some of the decisions we make.  This documents
the erofs images produced by the `composefs` rust crate, which are currently
different from the official `composefs` repository (ie: `libcomposefs`, in C).
It would be very desirable to try to make this implementation exactly match the
`libcomposefs` implementation so that we could check them against each other to
ensure that they produce bitwise identical output.  On the other hand, we've
been discussing creating a "version 1.1" format, and this might be a good
jumping-off spot for that.

The goal of this document is to completely and unambiguously document every
decision we made in such a way that you could use this document as a guide to
produce a new composefs erofs writer implementation, from scratch, which
produces exactly the same output.  However, this document is probably currently
very incomplete, and maybe even incorrect.  We should strive to cover every
possible detail here, but it's hard.  Hopefully things will improve with time,
but until then, you might need to check the implementation.

In cases of ambiguity or incorrectness, issues and patches are extremely
welcome.

## Overall layout concept

The composefs header and superblock are the only things that need to be at
fixed offsets.  How do we organize everything else?

Generally speaking, we perform these steps:
*    collect the filesystem into a flat list of inodes
*    collect and "share" xattrs, as appropriate
*    write the composefs header and the superblock
*    write the inodes directly following the superblock
*    write the shared xattrs directly following the inodes
*    then the blocks (only for directories)

## Collecting inodes

We collect the inodes into a flat list according to the following algorithm:
*   our goal is to visit each inode, collecting it into the inode list as we
    visit it, in the order that we visited it
*   start at the root directory
*   for each directory that we visit:
    -   the directory is stored first, then the children
    -   we visit the children in asciibetical order, regardless of file type
        (ie: we interleave directories and regular files)
    -   when visiting a child directory, we store all content of the child
        directory before returning to the parent directory (ie: depth first)
*   in the case of hardlinks, the inode gets added to the list at the spot that
    the first link was encountered

Consider a filesystem tree

```
 /
   bin/
     cfsctl
   usr/
     lib/
       libcomposefs.so
       libglib-2.0.so
     libexec/
       cfsctl
```

where `/bin/cfsctl` and `/usr/libexec/cfsctl` are hardlinks.

In that case, we'd collect the inodes in this order:
1.  `/`
1.  `/bin/`
1.  `/bin/cfsctl` (aka `/usr/libexec/cfsctl`)
1.  `/usr/`
1.  `/usr/lib/`
1.  `/usr/lib/libcomposefs.so`
1.  `/usr/lib/libglib-2.0.so`
1.  `/usr/libexec/`

(skipping `/usr/libexec/ctlctl` because we already had it by the time we encountered it).

So that's 8 inodes, in that order.

## Special handling for overlayfs

Ultimately, the erofs image that we produce needs to be used as a layer in an
overlayfs stack.  There are a lot of cases where the thing that we write out
only makes sense to overlayfs.  There are other cases where we need to avoiding
writing out things that overlayfs would treat as "special".

`libcomposefs` writes 256 files named from `00` to `ff` into the root directory
as character devices with major/minor of (0, 0).  Those are overlayfs whiteouts
and they are needed for older versions of overlayfs which don't support "data
only" layers.  We don't target these versions, so *we don't add these files*.
We also don't mark the root directory as opaque or do anything else special
with it.

Conversely, if we encounter a character device with major/minor (0, 0) then we
need to escape it to make sure that it appears as such in the final composed
image (and does not get handled by overlayfs as a whiteout).  We do that by:
TODO (not implemented yet).

We also need to make sure that the only `trusted.overlay.*` attributes which we
write are ones that came from us.  If we encounter any `trusted.overlay.*`
attributes in the source, we escape them to `trusted.overlay.overlay.`, causing
them to lose their special meaning.

## Extended attribute handling

For each inode, we collect and write the extended attributes in asciibetical
order, by full name.  Note: this is different than the shared xattr table which
has a more complicated sorting, but maybe we want to unify the two.

We use the hardcoded prefix indexes (which is actually mandatory).

We don't use "long prefixes", but we might start doing that at some point,
because it would sure be nice to not have to write `"overlay.redirect"`,
`"overlay.metacopy"` and `"selinux"` over and over again. The feature seems
complicated, though...

## Collecting shared xattrs

`erofs` has a facility for sharing xattrs where the name and the value are
identical, and we use it.  After we've collected all of our inodes, we iterate
the list and take note of all (name, value) pairs.  If any (name, value) pair
appears more than once, we share it.

The process of "sharing" involves modifying the original inode.  We iterate the
present xattrs, and for each attribute that we share, we remove it from the
"inline" list and add it to the "shared" list, in the same order as it appeared
in the inline list.

NB: this operation is performed on the flattened inode list, not the directory
tree.  That means that if a particular (name, value) pair appears uniquely on
an inode with multiple hardlinks, we'll count that as a single occurrence and
it won't be shared.

Note also: the attributes that we add ourselves are considered candidates for
sharing.  That means that if we had two external files which were not hardlinks
but nevertheless contained the same data, we'd end up sharing their
`trusted.overlayfs.` attributes.

## The composefs header

`erofs` leaves the first 1024 bytes of the file free to us, and we store a
32-byte header at offset 0.  The kernel ignores this, and our mount code
doesn't actually do anything with it at the moment, either.  We try to fill it
out in the same way as `libcomposefs`:

*   `magic` (`u32`): `0xd078629a`
*   `version` (`u32`): I think this is something like the overall file format
    version.  If this changes, then things are possibly incompatible, and maybe
    this isn't even an `erofs` anymore.  Currently `1`.
*   `flags`: `0`
*   `composefs_version`: I think this is something like a statement about the
    current strategy for layout decisions.  If this changes, the algorithm for
    building the file has probably decided to put things in different places
    (and the checksum of the file will have changed), but the result is still
    understandable as an `erofs`.  Currently `1`.

## The superblock

*   `checksum`: we don't fill that out
*   `feature_compat`: we set `MTIME` and `XATTR_FILTER`
*   `blkszbits`: we use 12, for a block size of 4096
*   `root_nid`: that's going to end up being 36, which follows from the fact
    that we put the root inode directly following the superblock, at offset
    `1024 + 128` = `1152`.  `1152 / 32` = `36`.
*   `inos`: we currently set that to the number of inodes in the filesystem.
    `libcomposefs` adds some extra file content (the `00`..`ff` whiteouts) so
    it gets a larger number than we do.
*   `blocks`: the total filesize, divided by 4096.
*   `build_time`, `build_time_nsec`: since we only use extended format inodes,
    these fields are meaningless and we currently set them to 0 (which is
    different from `libcomposefs`).
*   `meta_blkaddr`, `xattr_blkaddr`.  We currently set both of these to 0 to
    keep things simple. `libcomposefs` performs a complicated calculation to
    set `meta_blkaddr` to zero as well (since the first inode directly follows
    the superblock, it will always be within the first 4096 byte filesystem
    block), but its complicated calculation for `xattr_blkaddr` might well land
    on a non-zero value, so that's different from us.

## The inodes

After the superblock, we write the inodes.  Some notes:

*   we only use extended inodes, because mtime is important to us and we
    generally expect every file to have a unique mtime.  This is a difference
    from `libcomposefs`.

*   we use a "chunk based" data layout for non-inline regular files:

    -   the way this works in overlayfs, we want to store a correctly-sized
        sparse file in the upper layer.  This lets us have the correct `size`
        field on the inode, so we don't need to interact with the data layer in
        order to do `stat()`.

    -   we set the chunk format (ie: the `i_u` field) to 31, the maximum

    -   we store a single "null" chunk pointer

    -   this corresponds to a chunk size of 8TB, which is then the upper limit
        of files we can store

    -   `libcomposefs` tries to take the smallest chunk format value which will
        get the job done with a single chunk pointer, and will write multiple
        chunk pointers if necessary (for extreemely large files). Maybe we
        should do that too.

    -   in this case we set the `trusted.overlay.metacopy` and
        `trusted.overlay.redirect` attributes (in that order) on the file.
        These attributes are written first, before the other attributes that
        would be present on the same file (which are otherwise in sorted
        order).

    -   the `trusted.overlay.metacopy` attribute is 36 bytes long, and is set to:
        +   the 4-byte header: [0 36, 0, 1]
        +   the 32-byte SHA256 fs-verity digest

    -   the `trusted.overlay.redirect` attribute is set to the string
        `"/xx/yyyy..."` where `xx` is the first two lowercase hexidecimal bytes
        of the fs-verity digest and the `yyyy...` is the rest.  That's just a
        reference into the `objects/` subdirectory of the repository (which is
        mounted in the overlayfs stack as the data layer).

*   we use a "flat inline" data layout for all other inodes:

    -   for character and block devices, as well as fifos and sockets this is
        meaningless, but we need to set something

    -   for inline regular files we store the content inline.  This will break
        if we try to inline a file larger than 4095 characters, but our current
        cut-off is 64.

    -   for symlinks this means that the link target gets stored inline.
        Hopefully we don't have symlinks with targets longer than 4095
        characters, or we're gonna get in trouble.

    -   directories may well be larger than 4096 bytes, so we might end up
        needing to store blocks for those.  These follow the "shared xattrs"
        area.  We could probably set "flat plain" for directories that are an
        exact multiple of 4096 bytes in size, and `libcomposefs` does that, but
        we don't bother.

We pad the last inode to the required alignment for inodes, even though it is
generally followed by a shared xattr (which has a less stringent alignment
requirement).

## The shared xattrs

There's not much left to be said about these.  We currently write them out in
the order that `collections::BTreeMap` applies to our `struct XAttr`, which I
think basically ends up sorting them by prefix index, then by suffix, then by
value.  We might like to firm that up at some point.  This is notably different
than the sorting applied to the attributes as they appear in the inodes, and we
also don't give any special treatment to the `trusted.overlay.` attributes that
we added: they're sorted here in the usual way.

After we do this, and even if there was no shared xattrs, we always pad up to a
4096 byte boundary, even if there are no data blocks.  That means that the
filesystem image will always be a multiple of 4096.

## The blocks

Now comes the data blocks.  These are written in sequence for each inode,
according to the sequence of the inode in the inode list.  Due to our use of
"flat inline" data layout, only full blocks are stored (although they may have
included inter-block padding in directories), so we keep 4096-byte alignment
from here on out.

## The end

That's it.  The file is over now.  We'll have ended on a multiple of 4096.
