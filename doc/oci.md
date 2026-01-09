# How to create a composefs from an OCI image

This document is incomplete.  It only serves to document some decisions we've
taken about how to resolve ambiguous situations.

# Data precision

We currently create a composefs image using the granularity of data as
typically appears in OCI tarballs:
 - atime and ctime are not present (these are actually not physically present
   in the erofs inode structure at all, either the compact or extended forms)
 - mtime is set to the mtime in seconds; the sub-seconds value is simply
   truncated (ie: we always round down).  erofs has an nsec field, but it's not
   normally present in OCI tarballs.  That's down to the fact that the usual
   tar header only has timestamps in seconds and extended headers are not
   usually added for this purpose.
 - we take great care to faithfully represent hardlinks: even though the
   produced filesystem is read-only and we have data de-duplication via the
   objects store, we make sure that hardlinks result in an actual shared inode
   as visible via the `st_ino` and `st_nlink` fields on the mounted filesystem.

We apply these precision restrictions also when creating images by scanning the
filesystem.  For example: even if we get more-accurate timestamp information,
we'll truncate it to the nearest second.

# Merging directories

This is done according to the OCI spec, with an additional clarification: in
case a directory entry is present in multiple layers, we use the tar metadata
from the most-derived layer to determine the attributes (owner, permissions,
mtime) for the directory.

# The root inode

The root inode (/) is a difficult case because OCI container layer tars often
don't include a root directory entry, and when they do, container runtimes
(Podman, Docker) ignore it and use hardcoded defaults.  For example, Podman's
[containers/storage](https://github.com/containers/storage) uses root:root
ownership, mode `0555`, and epoch (0) mtime when extracting layers, but
Docker uses `0755`. In general, the metadata for `/` is not defined.

Because composefs requires (has a goal of providing) precise cryptographically
verifiable filesystem trees, we solve this for OCI by copying the metadata from `/usr`
to the root directory.  The rationale is that `/usr` is always present in
standard filesystem layouts and must be defined explicitly in the OCI layers.

This is implemented via the `copy_root_metadata_from_usr()` method and the
`read_container_root()` convenience function.

When building a filesystem from OCI layers programmatically, use
`Stat::uninitialized()` to create the initial `FileSystem`.  This placeholder
has mode `0` (obviously invalid) to make it clear that the root metadata should
be set before computing digests - typically by calling
`copy_root_metadata_from_usr()` after processing all layers.
