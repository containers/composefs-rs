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

The root inode (/) is a difficult case because it doesn't always appear in the
layer tarballs.  We need to make some arbitrary decisions about the metadata.

Here's what we do:

 - if any layer tarball contains an empty for '/' then we'd like to use it.
   The code for this doesn't exist yet, but it seems reasonable as a principle.
   In case the `/` entry were to appear in multiple layers, we'd use the
   most-derived layer in which it is present (as per the logic in the previous
   section).
 - otherwise:
   - we assume that the root directory is owned by root:root and has `a+rx`
     permissions (ie: `0555`).  This matches the behaviour of podman.  Note in
     particular: podman uses `0555`, not `0755`: the root directory is not
     (nominally) writable by the root user.
   - the mtime of the root directory is taken to be equal to the most recent
     file in the entire system, that is: the highest numerical value of any
     mtime on any inode.  The rationale is that this is usually a very good
     proxy for "when was the (most-derived) container image created".
