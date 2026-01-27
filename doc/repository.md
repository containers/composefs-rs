# composefs repository design

This document describes the current on-disk layout of a composefs repository.

At this time, the composefs-rs repository format is not declared stable.

## Location

A composefs repository is a directory located anywhere. The location is chosen
for the `cfsctl` command as follows:

 - `--repo` can specify an arbitrary directory

 - if `--user` is specified (default if the current uid is not 0), then the
   repository defaults to `~/.var/lib/composefs`.

 - if `--system` is specified (default if the current uid is 0), then the
   repository defaults to `/sysroot/composefs`.

## Layout

A composefs repository has a layout that looks something like

```
composefs
├── objects
│   ├── 00
│   │   ├── 002183fb91[...]
│   │   ├── [...]
│   │   └── ff9d7bd692[...]
│   ├── 4e
│   │   ├── 67eaccd9fd[...]
│   │   └── [...]
│   ├── 50
│   │   ├── 2b126bca0c[...]
│   │   └── [...]
│   └── [...]
├── images
│   ├── 4e67eaccd9fd[...] -> ../objects/4e/67eaccd9fd[...]
│   └── refs
│       └── some/name -> ../../images/4e67eaccd9fd[...]
└── streams
    ├── 502b126bca0c[...] -> ../objects/50/2b126bca0c[...]
    └── refs
        └── some/name.tar -> ../../streams/502b126bca0c[...]
```

## `objects/`

This is where the content-addressed data is stored.  The immediate children of
this directory are 256 subdirectories from `00` to `ff`.  Each of those
directories contains a number of files with 62-character hexidecimal names.
Taken together with the directory in which it resides, each filename represents
a 256bit hash value which equals the measured fs-verity digest of that file.
fs-verity must be enabled for every file.

## `images/`

This is where composefs (erofs) images are accounted for.  The images
themselves are fs-verity enabled and stored in the object store in the same way
as the file data, but the `images/` directory contains symlinks to the images
that we know about.  Each symlink is named for the full 256bit fsverity digest.

Images are tracked in a separate directory because of the security model of
filesystems in the Linux kernel.  Although it would be feasible for "regular
users" to mount an erofs in their own mount namespace, the kernel currently
disallows it as a way to avoid allowing non-root users to expose the filesystem
code to hostile data.  As such, we only mount images that we produced for
ourselves (with mkcomposefs), and those are the ones that are linked in this
directory.

Another way to say it: we must never attempt to mount an arbitrary object: we
may only mount via symlinks present in this directory.

## `streams/`

This is where [split streams](splitstream.md) are stored.  As for the images,
this is a bunch of 256bit symlinks which are symlinks to data in the object
storage.

Note: the names of the hashes in this directory are the fs-verity hashes of the
content of the splitstream file, not the original file.  More specifically: if
you have a tar file with a specific sha256 digest, and you import it into the
repository as a splitstream, the resulting filename in this directory will have
no relation to the original content.  You can, however, store a reference for
it.

## `{images,streams}/refs/`

This is where we record which images and streams are currently "requested" by
some external user.  When importing a tar file, in addition to creating the
file in the objects database and the toplevel symlink in the `streams/`
directory, we also assign it a name which is chosen by the software which is
performing the import.

Each ref is a symlink to the top-level entry in `images/` or `streams/`.

There are some rough ideas for how we might namespace this.  Something like
this model is imagined:

```
refs
├── system
│   └── rootfs
│       ├── some_id -> ../../../974d04eaff[...]
│       └── [...]
├── 1000                      # uid of a user
│   ├── flatpak
│   │   ├── some_id -> ../../../f8e2bec500[...]
│   │   └── [...]
│   └── containers
│       ├── some_id -> ../../../96a87f8b4b[...]
│       └── [...]
└── [...]
```

Where the toplevel directories are `system` plus a set of uids.  Each `system`
or uid subdirectory is namespaced by the particular piece of software that's
responsible for storing the given image or stream.

The per-user directories will all be owned by root and have 0700 permissions,
but each user will be able to access their own uid-numbered subdirectories by
way of an acl.  The reason that we want the directories owned by root is to
prevent users from corrupting the layout of the repository.  The reason for the
acl is that read-only operations on the repository should be performed
directly on the repository and not via some central agent.

## Referring to images and streams

Operations that are performed on images or streams (mount, cat, etc.) name the
stream in one of two ways:

 - via the user-chosen name such as `refs/1000/flatpak/some_id`
 - via the fs-verity digest stored in the toplevel dir

ie: the name must either start with the string `refs/`, or must be a
hexadecimal string (64 characters for sha256, 128 for sha512).

In both cases, the name is a path relative to the `images/` or `streams/`
directory and this path contains a symlink (either direct or indirect) to the
underlying file in `objects/`.

When specified via fs-verity digest, the digest is verified before performing
the operation.

For example:

```sh
cfsctl mount refs/system/rootfs/some_id /mnt   # does not check fs-verity
cfsctl mount 974d04eaff[...] /mnt              # enforces fs-verity
```
