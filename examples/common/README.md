# Common files used in examples

This isn't a composefs example, but it's used by the other examples.

## `fix-fsverity/`

This is a workaround for missing fs-verity support in e2fsprogs and
systemd-repart.

That's being worked on here:
 - https://github.com/systemd/systemd/issues/35352
 - https://github.com/tytso/e2fsprogs/pull/203

But we'll probably need this workaround until those changes are widely
available.

## `run`

The script to run the VM.

## `make-image`

Creates the qcow2 filesystem image from the contents of the `tmp/` directory.

This also invokes the `fix-fsverity` hack required to build a working image.

## `run-repart`

The part of `make-image` that needs to run under `fakeroot`.

## `repart.d`

The partition definitions for `systemd-repart`.
