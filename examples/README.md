# composefs examples

This directory contains a few different approaches to using `cfsctl` to produce
a verified operating system image.

 - `uki`: an OS built around a [Unified Kernel Image](https://github.com/uapi-group/specifications/blob/main/specs/unified_kernel_image.md).
   If this image is signed then the signature effectively covers every single file in the filesystem.
   This works with a special form of multi-stage `Containerfile` which builds a base image, measures it using `cfsctl` and then uses that measurement to inject the composefs image fs-verity hash into the second stage of the build which actually builds the UKI (and embeds the hash into the `.cmdline`).
   We avoid a circular hash dependency by removing the UKI from the final image via a white-out (but `cfsctl` still knows how to find it).
 - `bls`: an OS built around a separate kernel and initramfs installed with a [Type #1 Boot Loader Specification Entries](https://uapi-group.org/specifications/specs/boot_loader_specification/#type-1-boot-loader-specification-entries).
   In this case we simply hack the bootloader entry to refer to the correct composefs hash at install type.
 - `unified`: similar to the `uki` example, but avoiding the intermediate `cfsctl` step by running `cfsctl` inside a build stage from the `Containerfile` itself.
   This involves bind-mounting the earlier build stage of the base image so that we can measure it from inside the stage that builds the UKI.
 - `unified-secureboot`: based on the `unified` example, adding signing for Secure Boot.

## Using the examples

The main use of the examples is to act as a scratch space for feature
development (like initramfs integration) and to show how you can build a system
image in various configurations using composefs.  They are also run from CI and
are very useful for local testing, however.

You can build the various images using the `build` script found in each
subdirectory.  It takes a single argument: the OS to build the image from
(`fedora`, `rawhide`, `arch`, `ubuntu`, `rhel9`, etc.).  You should not build
multiple images in parallel due to conflicting feature flags and shared use of
the tmp/ directory.  After the image is built, you can run tests against it by
saying something like:

```
TEST_IMAGE=examples/bls/arch-bls-efi.qcow2 pytest examples/test
```

Building and running tests on a particular image is supported via the
`examples/test/run` script, which you can use like:

```
examples/test/run bls rhel9
```

The tests are run using [`test.thing`](https://codeberg.org/lis/test.thing). We
keep a copy of it in-tree.  You you can also use it to run the VM images for
manual inspection:

```
examples/testthing.py examples/bls/fedora-bls-efi.qcow2
```

In that case, you should add this fragment to your ssh configuration:

```
Host tt.*
        ControlPath ${XDG_RUNTIME_DIR}/test.thing/%h/ssh
```

So you can access the test machine via `ssh tt.0` and so on.
