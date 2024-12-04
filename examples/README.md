# composefs examples

This directory contains a few different approaches to using `cfsctl` to produce
a verified operating system image.

 - `uki`: an OS built around a [Unified Kernel
   Image](https://github.com/uapi-group/specifications/blob/main/specs/unified_kernel_image.md).  If this image is signed then the signature effectively covers every single file in the filesystem.  This works with a special form of multi-stage `Containerfile` which builds a base image, measures it using `cfsctl` and then uses that measurement to inject the composefs image fs-verity hash into the second stage of the build which actually builds the UKI (and embeds the hash into the `.cmdline`).  We avoid a circular hash dependency by removing the UKI from the final image via a white-out (but `cfsctl` still knows how to find it).
 - `bls`: an OS built around a separate kernel and initramfs installed with a [Type #1 Boot Loader Specification Entries](https://uapi-group.org/specifications/specs/boot_loader_specification/#type-1-boot-loader-specification-entries).  In this case we simply hack the bootloader entry to refer to the correct composefs hash at install type.
 - `unified`: similar to the `uki` example, but avoiding the intermediate `cfsctl` step by running `cfsctl` inside a build stage from the `Containerfile` itself.  This involves bind-mounting the earlier build stage of the base image so that we can measure it from inside the stage that builds the UKI.
