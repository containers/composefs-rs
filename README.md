# composefs-rs

A Rust implementation of [composefs](https://github.com/containers/composefs) with support for
creating and managing verified operating system images. This project provides tools and libraries
for working with composefs repositories and building secure, content-addressed filesystem images.

Note: it is planned for this project to become the primary reference implementation of composefs,
replacing the C-based implementation. For more on this, see [this discussion](https://github.com/composefs/composefs/discussions/423).

## Goals

Anywhere one wants versioned immutable filesystem trees ("images"), composefs provides
a lot of compelling advantages. In particular this project aims to be the successor
to [ostree](https://github.com/ostreedev/ostree/) for example.

## Components

### Core Libraries

 - [`composefs`](crates/composefs): Core library for composefs operations including filesystem trees,
   fs-verity support, and repository management
 - [`composefs-oci`](crates/composefs-oci): OCI image handling and integration with container registries
 - [`composefs-boot`](crates/composefs-boot): Boot infrastructure support including UKI (Unified Kernel Image)
   and BLS (Boot Loader Specification) integration
 - [`composefs-http`](crates/composefs-http): HTTP support for fetching composefs content
 - [`composefs-fuse`](crates/composefs-fuse): FUSE filesystem implementation
 
### Command-line Tools

 - [`cfsctl`](crates/cfsctl/src/main.rs): Primary CLI tool for managing composefs repositories
 - [`composefs-setup-root`](crates/composefs-setup-root/src/main.rs): Early boot tool for setting up
   the root filesystem from a composefs image

### Examples

The [`examples`](examples/) directory contains working demonstrations of building verified OS images:

 - **UKI**: Unified Kernel Image with embedded composefs digest
 - **BLS**: Traditional kernel/initramfs with Boot Loader Specification entries
 - **Unified**: Streamlined UKI build using in-container measurement
 - **Unified-SecureBoot**: UKI with Secure Boot signing support

## Documentation

 - [Repository format](doc/repository.md)
 - [OCI integration](doc/oci.md)
 - [Splitstream format](doc/splitstream.md)
 - [Examples README](examples/README.md)

## Status

This project is under active development. It is still possible that the layout of a composefs
repository will change for example.

## License

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).
