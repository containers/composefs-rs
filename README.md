# composefs-rs

This is a set of experiments exploring ideas around how to structure an on-disk
[composefs](https://github.com/containers/composefs) repository.

The main consumables here are:

 - a [`Repository`](src/repository.rs) class representing an on-disk composefs
   repository and the operations that can be performed on it.  See the
   [repository format documentation](doc/repository.md).

 - [`cfsctl`](crates/cfsctl/src/main.rs): a command-line tool for performing operations
   on the repository via the above APIs.

 - (future?) some kind of a system service exposing those APIs to non-root
   users in a safe way.

The `cfsctl mount` command depends on (currently pre-release) Linux 6.12 for
support for directly mounting erofs images without creating loopback devices.

The purpose of this is to iterate fast on some new ideas (without worrying
about breaking existing composefs users) and also as a learning experience (as
my first real Rust project).

Nothing here is currently expected to be useful to anybody at all, and probably
never will be.  If these experiments go well, this code will probably end up
merged in other places.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
