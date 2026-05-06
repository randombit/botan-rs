# botan-src

This crate compiles the sources of the
[Botan](https://botan.randombit.net/) cryptography library as a static
library. It is supposed to be used by the
[botan-sys](https://crates.io/crates/botan-sys) crate.

A high level Rust interface built on this library is included in the
[botan](https://crates.io/crates/botan) crate.

## Building against a custom Botan tree

The crate ships the upstream Botan release tarball in `vendor/` and
extracts it at build time. Two environment variables let you override
that, which is useful when testing a fork or pre-release:

- `BOTAN_SRC_DIR=/path/to/checkout` — build from an existing source tree
  (e.g. a git checkout). No extraction, no checksum.
- `BOTAN_SRC_TARBALL=/path/to/foo.tar.xz` — extract this `.tar.xz`
  instead of the bundled one. No checksum.

If neither is set, the bundled tarball is extracted and verified against
the pinned SHA-256.
