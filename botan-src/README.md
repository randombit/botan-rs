# botan-src

This crate compiles the sources of the
[Botan](https://botan.randombit.net/) cryptography library as a static
library. It is supposed to be used by the
[botan-sys](https://crates.io/crates/botan-sys) crate.

A high level Rust interface built on this library is included in the
[botan](https://crates.io/crates/botan) crate.

## Configuring the build

Build scripts call `botan_src::build()`, which reads its settings from
the environment variables described below, or `botan_src::build_with`
with an explicit `botan_src::Config`. A `Config` is a plain value,
so a build script can set the compiler, module list and so on without
mutating the process environment; `Config::from_env()` gives the same
starting point that `build()` uses, so end users can still override
settings.

```rust
let config = botan_src::Config::from_env()
    .enable_modules(["ml_kem", "ml_dsa"]);
let (lib_dir, include_dir) = botan_src::build_with(&config);
```

The `BOTAN_CONFIGURE_<OPTION>` environment variables map onto the
`configure.py` options with a corresponding `Config` method: for example
`BOTAN_CONFIGURE_CC_BIN=clang++` passes `--cc-bin=clang++`, and
`BOTAN_CONFIGURE_ENABLE_MODULES=ml_kem,ml_dsa` passes
`--enable-modules=ml_kem,ml_dsa`. Setting `BOTAN_CONFIGURE_AMALGAMATION`
to any value enables `--amalgamation`.

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
