# botan-src

This crate compiles the sources of the
[Botan](https://botan.randombit.net/) cryptography library as a static
library. It is supposed to be used by the
[botan-sys](https://crates.io/crates/botan-sys) crate.

A high level Rust interface built on this library is included in the
[botan](https://crates.io/crates/botan) crate.

## What the crate ships

`vendor/Botan-X.Y.Z.tar.xz` is not the upstream release tarball as
published. That is about 10 MB, which is the crates.io upload limit, and
two thirds of it is the test suite. Instead `scripts/fetch.py` downloads
the upstream release, checks it against `upstream_sha256` in
`release.toml`, and repacks only what the library build needs:
`configure.py`, the license, `src/lib/` and `src/build-data/`. The tar
entries are copied byte for byte in upstream order, so the result is
reproducible from the upstream tarball alone. All library modules are
kept, so `BOTAN_CONFIGURE_ENABLE_MODULES` and friends work exactly as
with a full source tree.

`release.toml` pins the SHA-256 of the *decompressed* repack as
`vendored_tar_sha256`. The build verifies it before extracting anything,
and you can check a published crate yourself with

    xz -dc vendor/Botan-X.Y.Z.tar.xz | sha256sum

The tarball is not checked into git: run `python3 scripts/fetch.py`
before building or publishing this crate (CI does the same).

## Building against a custom Botan tree

Two environment variables let you bypass the bundled tarball, which is
useful when testing a fork or pre-release:

- `BOTAN_SRC_DIR=/path/to/checkout` — build from an existing source tree
  (e.g. a git checkout). No extraction, no checksum.
- `BOTAN_SRC_TARBALL=/path/to/foo.tar.xz` — extract this `.tar.xz`
  (for example a full upstream release) instead of the bundled one. No
  checksum.

If neither is set, the bundled tarball is extracted and verified against
the pinned SHA-256.

## Publishing

The vendored tarball is not committed, so `cargo publish` needs
`--allow-dirty`, which also disables cargo's own check against
publishing uncommitted work. `scripts/publish.py` replaces that check
with stricter ones (tracked files in `botan-src/` are unmodified, the
packaged file set is exactly the committed files plus the vendored
tarball, versions agree with `release.toml` and `botan-sys`, the version
is not already on crates.io, the crate is under the upload limit), shows
a summary, asks for confirmation and then runs `cargo publish`.

    python3 scripts/publish.py --dry-run   # checks, then cargo publish --dry-run
    python3 scripts/publish.py             # checks, confirm, publish

Pass `--yes` to skip the prompt; arguments after `--` go to `cargo publish`.

## Bumping the bundled Botan version

1. In `release.toml` set `version` and `upstream_sha256`, and set
   `vendored_tar_sha256 = ""`.
2. Run `python3 scripts/fetch.py`; it prints the `vendored_tar_sha256`
   to pin. Run it again to confirm.
3. Bump the crate version in `Cargo.toml` (`0.MNNPP.X` for Botan
   M.NN.PP) and the `botan-src` dependency in `botan-sys/Cargo.toml`.
4. `cargo test -p botan --features vendored`
5. Commit, push, then `python3 scripts/publish.py`
