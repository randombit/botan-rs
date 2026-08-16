# botan-rs

[![Build status](https://github.com/randombit/botan-rs/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/randombit/botan-rs/actions)
[![crates.io](https://img.shields.io/crates/v/botan.svg)](https://crates.io/crates/botan)
[![docs.rs](https://docs.rs/botan/badge.svg)](https://docs.rs/botan)

This crate wraps the C API exposed by the [Botan](https://botan.randombit.net/)
cryptography library.

Currently the crate exposes ciphers, hashes, MACs, KDFs, password based key
derivation (PBKDF2, Scrypt, Argon2, etc), bcrypt password hashes, random number
generators, X.509 certificates, format preserving encryption, HOTP/TOTP, NIST
key wrapping, multiprecision integers, and the usual public key algorithms (RSA,
ECDSA, ECDH, DH, ...)

PRs and comments/issues happily accepted.

MSRV
-----

The Minimum Supported Rust Version (MSRV) of this crate is Rust 1.85.0.

Any future increase in the MSRV will be accompanied by increasing the minor
version number.

Botan Versions Supported
--------------------------

The latest version of Botan3 is highly recomended for best security and
performance. At least 2.13.0 is required.

Features
---------

The following features are supported:

* `std` (enabled by default): Enable using std library features.  If
  disabled then the crates are `no_std`, however support for `alloc`
  is still required.
* `vendored`: Build a copy of the C++ library directly, without
  relying on a system installed version.
* `static`: Enable static linking for a non-vendored, externally
  provided Botan dependency.
* `pkg-config`: Enable finding a non-vendored, externally provided
  Botan with pkg-config. Can be used in combination with `static`.
* `dynamic-loading`: Instead of linking to Botan at build time, load the
  Botan shared library at runtime (using `dlopen`/`LoadLibrary`) and resolve
  each function on first use. See below. Requires `std`, and cannot be
  combined with `vendored` or `static`.

Availability Of Newer APIs
--------------------------

Botan's C interface gains new functions with most releases, and this crate
exposes wrappers for all of them regardless of which version of Botan it is
built or run against. If an operation requires a function that the Botan
library in use does not provide, it returns an error of type
`ErrorType::NotImplemented` (the same error returned when an algorithm was
compiled out of the library), and `Error::is_function_unavailable` returns
true. The documentation of each affected function notes the minimum Botan
version required, and `Version::current` / `Version::supports_version` can be
used to check the version of the library in use at runtime.

When building against a system installed Botan, `botan-sys` detects at build
time which functions the headers declare; functions the headers predate are
replaced by stubs which return the error above.

Dynamic Loading
---------------

With the `dynamic-loading` feature, no Botan installation is required to build
the crate, and the resulting binary has no link time dependency on Botan.
Instead the shared library (`libbotan-3.so.N`, `libbotan-3.dylib`,
`botan-3.dll`, or the Botan 2 equivalents) is searched for and loaded the first
time it is needed, or `botan::load_library` can be called first to specify
exactly which library to use. Every FFI function is resolved on first use, so
the set of available functionality is determined entirely by the library found
at runtime: an application built against this crate can pick up newer Botan
features simply by being run against a newer library, and continues to work
(returning `NotImplemented` for newer features) against an older one. If no
usable library can be found, operations fail with `ErrorType::LibraryNotLoaded`.
