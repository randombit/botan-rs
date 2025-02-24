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

The Minimum Supported Rust Version (MSRV) of this crate is Rust 1.64.0.

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
* `botan3`: Enable support for using APIs added in Botan 3.
  This enables several new features, and more efficient operation.
  This feature is implicitly enabled if you use `vendored`.
* `static`: Enable static linking for a non-vendored, externally
  provided Botan dependency.
* `pkg-config`: Enable finding a non-vendored, externally provided
  Botan with pkg-config. Can be used in combination with `static`.
