# botan-rs

[![Build status](https://github.com/randombit/botan-rs/workflows/ci/badge.svg)](https://github.com/randombit/botan-rs/actions)
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

The Minimum Supported Rust Version of this crate is Rust 1.64.0.

Botan Versions Supported
--------------------------

This crate requires Botan 2.13.0 or higher. However the latest
available version of Botan3 is highly recomended for best security and
performance.

Features
---------

The following features are supported:

* `std` (enabled by default): Enable using std library. If disabled
  (resulting in a `no_std` build), then Rust 1.64.0 or higher is
  required.
* `vendored`: Build a copy of the C++ library directly, without
  relying on a system installed version.
* `botan3`: Enable support for using APIs added in Botan 3.
  This enables several new features, and more efficient operation.
  This feature is implicitly enabled if you use `vendored`.
