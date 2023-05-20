# botan-rs

[![Build status](https://github.com/randombit/botan-rs/workflows/ci/badge.svg)](https://github.com/randombit/botan-rs/actions)
[![crates.io](https://img.shields.io/crates/v/botan.svg)](https://crates.io/crates/botan)
[![docs.rs](https://docs.rs/botan/badge.svg)](https://docs.rs/botan)

This crate wraps the C API exposed by the [Botan](https://botan.randombit.net/)
cryptography library. The current version requires Botan 2.8.0 or higher
and Rust 1.58.0 or higher.

The following features are supported:

* `no-std`: Enable a no-std build. This requires Rust 1.64.0 or higher,
  as well as `alloc` support
* `vendored`: Build a copy of the C++ library directly, without
  relying on a system installed version.
* `botan3`: Link against Botan 3 rather than the current default Botan 2.
  This enables several new features, and more efficient operation

Currently the crate exposes ciphers, hashes, MACs, KDFs, password based key
derivation (PBKDF2, Scrypt, Argon2, etc), bcrypt password hashes, random number
generators, X.509 certificates, format preserving encryption, HOTP/TOTP, NIST
key wrapping, multiprecision integers, and the usual public key algorithms (RSA,
ECDSA, ECDH, DH, ...)

PRs and comments/issues happily accepted.
