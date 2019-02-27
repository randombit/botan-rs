# botan-rs

[![Build status](https://travis-ci.org/randombit/botan-rs.svg?branch=master)](https://travis-ci.org/randombit/botan-rs)
[![crates.io](https://img.shields.io/crates/v/botan.svg)](https://crates.io/crates/botan)
[![docs.rs](https://docs.rs/botan/badge.svg)](https://docs.rs/botan)

This crate wraps the C API exposed by the [Botan](https://botan.randombit.net/)
cryptography library. Botan 2.8.0 or higher is required.

Rust 1.32.0 or later are supported.  `no_std` builds are supported,
just use feature `no-std`.

Currently the crate exposes ciphers, hashes, MACs, KDFs, PBKDF2, Scrypt, random
number generators, X.509 certificates, format preserving encryption, HOTP/TOTP,
NIST key wrapping, multiprecision integers, and various public key algorithms.

PRs and comments/issues happily accepted.
