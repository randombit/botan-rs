# botan-rs

[![Build status](https://api.travis-ci.com/randombit/botan-rs.svg?branch=master)](https://travis-ci.com/github/randombit/botan-rs)
[![crates.io](https://img.shields.io/crates/v/botan.svg)](https://crates.io/crates/botan)
[![docs.rs](https://docs.rs/botan/badge.svg)](https://docs.rs/botan)

This crate wraps the C API exposed by the [Botan](https://botan.randombit.net/)
cryptography library. Botan 2.8.0 or higher is required.

Rust 1.36.0 or later are supported.  `no_std` builds are supported,
just use feature `no-std`.

Currently the crate exposes ciphers, hashes, MACs, KDFs, password based
key derivation (PBKDF2, Scrypt, Argon2, etc), bcrypt password hashes,
random number generators, X.509 certificates, format preserving encryption,
HOTP/TOTP, NIST key wrapping, multiprecision integers, and various
public key algorithms (RSA, ECDSA, ECDH, ...)

PRs and comments/issues happily accepted.
