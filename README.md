# botan-rs

[![Build status](https://travis-ci.org/randombit/botan-rs.svg?branch=master)](https://travis-ci.org/randombit/botan-rs)
[![crates.io](https://img.shields.io/crates/v/botan.svg)](https://crates.io/crates/botan)
[![docs.rs](https://docs.rs/botan/badge.svg)](https://docs.rs/botan)

This crate wraps the C API exposed by the [Botan](https://botan.randombit.net/)
cryptography library. Due to making use of functions only recently added to the
C API, right now the latest version of `master` branch (upcoming 2.8) is required.

Currently the crate exposes ciphers, hashes, MACs, KDFs, PBKDF2, Scrypt, random
number generators, X.509 certificates, format preserving encryption, NIST key
wrapping, multiprecision integers, and various public key algorithms.

This is still a work in progress and the API may change in the future.

PRs and comments/issues happily accepted.
