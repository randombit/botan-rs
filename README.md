# botan-rs

[![Build status](https://travis-ci.org/randombit/botan-rs.svg?branch=master)](https://travis-ci.org/randombit/botan-rs)
[![crates.io](https://img.shields.io/crates/v/botan.svg)](https://crates.io/crates/botan)

This crate wraps the C API exposed by the
[Botan](https://botan.randombit.net/) cryptography library.

This is an early work in progress. Some functionality like hashes, MACs, KDFs,
PBKDF2, random number generators, and public key operations (sign, verify,
encrypt, decrypt, key agreement) are available now.
