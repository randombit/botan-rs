# botan-sys

This crate contains the FFI declarations for calling the C API included in the
[Botan](https://botan.randombit.net/) cryptography library as well as the rules
for linking to it.

A high level Rust interface built on these declarations is included in the
[botan](https://crates.io/crates/botan) crate.

This crate is always `no_std`

## Features

* `vendored`: Build against the `botan-src` crate
* `static`: Statically link the library. This is always used if `vendored` is set
* `pkg-config`: Use `pkg-config` instead of probing to find the library

## Exported cfg

This crate will detect which version of the FFI interface is supported and enable
features on that basis. The feature sets can be checked using

* `#[cfg(botan_ffi_20230403)]`: Botan 3.0
* `#[cfg(botan_ffi_20240408)]`: Botan 3.4
* `#[cfg(botan_ffi_20250506)]`: Botan 3.8

## Environment Variables

The following environment variables are used to guide features

* `BOTAN_INCLUDE_DIR` the base path to where the relevant library includes are
  found. For example if the headers are in `/opt/foo/botan-3/botan`, this
  variable should be set to `/opt/foo`. If not set, tries a few common
  locations. This variable is ignored if the `pkg-config` or `vendored`
  features are used.
* `BOTAN_LIB_DIR` the directory to search for pre-build shared or static
   libraries.
