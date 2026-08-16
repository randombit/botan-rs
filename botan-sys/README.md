# botan-sys

This crate contains the FFI declarations for calling the C API included in the
[Botan](https://botan.randombit.net/) cryptography library as well as the rules
for linking to it.

A high level Rust interface built on these declarations is included in the
[botan](https://crates.io/crates/botan) crate.

This crate is `no_std` unless the `dynamic-loading` feature is used.

## Features

* `vendored`: Build against the `botan-src` crate
* `static`: Statically link the library. This is always used if `vendored` is set
* `pkg-config`: Use `pkg-config` instead of probing to find the library
* `dynamic-loading`: Do not link to Botan; instead load the shared library at
  runtime and resolve each function on first use. Requires `std`, and cannot
  be combined with `vendored` or `static`. See `botan_sys::load_library`.

## Availability of functions

Every function in Botan's C API is declared by this crate, regardless of the
version of Botan detected at build time. Functions which the detected headers
predate are replaced by stubs with the identical name and signature which
return `BOTAN_FFI_ERROR_FUNCTION_NOT_AVAILABLE` (a code never returned by
Botan itself; for the few functions which do not return an error code the
stub returns 0 or a null pointer). This means code using this crate can be
written against the newest API without regard to which version will be
present, and handle unavailable functionality at runtime.

Internally the crate detects which version of the FFI interface the headers
declare and enables `#[cfg(botan_ffi_YYYYMMDD)]` for each supported version;
these cfgs are not visible to dependent crates.

With the `dynamic-loading` feature there is no build time detection at all;
each function is a wrapper which resolves the symbol from the loaded library
on first use, returning `BOTAN_FFI_ERROR_FUNCTION_NOT_AVAILABLE` if the
library does not export it, or `BOTAN_FFI_ERROR_LIBRARY_NOT_LOADED` if no
library could be loaded.

## Environment Variables

The following environment variables are used to guide features

* `BOTAN_INCLUDE_DIR` the base path to where the relevant library includes are
  found. For example if the headers are in `/opt/foo/botan-3/botan`, this
  variable should be set to `/opt/foo`. If not set, tries a few common
  locations. This variable is ignored if the `pkg-config` or `vendored`
  features are used.
* `BOTAN_LIB_DIR` the directory to search for pre-build shared or static
   libraries.
