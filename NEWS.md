## 0.11.0 Not Yet Released

- Bump MSRV to 1.64.0 for both std and no-std builds
- The `no-std` feature has been replaced by a `std` feature;
  use `no-default-features` to request a no_std enabled build.

## 0.10.7 2023-10-05

- Fix a bug which prevented compilation on systems where C chars
  are unsigned, such as aarch64

## 0.10.6 2023-07-18

- Add support for generating ElGamal and DSA keys using randomly
  generated groups
- Fix a new clippy from nightly

## 0.10.5 2023-07-14

- Improve support for building on Windows
- Rewrote the CI script in Python so it can be used on Windows as well

## 0.10.4 2023-07-13

- Add basic support for X.509 CRLs
- Add Cipher::ideal_update_granularity
- Fix test failures when compiling against Botan3 without "botan3" feature
  flag enabled.
- Fix some problems building with "botan3" feature flag in no-std builds
- The vendored Botan library is now 3.1.1 instead of 2.19.3; building with
  feature "vendored" implicitly enables also "botan3" feature.
- The published version of `botan-src` now excludes the C++ library
  tests, which improves the package size.

## 0.10.3 2023-05-20

- Fix an error that prevented compiling on 1.58.0 with botan3 flag
- Fix a new clippy warning
- When building the vendored library, add support for setting the
  method that source files are linked with (symlink, hardlink, copy).

## 0.10.2 2023-03-27

- Fix Pubkey::fingerprint
- Make use of new functionality in botan3 FFI which eliminates the need for
  potentially retrying an operation if the provided output buffer was too small.
- Add support for key encapsulation added in botan3

## 0.10.1 2023-03-08

- The MSRV for std builds has been reduced to Rust 1.58. The MSRV for
  no-std builds remains Rust 1.64

## 0.10.0 2023-03-07

- Add support for new Botan 3 APIs including zfec forward error correction,
  NIST keywrap with padding, and support for MACs with nonces
- Add more Wycheproof tests
- Add support for loading DSA public and private keys using
  ``Pubkey::load_dsa`` and ``Privkey::load_dsa``
- Add support for loading ElGamal public and private keys using
  ``Pubkey::load_elgamal`` and ``Privkey::load_elgamal``
- Add an interface to ``Cipher`` that avoids a heap allocation during
  encryption and decryption: ``Cipher::update_into`` and
  ``Cipher::finalize_into``

## 0.9.2 2023-02-24

- impl Send/Sync for the various types like ``BlockCipher``
- Fix ``MsgAuthCode`` to use ``&mut self`` for internally mutating
  operations; this was missed when the rest of the types were so
  modified in 0.9.0

## 0.9.1 2023-01-29

- Fix a problem building on Windows
- Fix various clippy warnings

## 0.9.0 2022-12-09

- Incompatible change: previously operations which modified the
  internal state of an object, such as ``BlockCipher::set_key`` and
  ``HashFunction::update`` used ``&self`` now use ``&mut self``.
- Errors can now capture a string message related to exceptions
- Add support for building against (currently unreleased) Botan 3.x
- Add more convenience macros for calling FFI
- Fix no_std builds with latest nightly
- Switch to using `core::ffi` added in Rust 1.64. As a result new
  MSRV is 1.64
- Updated botan-src to 2.19.3

## 0.8.1 2021-03-14

- Fix a bug that prevented using vendored builds on systems which
  use libc++ instead of libstdc++
- MSRV is now 1.43.0
- Fix some test compilation problems with recent nightly

## 0.8.0 2020-11-13

- Update botan-src to upstream 2.17.1 release
- Add ability to encrypt in place in raw block cipher API
- Fix a dangling pointer bug in the botan-sys tests which caused a
  crash with recent nightly

## 0.7.0 2020-09-27

- Add support for vendoring the Botan library via new botan-src crate
- Fix a problem with no_std builds in Rust 1.36 and higher
- Fix a build problem affecting machines with unsigned char
- Minimum supported version of Rust increased to 1.36

## 0.6.1 2020-02-15

- Fix some warnings under latest beta/nightly versions of Rust

## 0.6.0 2019-08-19

- Add time-based password key derivation
- Switch to using cty crate instead of libc to get C ABI types

## 0.5.0 2019-02-27

- Add incremental cipher interface
- Support no_std builds (feature `no-std`)
- Switch to 2018 edition

## 0.4.0 2018-10-01

- Add setters and getters for X25519 specific fields
- Use new interface for password hashing

## 0.3.0 2018-08-16

- Add certificate verification
- Add HOTP and TOTP
- Add setters and getters for Ed25519 specific fields
- Add base64 encode/decode

## 0.2.0 2018-08-15

Due to using several APIs only recently added, 0.2.0 onwards requires current
`master` branch of botan (upcoming 2.8, to be released in early October).

- Adds MPI type.
- Adds scrypt.
- Adds format preserving encryption
- Add NIST key wrapping.
- Adds various util functions to existing types.
- Fix a bug affecting DH/ECDH (it always returned exactly 128 bytes,
  instead of taking the requested KDF output length from the caller).

## 0.1.5 2018-08-5

Add documentation for most interfaces. No code changes.

## 0.1.4 2018-08-2

Add cipher modes, encrypted PEM keys, X509 certificates

## 0.1.3 2018-08-2

Adds bcrypt, KDF, PBKDF, public key operations

## 0.1.2 2018-07-26

Adds raw (ECB) block cipher interface

## 0.1.1 2018-07-25

Adds message authentication

## 0.1.0 2018-07-19

First release, mostly FFI declarations plus hashing.
