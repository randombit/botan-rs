# Release notes for the `botan`, `botan-src`, and `botan-sys` crates.

## 2026-08-17 botan-src 0.31300.1

- On Windows, build the library using `nmake` rather than `make`, since the
  generated Makefile targets the MSVC toolchain and GNU make is frequently
  not installed (GH #197)
- On Windows, skip symlinks and hard links when extracting the bundled source
  tarball (GH #198)

## 2026-08-16 botan 0.14.0

- Minor version bump due to changes to `ErrorType`
- Add enumeration-based algorithm specifiers instead of forcing the use of
  string based names, eg for `botan::mac::new` instead of "HMAC/SHA-256",
  one can use `botan::MacAlgorithm::Hmac(botan::HashAlgorithm::Sha256)`.
  The string naming still works too.
- All APIs are available no matter what version of Botan the crate builds against.
  If an older library is in use, the API will fail with `NotImplemented`; the
  new `Error::is_function_unavailable` distinguishes this from functionality
  compiled out of the library.
- Add the `dynamic-loading` feature, which loads the Botan shared library at
  runtime rather than linking to it. No Botan installation is needed to build,
  and the available functionality is determined by the library found at
  runtime. See `botan::load_library`.
- `ErrorType` is now `#[non_exhaustive]` and gains the `LibraryNotLoaded` variant
- The `no_std` build no longer requires Botan 3.11.0 at build time; instead
  relevant public key operations return an error at runtime with older versions
- The per-key lock used to work around thread safety bugs in Botan versions
  prior to 3.11.0 is now skipped for keys using algorithms known to be
  unaffected (RSA, ECDSA, Ed25519, etc). In `no_std` builds, operations with
  such keys now work with older versions of Botan.
- Add support for SPAKE2+ added in Botan 3.13
- Add support for X.509 RPKI extensions added in Botan 3.13
- Add `EcGroup::unregister` (requires Botan 3.11)
- Upgrade `rand` dependency to 0.10
- Fix various tests which could fail if features were compiled out
  of the underlying C++ library

## 2026-08-16 botan-src 0.31300.0

- Update the bundled Botan to 3.13.0

## 2026-08-16 botan-sys 1.20260811.1

- Add declarations for the functions added in the Botan 3.13 FFI (version
  20260811): SPAKE2+, the X.509 RPKI (IP address and AS blocks) extension
  accessors, and `botan_hash_security_level`
- Every FFI function is now declared unconditionally, regardless of the version
  of Botan detected at build time. Functions which the detected headers predate
  are replaced by stubs with the identical name and signature which return the
  new `BOTAN_FFI_ERROR_FUNCTION_NOT_AVAILABLE` error code, so unavailable
  functionality is a runtime error rather than a compile error. The
  `botan_ffi_YYYYMMDD` cfgs are now purely internal to the crate.
- Add the `dynamic-loading` feature. Instead of linking against Botan, the
  shared library is loaded at runtime (using `libloading`) and each function is
  resolved on first use; see `botan_sys::load_library`. Adds the
  `BOTAN_FFI_ERROR_LIBRARY_NOT_LOADED` error code. The crate is no longer
  `no_std` when this feature is enabled, and it cannot be combined with
  `vendored` or `static`.
- `BOTAN_INCLUDE_DIR` is now searched for a `botan-3` (or `botan-2`)
  subdirectory, as the documentation always described, rather than being used
  directly as the include path

## 2026-05-07 botan 0.13.0

- Minor version bump due to MSRV increase
- Bump MSRV to 1.85.0
- Bump Rust Edition to 2024
- Add support for new FFI interfaces in Botan 3.10, 3.11, 3.12
- Add locking to Privkey to work around bugs in versions of Botan prior to 3.11.0.
  This requires `std` support; thus `no_std` builds now require at least Botan 3.11.0
- Implement `rand::TryRngCore` for `RandomNumberGenerator`, behind the new
  (default) `rand` feature
- Add `Signer::signature_length`
- Add `Pubkey::load_rsa_pkcs1` for loading RSA public keys in PKCS#1 form
- Add `EcPoint` and `EcScalar` types (requires Botan 3.12)
- Add various interfaces for CRL generation and handling
- Add additional X.509 certificate getters: `ocsp_responders`,
  `issuer_dn`, `subject_dn`, `is_ca`, `path_limit`, `pem_encode`, `der_encode`
- Fix `Cipher::update`/`Cipher::finish` and their `_into` variants to size the
  output using the cipher's actual output length; previously they failed with
  modes such as CBC where padding makes the output longer than the input
  (GH #154, GH #155)
- Fix some tests that hit behavior changes in Botan 3.12

## 2026-05-07 botan-src 0.31200.0

- Update the bundled Botan to 3.12.0
- The crate now ships the upstream Botan release tarball (`.tar.xz`) inside
  the published crate and extracts it at build time, verifying its SHA-256,
  rather than building from a git submodule with parts of the source tree
  excluded at publication. The pinned release is recorded in `release.toml`
  and exposed as `botan_src::BOTAN_VERSION`, `BOTAN_TARBALL_SHA256`, and
  `BOTAN_TARBALL_URL`. This adds build-time dependencies on `lzma-rs`,
  `sha2`, and `tar`.
- Add the `BOTAN_SRC_DIR` and `BOTAN_SRC_TARBALL` environment variables, to
  build from a local source tree or an alternate tarball instead of the
  bundled release
- Bump MSRV to 1.85.0 and Rust Edition to 2024

## 2026-05-07 botan-sys 1.20260506.0

- Add declarations for the functions added in the Botan 3.10 (20250829),
  3.11 (20260303) and 3.12 (20260506) FFI interfaces, including XOFs, SRP6,
  TPM2, EC points and scalars, EC, RSA, X448 and Ed448 key accessors, custom
  and DRBG RNGs, CRL creation, and many additional X.509 certificate and CRL
  accessors, as well as various functions declared in older versions of
  `ffi.h` that had been missed
- Add error codes `BOTAN_FFI_ERROR_OUT_OF_RANGE`,
  `BOTAN_FFI_ERROR_ROUGHTIME_ERROR`, and `BOTAN_FFI_ERROR_TPM_ERROR`
- Remove the declaration of `botan_x509_cert_gen_selfsigned`, which does not
  exist in Botan's C API
- Bump MSRV to 1.85.0 and Rust Edition to 2024

## 2025-08-05 botan 0.12.0

- Minor version bump due to removing a feature
- The `botan3` feature has been removed from the crate. Now `botan-sys` detects
  the version of Botan it is being built against, and exports appropriate `cfg`
  variables.
- Add ML-KEM support (requires Botan 3.8 or higher)
- Add support for X448 and Ed448 (requires Botan 3.4 or higher)
- Add `OID` and `EcGroup` types (requires Botan 3.8 or higher)
- Add `RandomNumberGenerator::new_of_type`
- Add `RandomNumberGenerator::new_jitter`, `new_esdm`, and `new_esdm_pr`

## 2025-08-05 botan-src 0.30900.2

- Update the bundled Botan to 3.9.0 (Botan 3.8.0 was never published in a
  `botan-src` release)
- `build()` now returns the include directory as a `PathBuf` rather than a
  `String`

## 2025-08-05 botan-src 0.30900.1 (yanked)

- Yanked: this was accidentally published from a checkout with a stale
  submodule, so despite the version number it contained Botan 3.5.0.
  Use 0.30900.2 instead.

## 2025-08-05 botan-sys 1.20250506.0

- The crate has been renumbered as `1.YYYYMMDD.X` where YYYYMMDD is the
  latest supported Botan FFI version, since changes to the FFI layer are only
  ever additive (GH #113)
- The `botan3` feature has been removed. Instead the build script detects the
  version of Botan being built against by preprocessing its headers, and
  enables `botan_ffi_YYYYMMDD` cfgs on that basis. Declarations for functions
  added since Botan 3.0 are only present when the detected version supports
  them.
- Add declarations for functions added in Botan 3.0 through 3.8, including
  OIDs, EC groups, loading of ML-KEM, ML-DSA, SLH-DSA, FrodoKEM, Classic
  McEliece, X448 and Ed448 keys, and raw key views
- Remove the declaration of the long deprecated `botan_privkey_create_mceliece`
- Add the `BOTAN_INCLUDE_DIR` and `BOTAN_LIB_DIR` environment variables to
  specify where the headers and library are found
- The `links` key is now `botan` rather than `botan-3`
- On docs.rs, all functionality is documented regardless of the installed
  library

## 2025-03-13 botan-src 0.30701.2

- Fix a configure failure ("Module policy fips140.txt includes non-existent
  module sodium") when building the published crate, caused by a policy file
  in Botan 3.7 referencing the `sodium` module whose sources had been
  excluded from the crate. The `sodium` and TLS sources are included again,
  so the crate is somewhat larger and slower to compile. (GH #144)
- `build()` now returns `build/include/public` as the include directory,
  matching where Botan 3.x places its public headers

## 2025-02-25 botan 0.11.1

- Add getters for X.509 certificate notBefore and notAfter fields
- Add function to create signatures with DER encoding
- Fix various new clippy warnings
- Fix a test to handle differing behavior for X25519 key agreement

## 2025-02-25 botan-src 0.30701.1 (yanked)

- Update the bundled Botan to 3.7.1
- The crate now takes target CPU and OS from the cargo target triple rather
  than requiring it be set separately using environment variables (GH #128)
- Remove passthrough of several further `BOTAN_CONFIGURE_*` options that are
  not applicable to a crate build, including `--link-method`,
  `--minimized-build`, `--no-optimizations`, and the install path options
- Exclude more of the unused upstream source tree (TLS, TPM2, the Python
  module, and CT self tests) from the published crate
- Yanked: a policy file added in Botan 3.7 references the `sodium` module,
  whose sources are excluded from the published crate, causing a hard error
  from `configure.py` (GH #144). Use 0.30701.2 instead.

## 2025-02-25 botan-sys 0.11.1

- Add declarations for `botan_x509_cert_not_before` and
  `botan_x509_cert_not_after`
- Add error code `BOTAN_FFI_ERROR_NO_VALUE`
- Fix new clippy warnings

## 2024-08-28 botan 0.11.0

- Minor version bump due to MSRV increase and feature renames
- Bump MSRV to 1.64.0 for both std and no-std builds
- The `no-std` feature has been replaced by a `std` feature;
  use `default-features = false` to request a `no_std` enabled build.
- Add `pkg-config` and `static` features
- Fix various clippy warnings
- Update wycheproof test dependency to 0.6

## 2024-08-28 botan-src 0.30500.1

- Update the bundled Botan to 3.5.0
- Exclude additional unused parts of the upstream source tree (`sodium`
  compat, filters, and the PKCS #11 and TPM providers) from the published
  crate, reducing its size (GH #107)
- Remove the Makefile hack previously used on Windows
- Bump MSRV to 1.64.0

## 2024-08-28 botan-sys 0.11.0

- Bump MSRV to 1.64.0
- The `no-std` feature has been removed; the crate is now always `no_std`
- Add the `static` feature to link statically against a system Botan, and the
  `pkg-config` feature to locate the library using pkg-config
- The `links` key is now `botan-3` rather than `botan-2`

## 2023-10-05 botan 0.10.7

- Fix a bug which prevented compilation on systems where C chars
  are unsigned, such as aarch64

## 2023-07-18 botan 0.10.6

- Add support for generating ElGamal and DSA keys using randomly
  generated groups
- Fix a new clippy from nightly

## 2023-07-14 botan 0.10.5

- Improve support for building on Windows (in `botan-src` and `botan-sys`)
- Rewrote the CI script in Python so it can be used on Windows as well

## 2023-07-14 botan-src 0.30101.2

- Improve support for building on Windows: the amalgamation build is used
  to avoid overly long linker command lines, and the generated Makefile is
  patched to use the correct path separator

## 2023-07-14 botan-sys 0.10.5

- Improve support for building on Windows: when using the vendored library,
  link against `user32` and `crypt32` rather than a C++ runtime library

## 2023-07-13 botan 0.10.4

- Add basic support for X.509 CRLs
- Add Cipher::ideal_update_granularity
- Fix test failures when compiling against Botan3 without "botan3" feature
  flag enabled.
- Fix some problems building with "botan3" feature flag in no-std builds
- The vendored Botan library is now 3.1.1 instead of 2.19.3; building with
  feature "vendored" implicitly enables also "botan3" feature.

## 2023-07-13 botan-src 0.30101.1

- The bundled Botan is now 3.1.1 instead of 2.19.3
- The published version of the crate now excludes the C++ library
  tests (along with the documentation, CLI, examples and fuzzers),
  which improves the package size.

## 2023-07-13 botan-sys 0.10.4

- Add declarations for the X.509 CRL functions and
  `botan_cipher_get_ideal_update_granularity`
- The `vendored` feature now implies `botan3`, since the vendored library is
  now Botan 3.1.1; the build no longer panics when both are set

## 2023-05-20 botan 0.10.3

- Fix an error that prevented compiling on 1.58.0 with botan3 flag
  (in `botan-sys`)
- Fix a new clippy warning

## 2023-05-20 botan-sys 0.10.3

- Fix an error that prevented compiling on 1.58.0 with botan3 flag (GH #85)

## 2023-04-13 botan-src 0.21903.1

- When building the vendored library, add support for setting the
  method that source files are linked with (symlink, hardlink, copy)
  using `BOTAN_CONFIGURE_LINK_METHOD` (GH #82)

## 2023-03-27 botan 0.10.2

- Fix Pubkey::fingerprint
- Make use of new functionality in botan3 FFI which eliminates the need for
  potentially retrying an operation if the provided output buffer was too small.
- Add support for key encapsulation added in botan3

## 2023-03-27 botan-sys 0.10.2

- Add declarations for the botan3 view functions (`botan_*_view_*`) along
  with the `botan_view_ctx`, `botan_view_bin_fn` and `botan_view_str_fn` types
- Add declarations for the botan3 KEM interface (`botan_pk_op_kem_*`)
- Add error code `BOTAN_FFI_ERROR_STRING_CONVERSION_ERROR`

## 2023-03-08 botan 0.10.1

- The MSRV for std builds has been reduced to Rust 1.58. The MSRV for
  no-std builds remains Rust 1.64

## 2023-03-08 botan-sys 0.10.1

- The MSRV for std builds has been reduced to Rust 1.58, by using
  `std::os::raw` rather than `std::ffi` for C types. The MSRV for
  no-std builds remains Rust 1.64
- The build now fails early with an explanatory panic if `vendored` and
  `botan3` are combined, since the vendored library was still Botan 2.x

## 2023-03-07 botan 0.10.0

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

## 2023-03-07 botan-sys 0.10.0

- Add declarations for new Botan 3 APIs: zfec (`botan_zfec_encode`,
  `botan_zfec_decode`), NIST key wrap with padding (`botan_nist_kw_enc`,
  `botan_nist_kw_dec`), and `botan_mac_set_nonce`
- The C types used in the declarations are now re-exported from a new
  `botan_sys::ffi_types` module. The crate is now only `no_std` when the
  `no-std` feature is enabled; C types come from `core::ffi` in that case
  and `std::ffi` otherwise.

## 2023-02-24 botan 0.9.2

- impl Send/Sync for the various types like ``BlockCipher``
- Fix ``MsgAuthCode`` to use ``&mut self`` for internally mutating
  operations; this was missed when the rest of the types were so
  modified in 0.9.0

## 2023-01-29 botan 0.9.1

- Fix a problem building on Windows (in `botan-sys`)
- Fix various clippy warnings

## 2023-01-29 botan-sys 0.9.1

- Fix a problem building on Windows, where the Botan 2.x library does not
  include the major version in its name (GH #58)
- Fix various clippy warnings

## 2022-12-09 botan 0.9.0

- Incompatible change: previously operations which modified the
  internal state of an object, such as ``BlockCipher::set_key`` and
  ``HashFunction::update`` used ``&self`` now use ``&mut self``.
- Errors can now capture a string message related to exceptions
- Add support for building against (currently unreleased) Botan 3.x
  using the new `botan3` feature
- Add more convenience macros for calling FFI
- Fix no_std builds with latest nightly
- Switch to using `core::ffi` added in Rust 1.64. As a result new
  MSRV is 1.64
- Switch to 2021 edition

## 2022-12-09 botan-src 0.21903.0

- Update the bundled Botan to 2.19.3
- `configure.py` is now invoked using `python3` rather than `python`
- Switch to 2021 edition

## 2022-12-09 botan-sys 0.9.0

- Add the `botan3` feature, which links against `botan-3` rather than
  `botan-2`, for building against (currently unreleased) Botan 3.x
- Add declaration for `botan_error_last_exception_message`
- Add error codes `BOTAN_FFI_ERROR_HTTP_ERROR`,
  `BOTAN_FFI_ERROR_INTERNAL_ERROR`, `BOTAN_FFI_ERROR_INVALID_OBJECT_STATE`,
  `BOTAN_FFI_ERROR_SYSTEM_ERROR`, and `BOTAN_FFI_ERROR_TLS_ERROR`
- Switch to using `core::ffi` added in Rust 1.64 for the C types, dropping
  the dependency on `cty`. As a result new MSRV is 1.64
- Switch to 2021 edition

## 2021-03-14 botan 0.8.1

- Fix a bug that prevented using vendored builds on systems which
  use libc++ instead of libstdc++ (in `botan-sys`)
- MSRV is now 1.43.0
- Fix some test compilation problems with recent nightly

## 2021-03-14 botan-src 0.21703.0

- Update the bundled Botan to 2.17.3
- The `BOTAN_CONFIGURE_*` environment variables are now derived directly
  from the corresponding `configure.py` option names. As a result the
  misnamed `BOTAN_CONFIGURE_CC_API_FLAGS` is now
  `BOTAN_CONFIGURE_CC_ABI_FLAGS`, and `BOTAN_CONFIGURE_COMPILER_CACHE`
  is newly supported.

## 2021-03-14 botan-sys 0.8.1

- Fix a bug that prevented using vendored builds on systems which
  use libc++ instead of libstdc++
- MSRV is now 1.43.0

## 2020-11-13 botan 0.8.0

- Add ability to encrypt in place in raw block cipher API

## 2020-11-13 botan-src 0.21701.0

- Update the bundled Botan to 2.17.1
- The library is now always built with optimizations enabled; debug builds
  add debug info rather than disabling optimization
- Support parallel builds by passing cargo's jobserver settings to `make`
- Fail the build if `configure.py` or `make` fails, rather than continuing
- Remove passthrough of a number of `BOTAN_CONFIGURE_*` environment variables
  (CPU feature toggles, sanitizer, fuzzer and coverage options, etc) that are
  not relevant to a crate build

## 2020-11-13 botan-sys 0.8.0

- Fix a dangling pointer bug in the tests which caused a
  crash with recent nightly
- Add a dummy `no-std` feature (the crate is always `no_std`), so that
  the feature can be enabled uniformly across the workspace

## 2020-09-27 botan 0.7.0

- Add support for vendoring the Botan library via new botan-src crate
  and the `vendored` feature
- Fix a problem with no_std builds in Rust 1.36 and higher
- Fix a build problem affecting machines with unsigned char
- Minimum supported version of Rust increased to 1.36

## 2020-09-27 botan-src 0.21500.0

- First release, providing the sources of Botan 2.15.0 (as a git submodule)
  and a `build()` function which configures and builds them as a static
  library. The version number encodes the bundled Botan version as
  `0.MMmmpp.X`.
- The build can be customized using `BOTAN_CONFIGURE_*` environment
  variables, each of which passes the corresponding `configure.py` option

## 2020-09-27 botan-sys 0.7.0

- Add the `vendored` feature which builds and statically links the library
  using the new `botan-src` crate

## 2020-02-15 botan 0.6.1

- Fix some warnings under latest beta/nightly versions of Rust

## 2019-08-19 botan 0.6.0

- Add time-based password key derivation
- Switch to using cty crate instead of libc to get C ABI types

## 2019-08-19 botan-sys 0.6.0

- Switch to using cty crate instead of libc to get C ABI types

## 2019-02-27 botan 0.5.0

- Add incremental cipher interface
- Support no_std builds (feature `no-std`)
- Switch to 2018 edition

## 2019-02-27 botan-sys 0.5.0

- The crate is now `no_std`, using the `libc` crate rather than
  `std::os::raw` for C types

## 2018-10-01 botan 0.4.0

- Add setters and getters for X25519 specific fields
- Use new interface for password hashing

## 2018-10-01 botan-sys 0.4.0

- Add declarations for the X25519 key functions
- Add declarations for `botan_pwdhash` and `botan_pwdhash_timed`

## 2018-08-17 botan 0.3.0

- Add certificate verification
- Add HOTP and TOTP
- Add setters and getters for Ed25519 specific fields
- Add base64 encode/decode

## 2018-08-17 botan-sys 0.3.0

- Add declarations for certificate verification and `botan_x509_cert_dup`
- Add declarations for HOTP and TOTP

## 2018-08-15 botan 0.2.0

Due to using several APIs only recently added, 0.2.0 onwards requires at
least Botan 2.8

- Adds MPI type.
- Adds scrypt.
- Adds format preserving encryption
- Add NIST key wrapping.
- Adds various util functions to existing types.
- Fix a bug affecting DH/ECDH (it always returned exactly 128 bytes,
  instead of taking the requested KDF output length from the caller).

## 2018-08-15 botan-sys 0.2.0

- Add declarations for functions added in Botan 2.8, including scrypt,
  format preserving encryption, key wrapping, algorithm name and key
  specification queries, output length queries for public key operations,
  `botan_privkey_load_rsa_pkcs1`, and RNG entropy functions
- Rename the error code constants, eg `BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_BAD_MAC`
  is now `BOTAN_FFI_ERROR_BAD_MAC`
- Add error code `BOTAN_FFI_ERROR_INVALID_KEY_LENGTH`

## 2018-08-05 botan 0.1.5

Add documentation for most interfaces. No code changes.

## 2018-08-05 botan-sys 0.1.5

Crate metadata changes only.

## 2018-08-02 botan 0.1.4

Add cipher modes, encrypted PEM keys, X509 certificates

## 2018-08-02 botan-sys 0.1.4

Crate metadata changes only.

## 2018-08-02 botan 0.1.3

Adds bcrypt, KDF, PBKDF, public key operations

## 2018-08-02 botan-sys 0.1.3

Crate metadata changes only.

## 2018-07-27 botan 0.1.2

Adds raw (ECB) block cipher interface

## 2018-07-27 botan-sys 0.1.2

Adds declarations for the raw block cipher interface

## 2018-07-26 botan 0.1.1

Adds message authentication

## 2018-07-26 botan-sys 0.1.1

Adds declarations for most of the remaining C API: bcrypt, ciphers, KDF,
PBKDF, MPI, public key operations, and X.509 certificates

## 2018-07-19 botan 0.1.0

First release, mostly FFI declarations plus hashing.

## 2018-07-19 botan-sys 0.1.0

First release, with declarations for hashing, MACs, RNGs, and utility functions.
