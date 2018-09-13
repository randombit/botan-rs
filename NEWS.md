
## 0.4.0 Not Yet Released

- Add setters and getters for X25519 specific fields
- Use new interface for password hashing

## 0.3.0 2018-8-16

- Add certificate verification
- Add HOTP and TOTP
- Add setters and getters for Ed25519 specific fields
- Add base64 encode/decode

## 0.2.0 2018-8-15

Due to using several APIs only recently added, 0.2.0 onwards requires current
`master` branch of botan (upcoming 2.8, to be released in early October).

- Adds MPI type.
- Adds scrypt.
- Adds format preserving encryption
- Add NIST key wrapping.
- Adds various util functions to existing types.
- Fix a bug affecting DH/ECDH (it always returned exactly 128 bytes,
  instead of taking the requested KDF output length from the caller).

## 0.1.5 2018-8-5

Add documentation for most interfaces. No code changes.

## 0.1.4 2018-8-2

Add cipher modes, encrypted PEM keys, X509 certificates

## 0.1.3 2018-8-2

Adds bcrypt, KDF, PBKDF, public key operations

## 0.1.2 2018-7-26

Adds raw (ECB) block cipher interface

## 0.1.1 2018-7-25

Adds message authentication

## 0.1.0 2018-7-19

First release, mostly FFI declarations plus hashing.
