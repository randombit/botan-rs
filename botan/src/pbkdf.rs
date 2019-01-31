
use botan_sys::*;
use crate::utils::*;

/// Password based key derivation function
///
/// # Examples
/// ```
/// let rng = botan::RandomNumberGenerator::new().unwrap();
/// let salt = rng.read(10).unwrap();
/// let key = botan::derive_key_from_password("Scrypt", 32, "passphrase", &salt, 8192, 8, 1).unwrap();
/// assert_eq!(key.len(), 32);
/// ```
pub fn derive_key_from_password(
    algo: &str,
    out_len: usize,
    passphrase: &str,
    salt: &[u8],
    param1: usize,
    param2: usize,
    param3: usize) -> Result<Vec<u8>> {

    let algo = make_cstr(algo)?;
    let passphrase = make_cstr(passphrase)?;

    let mut output = vec![0u8; out_len];

    call_botan! {
        botan_pwdhash(algo.as_ptr(),
                      param1,
                      param2,
                      param3,
                      output.as_mut_ptr(),
                      output.len(),
                      passphrase.as_ptr(),
                      0,
                      salt.as_ptr(),
                      salt.len())
    }

    Ok(output)
}

/// Password based key derivation function
///
/// Note currently only PBKDF2 is supported by this interface.
/// For PBKDF2, iterations >= 100000 is recommended.
///
/// # Examples
/// ```
/// let rng = botan::RandomNumberGenerator::new().unwrap();
/// let salt = rng.read(10).unwrap();
/// let key = botan::pbkdf("PBKDF2(SHA-256)", 32, "passphrase", &salt, 10000).unwrap();
/// assert_eq!(key.len(), 32);
/// ```
pub fn pbkdf(algo: &str,
             out_len: usize,
             passphrase: &str,
             salt: &[u8],
             iterations: usize) -> Result<Vec<u8>> {

    derive_key_from_password(algo, out_len, passphrase, salt, iterations, 0, 0)
}

/// Scrypt key derivation
///
/// The n, r, p parameters control how much time and memory is used.
/// As of 2018, n = 32768, r = 8, p = 1 seems sufficient.
///
/// # Examples
/// ```
/// let rng = botan::RandomNumberGenerator::new().unwrap();
/// let salt = rng.read(10).unwrap();
/// let n = 32768;
/// let r = 8;
/// let p = 1;
/// let key = botan::scrypt(32, "passphrase", &salt, n, r, p).unwrap();
/// assert_eq!(key.len(), 32);
/// ```
pub fn scrypt(out_len: usize,
              passphrase: &str,
              salt: &[u8],
              n: usize,
              r: usize,
              p: usize) -> Result<Vec<u8>> {

    derive_key_from_password("Scrypt", out_len, passphrase, salt, n, r, p)
}
