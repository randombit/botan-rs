
use botan_sys::*;
use utils::*;

/// Password based key derivation function
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

    let algo = CString::new(algo).unwrap();
    let passphrase = CString::new(passphrase).unwrap();

    let mut output = vec![0u8; out_len];

    call_botan! { botan_pbkdf(algo.as_ptr(),
                              output.as_mut_ptr(),
                              output.len(),
                              passphrase.as_ptr(),
                              salt.as_ptr(),
                              salt.len(),
                              iterations) }

    Ok(output)
}


/// Scrypt key derivation
pub fn scrypt(out_len: usize,
              passphrase: &str,
              salt: &[u8],
              n: usize,
              r: usize,
              p: usize) -> Result<Vec<u8>> {

    let passphrase = CString::new(passphrase).unwrap();

    let mut output = vec![0u8; out_len];

    call_botan! {
        botan_scrypt(output.as_mut_ptr(), output.len(),
                     passphrase.as_ptr(),
                     salt.as_ptr(), salt.len(),
                     n, r, p)
    }

    Ok(output)

}
