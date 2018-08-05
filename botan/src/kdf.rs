use super::{Error, Result};

use botan_sys::*;

use std::ffi::CString;

/// Key derivation function
/// Produces a KDF output of the specified size when run over the
/// provided secret, salt, and label inputs
///
/// # Examples
/// ```
/// let salt = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
/// let label = vec![0x42, 0x6F, 0x62];
/// let secret = vec![0x4E, 0x6F, 0x74, 0x20, 0x54, 0x65, 0x6C, 0x6C, 0x69, 0x6E, 0x67];
/// let v = botan::kdf("HKDF(SHA-256)", 23, &secret, &salt, &label).unwrap();
/// assert_eq!(v.len(), 23);
/// ```
pub fn kdf(algo: &str, output_len: usize, secret: &[u8], salt: &[u8], label: &[u8]) -> Result<Vec<u8>> {

    let mut output = vec![0u8; output_len];

    let algo = CString::new(algo).unwrap();

    call_botan! { botan_kdf(algo.as_ptr(),
                            output.as_mut_ptr(), output_len,
                            secret.as_ptr(), secret.len(),
                            salt.as_ptr(), salt.len(),
                            label.as_ptr(), label.len()) };

    Ok(output)

}
