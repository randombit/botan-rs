use crate::utils::*;
use botan_sys::*;

/// Wrap a key using NIST's AES key wrap algorithm.
///
/// The kek (key-encryption-key) must be a valid length for an AES
/// key. The wrapped key must be a multiple of 8 bytes.
///
/// # Examples
///
/// ```
/// // Wrap a 128-bit key with a 256-bit key:
/// let key = vec![0; 16];
/// let kek = vec![0; 32];
/// let wrapped = botan::nist_key_wrap(&kek, &key).unwrap();
/// ```
pub fn nist_key_wrap(kek: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if kek.len() != 16 && kek.len() != 24 && kek.len() != 32 {
        return Err(Error::InvalidKeyLength);
    }

    if key.len() % 8 != 0 {
        return Err(Error::InvalidInput);
    }

    let mut output = vec![0; key.len() + 8];
    let mut output_len = output.len();

    call_botan! {
        botan_key_wrap3394(key.as_ptr(), key.len(),
                           kek.as_ptr(), kek.len(),
                           output.as_mut_ptr(), &mut output_len)
    }

    output.resize(output_len, 0);

    Ok(output)
}

/// Unwrap a key encrypted using NIST's AES key wrap algorithm
/// # Examples
///
/// ```
/// // Wrap a 128-bit key with a 256-bit key:
/// let key = vec![0; 16];
/// let kek = vec![0; 32];
/// let wrapped = botan::nist_key_wrap(&kek, &key).unwrap();
/// let unwrapped = botan::nist_key_unwrap(&kek, &wrapped).unwrap();
/// assert_eq!(unwrapped, key);
/// ```
pub fn nist_key_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    if kek.len() != 16 && kek.len() != 24 && kek.len() != 32 {
        return Err(Error::InvalidKeyLength);
    }

    if wrapped.len() % 8 != 0 {
        return Err(Error::InvalidInput);
    }

    let mut output = vec![0; wrapped.len() - 8];
    let mut output_len = output.len();

    call_botan! {
        botan_key_unwrap3394(wrapped.as_ptr(), wrapped.len(),
                             kek.as_ptr(), kek.len(),
                             output.as_mut_ptr(), &mut output_len)
    }

    output.resize(output_len, 0);

    Ok(output)
}
