use crate::utils::*;
use botan_sys::*;

/// Wrap a key using NIST key wrap algorithm
///
/// This requires `botan_ffi_20230403`, otherwise a not implemented error is returned
pub fn nist_kw_enc(cipher_algo: &str, padding: bool, kek: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    crate::ffi_version_guard!(
        "nist_kw_enc",
        botan_ffi_20230403,
        [cipher_algo, padding, kek, key],
        {
            let mut output = vec![0; key.len() + if padding { 32 } else { 8 }];
            let mut output_len = output.len();

            botan_call!(
                botan_nist_kw_enc,
                make_cstr(cipher_algo)?.as_ptr(),
                c_int::from(padding),
                key.as_ptr(),
                key.len(),
                kek.as_ptr(),
                kek.len(),
                output.as_mut_ptr(),
                &mut output_len
            )?;

            output.resize(output_len, 0);

            Ok(output)
        }
    )
}

/// Unwrap a key using NIST key wrap algorithm
///
/// This requires `botan_ffi_20230403`, otherwise a not implemented error is returned
pub fn nist_kw_dec(
    cipher_algo: &str,
    padding: bool,
    kek: &[u8],
    wrapped: &[u8],
) -> Result<Vec<u8>> {
    crate::ffi_version_guard!(
        "nist_kw_dec",
        botan_ffi_20230403,
        [cipher_algo, padding, kek, wrapped],
        {
            let mut output = vec![0; wrapped.len()];
            let mut output_len = output.len();

            botan_call!(
                botan_nist_kw_dec,
                make_cstr(cipher_algo)?.as_ptr(),
                c_int::from(padding),
                wrapped.as_ptr(),
                wrapped.len(),
                kek.as_ptr(),
                kek.len(),
                output.as_mut_ptr(),
                &mut output_len
            )?;

            output.resize(output_len, 0);

            Ok(output)
        }
    )
}

/// Wrap a key using RFC 3394's AES key wrap algorithm.
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
/// let wrapped = botan::rfc3394_key_wrap(&kek, &key).unwrap();
/// ```
pub fn rfc3394_key_wrap(kek: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if kek.len() != 16 && kek.len() != 24 && kek.len() != 32 {
        return Err(Error::with_message(
            ErrorType::InvalidKeyLength,
            "Invalid AES key length".to_string(),
        ));
    }

    if key.len() % 8 != 0 {
        return Err(Error::with_message(
            ErrorType::InvalidInput,
            "Invalid keywrap input length".to_string(),
        ));
    }

    let mut output = vec![0; key.len() + 8];
    let mut output_len = output.len();

    botan_call!(
        botan_key_wrap3394,
        key.as_ptr(),
        key.len(),
        kek.as_ptr(),
        kek.len(),
        output.as_mut_ptr(),
        &mut output_len
    )?;

    output.resize(output_len, 0);

    Ok(output)
}

/// Unwrap a key encrypted using RFC3394's AES key wrap algorithm
/// # Examples
///
/// ```
/// // Wrap a 128-bit key with a 256-bit key:
/// let key = vec![0; 16];
/// let kek = vec![0; 32];
/// let wrapped = botan::rfc3394_key_wrap(&kek, &key).unwrap();
/// let unwrapped = botan::rfc3394_key_unwrap(&kek, &wrapped).unwrap();
/// assert_eq!(unwrapped, key);
/// ```
pub fn rfc3394_key_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    if kek.len() != 16 && kek.len() != 24 && kek.len() != 32 {
        return Err(Error::with_message(
            ErrorType::InvalidKeyLength,
            "Invalid AES key length".to_string(),
        ));
    }

    if wrapped.len() % 8 != 0 {
        return Err(Error::with_message(
            ErrorType::InvalidInput,
            "Invalid keywrap input length".to_string(),
        ));
    }

    let mut output = vec![0; wrapped.len() - 8];
    let mut output_len = output.len();

    botan_call!(
        botan_key_unwrap3394,
        wrapped.as_ptr(),
        wrapped.len(),
        kek.as_ptr(),
        kek.len(),
        output.as_mut_ptr(),
        &mut output_len
    )?;

    output.resize(output_len, 0);

    Ok(output)
}
