
use botan_sys::*;
use crate::utils::*;

/// Const time comparison
///
/// Compare two arrays without leaking side channel information
#[must_use]
pub fn const_time_compare<T: Copy>(a: &[T], b: &[T]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let bytes = mem::size_of::<T>() * a.len();
    let rc = unsafe { botan_constant_time_compare(a.as_ptr() as *const u8, b.as_ptr() as *const u8, bytes) };

    return rc == 0;
}

/// Securely zeroize memory
///
/// Write zeros to the array (eg to clear out a key) in a way that is
/// unlikely to be removed by the compiler.
pub fn scrub_mem<T: Copy>(a: &mut [T]) {
    let bytes = mem::size_of::<T>() * a.len();
    unsafe { botan_scrub_mem(a.as_mut_ptr() as *mut c_void, bytes) };
}

/// Hex encode some data
pub fn hex_encode(x: &[u8]) -> Result<String> {
    let flags = 0u32;

    let mut output = vec![0u8; x.len() * 2];
    call_botan! { botan_hex_encode(x.as_ptr(), x.len(), output.as_mut_ptr() as *mut c_char, flags) };

    String::from_utf8(output).map_err(|_| Error::ConversionError)
}

/// Hex decode some data
pub fn hex_decode(x: &str) -> Result<Vec<u8>> {

    let mut output = vec![0u8; x.len()/2];
    let mut output_len = output.len();

    let input = make_cstr(x)?;

    call_botan! { botan_hex_decode(input.as_ptr(), x.len(), output.as_mut_ptr(), &mut output_len) }

    output.resize(output_len, 0);

    Ok(output)
}

/// Base64 encode some data
///
/// # Examples
///
/// ```
/// assert_eq!(botan::base64_encode(&[97,98,99,100,101,102]).unwrap(), "YWJjZGVm");
/// assert_eq!(botan::base64_encode(&[0x5A, 0x16, 0xAD, 0x4E, 0x17, 0x87, 0x79, 0xC9]).unwrap(), "WhatTheHeck=");
/// ```
pub fn base64_encode(x: &[u8]) -> Result<String> {

    let b64_len = 1 + ((x.len() + 2) / 3) * 4;

    call_botan_ffi_returning_string(b64_len, &|out_buf, out_len| {
        unsafe { botan_base64_encode(x.as_ptr(), x.len(), out_buf as *mut c_char, out_len) }
    })
}

/// Base64 decode some data
///
/// # Examples
///
/// ```
/// assert!(botan::base64_decode("ThisIsInvalid!").is_err());
/// assert_eq!(botan::base64_decode("YWJjZGVm").unwrap(), b"abcdef");
/// ```
pub fn base64_decode(x: &str) -> Result<Vec<u8>> {

    // Hard to provide a decent lower bound as it is possible x includes
    // lots of spaces or trailing = padding chars
    let bin_len = x.len();

    let input = make_cstr(x)?;

    call_botan_ffi_returning_vec_u8(bin_len, &|out_buf, out_len| {
        unsafe { botan_base64_decode(input.as_ptr(), x.len(), out_buf, out_len) }
    })
}
