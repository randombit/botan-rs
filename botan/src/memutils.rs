use super::{Error, Result};

use botan_sys::*;
use std::mem;
use std::os::raw::{c_void, c_char};
use std::ffi::CString;

/// Const time comparison
/// Compare two arrays without leaking side channel information
pub fn const_time_compare<T: Copy>(a: &[T], b: &[T]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let bytes = mem::size_of::<T>() * a.len();
    let rc = unsafe { botan_constant_time_compare(a.as_ptr() as *const u8, b.as_ptr() as *const u8, bytes) };

    return rc == 0;
}

/// Securely zeroize memory
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
    Ok(CString::new(output).unwrap().into_string().unwrap())
}

/// Hex decode some data
pub fn hex_decode(x: &str) -> Result<Vec<u8>> {

    let mut output = vec![0u8; x.len()/2];
    let mut output_len = output.len();

    let input = CString::new(x).unwrap();

    call_botan! { botan_hex_decode(input.as_ptr(), x.len(), output.as_mut_ptr(), &mut output_len) }

    output.resize(output_len, 0);

    Ok(output)
}
