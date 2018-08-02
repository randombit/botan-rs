use super::{Error, Result};

use botan_sys::*;

use std::ffi::CString;

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

