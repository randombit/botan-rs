use super::{Error, Result};

use botan_sys::*;

use std::ffi::CString;

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
