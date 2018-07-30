use super::{Error, Result};

use botan_sys::*;

use rng::RandomNumberGenerator;
use std::ffi::CString;

const BCRYPT_SIZE : usize = 60;

pub fn bcrypt_hash(pass: &str, rng : &RandomNumberGenerator, workfactor: usize) -> Result<String> {

    let mut out = vec![0; BCRYPT_SIZE + 1];
    let mut out_len = out.len();

    call_botan! {
        botan_bcrypt_generate(out.as_mut_ptr(), &mut out_len,
                              CString::new(pass).unwrap().as_ptr(),
                              rng.handle(),
                              workfactor, 0u32)
    };

    out.resize(out_len - 1, 0);
    Ok(String::from_utf8(out).unwrap())
}

pub fn bcrypt_verify(pass: &str, hash: &str) -> Result<bool> {

    let rc = unsafe {
        botan_bcrypt_is_valid(CString::new(pass).unwrap().as_ptr(),
                              CString::new(hash).unwrap().as_ptr())
    };

    if rc == 0 {
        Ok(true)
    }
    else if rc == BOTAN_FFI_ERROR_BOTAN_FFI_INVALID_VERIFIER {
        Ok(false)
    }
    else {
        Err(Error::from(rc))
    }
}
