use super::{Error, Result};
use super::{call_botan_ffi_returning_vec_u8};

use botan_sys::*;

use pubkey::{Privkey, Pubkey};
use rng::RandomNumberGenerator;
use std::ffi::CString;
use std::ptr;

#[derive(Debug)]
pub struct Signer {
    obj: botan_pk_op_sign_t
}

impl Drop for Signer {
    fn drop(&mut self) {
        unsafe { botan_pk_op_sign_destroy(self.obj) };
    }
}

impl Signer {

    pub fn new(key: &Privkey, padding: &str) -> Result<Signer> {
        let padding_cstr = CString::new(padding).unwrap();
        let mut obj = ptr::null_mut();
        call_botan! { botan_pk_op_sign_create(&mut obj, key.handle(), padding_cstr.as_ptr(), 0u32) }
        Ok(Signer { obj })
    }

    pub fn update(&self, data: &[u8]) -> Result<()> {
        call_botan! { botan_pk_op_sign_update(self.obj, data.as_ptr(), data.len()) };
        Ok(())
    }

    pub fn finish(&self, rng: &RandomNumberGenerator) -> Result<Vec<u8>> {
        call_botan_ffi_returning_vec_u8(&|out_buf, out_len| {
            unsafe { botan_pk_op_sign_finish(self.obj, rng.handle(), out_buf, out_len) }
        })
    }

}


#[derive(Debug)]
pub struct Verifier {
    obj: botan_pk_op_verify_t
}

impl Drop for Verifier {
    fn drop(&mut self) {
        unsafe { botan_pk_op_verify_destroy(self.obj) };
    }
}

impl Verifier {

    pub fn new(key: &Pubkey, padding: &str) -> Result<Verifier> {
        let padding_cstr = CString::new(padding).unwrap();
        let mut obj = ptr::null_mut();
        call_botan! { botan_pk_op_verify_create(&mut obj, key.handle(), padding_cstr.as_ptr(), 0u32) }
        Ok(Verifier { obj })
    }

    pub fn update(&self, data: &[u8]) -> Result<()> {
        call_botan! { botan_pk_op_verify_update(self.obj, data.as_ptr(), data.len()) };
        Ok(())
    }

    pub fn finish(&self, signature: &[u8]) -> Result<bool> {

        let rc = unsafe { botan_pk_op_verify_finish(self.obj, signature.as_ptr(), signature.len()) };

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

}

