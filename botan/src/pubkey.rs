use super::{Error, Result};
use super::{call_botan_ffi_returning_vec_u8, call_botan_ffi_returning_string};

use botan_sys::*;

use rng::RandomNumberGenerator;
use std::os::raw::{c_char};
use std::ffi::CString;
use std::ptr;

#[derive(Debug)]
pub struct Pubkey {
    obj: botan_pubkey_t
}

#[derive(Debug)]
pub struct Privkey {
    obj: botan_privkey_t
}

impl Drop for Privkey {
    fn drop(&mut self) {
        unsafe { botan_privkey_destroy(self.obj) };
    }
}

impl Drop for Pubkey {
    fn drop(&mut self) {
        unsafe { botan_pubkey_destroy(self.obj) };
    }
}

impl Privkey {

    pub(crate) fn handle(&self) -> botan_privkey_t { self.obj }

    pub fn create(alg: &str, params: &str, rng: &RandomNumberGenerator) -> Result<Privkey> {

        let mut obj = ptr::null_mut();

        call_botan! { botan_privkey_create(&mut obj,
                                           CString::new(alg).unwrap().as_ptr(),
                                           CString::new(params).unwrap().as_ptr(),
                                           rng.handle()) }

        Ok(Privkey { obj })
    }

    pub fn load_der(der: &[u8]) -> Result<Privkey> {
        let mut obj = ptr::null_mut();

        // Don't need this with 2.8
        let rng = RandomNumberGenerator::new_system()?;
        call_botan! { botan_privkey_load(&mut obj, rng.handle(), der.as_ptr(), der.len(), ptr::null()) }

        Ok(Privkey { obj })
    }

    pub fn check_key(&self, rng: &RandomNumberGenerator) -> Result<bool> {

        let flags = 1u32;
        let rc = unsafe { botan_privkey_check_key(self.obj, rng.handle(), flags) };

        if rc == 0 {
            Ok(true)
        }
        else if rc == -1 {
            Ok(false)
        }
        else {
            Err(Error::from(rc))
        }
    }

    pub fn pubkey(&self) -> Result<Pubkey> {
        let mut obj = ptr::null_mut();
        call_botan! { botan_privkey_export_pubkey(&mut obj, self.obj) }
        Ok(Pubkey { obj })
    }

    pub fn algo_name(&self) -> Result<String> {
        // FIXME(2.8) need botan_privkey_get_name
        self.pubkey()?.algo_name()
    }

    pub fn der_encode(&self) -> Result<Vec<u8>> {
        call_botan_ffi_returning_vec_u8(&|out_buf, out_len| {
            unsafe { botan_privkey_export(self.obj, out_buf, out_len, 0u32) }
        })
    }

    pub fn pem_encode(&self) -> Result<String> {
        call_botan_ffi_returning_string(&|out_buf, out_len| {
            unsafe { botan_privkey_export(self.obj, out_buf, out_len, 1u32) }
        })
    }
}

impl Pubkey {

    pub(crate) fn handle(&self) -> botan_pubkey_t { self.obj }

    pub fn load_der(der: &[u8]) -> Result<Pubkey> {
        let mut obj = ptr::null_mut();
        call_botan! { botan_pubkey_load(&mut obj, der.as_ptr(), der.len()) }
        Ok(Pubkey { obj })
    }

    pub fn der_encode(&self) -> Result<Vec<u8>> {
        call_botan_ffi_returning_vec_u8(&|out_buf, out_len| {
            unsafe { botan_pubkey_export(self.obj, out_buf, out_len, 0u32) }
        })
    }

    pub fn pem_encode(&self) -> Result<String> {
        call_botan_ffi_returning_string(&|out_buf, out_len| {
            unsafe { botan_pubkey_export(self.obj, out_buf, out_len, 1u32) }
        })
    }

    pub fn algo_name(&self) -> Result<String> {
        call_botan_ffi_returning_string(&|out_buf, out_len| {
            unsafe { botan_pubkey_algo_name(self.obj, out_buf as *mut c_char, out_len) }
        })
    }

}
