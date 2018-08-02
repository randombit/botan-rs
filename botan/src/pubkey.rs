use super::{Error, Result};

use botan_sys::*;

use rng::RandomNumberGenerator;
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
        Ok("Need botan_privkey_get_name".to_string())
    }

    pub fn der_encode(&self) -> Result<Vec<u8>> {
        let mut output = vec![0; 4096];
        let mut out_len = output.len();

        let rc = unsafe { botan_privkey_export(self.obj, output.as_mut_ptr(), &mut out_len, 0u32) };
        if rc == 0 {
            assert!(out_len <= output.len());
            output.resize(out_len, 0);
            return Ok(output);
        }

        output.resize(out_len, 0);
        call_botan! { botan_privkey_export(self.obj, output.as_mut_ptr(), &mut out_len, 0u32) }
        output.resize(out_len, 0);
        Ok(output)
    }

    pub fn pem_encode(&self) -> Result<String> {
        Ok("TODO".to_owned())
    }
}
