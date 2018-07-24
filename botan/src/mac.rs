use super::{Error, Result};

use botan_sys::*;

use std::ffi::CString;
use std::ptr;

#[derive(Debug)]
pub struct MsgAuthCode {
    obj: botan_mac_t,
    output_length: usize
}

impl Drop for MsgAuthCode {
    fn drop(&mut self) {
        unsafe { botan_mac_destroy(self.obj); }
    }
}

impl MsgAuthCode {
    pub fn new(name: &str) -> Result<MsgAuthCode> {
        let mut obj = ptr::null_mut();
        call_botan! { botan_mac_init(&mut obj, CString::new(name).unwrap().as_ptr(), 0u32) };

        let mut output_length = 0;
        call_botan! { botan_mac_output_length(obj, &mut output_length) };

        Ok(MsgAuthCode { obj, output_length })
    }

    pub fn output_length(&self) -> usize { self.output_length }

    pub fn set_key(&self, key: &[u8]) -> Result<()> {
        call_botan! { botan_mac_set_key(self.obj, key.as_ptr(), key.len()) };
        Ok(())
    }

    pub fn update(&self, data: &[u8]) -> Result<()> {
        call_botan! { botan_mac_update(self.obj, data.as_ptr(), data.len()) };
        Ok(())
    }

    pub fn finish(&self) -> Result<Vec<u8>> {
        let mut output = vec![0; self.output_length()];
        call_botan! { botan_mac_final(self.obj, output.as_mut_ptr()) };
        Ok(output)
    }

    pub fn clear(&self) -> Result<()> {
        call_botan! { botan_mac_clear(self.obj) };
        Ok(())
    }
}
