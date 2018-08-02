use super::{Error, Result};

use botan_sys::*;

use std::ffi::CString;
use std::ptr;

#[derive(Debug)]
pub struct Cipher {
    obj: botan_cipher_t,
    tag_length: usize,
    default_nonce_length: usize,
    min_keylen: usize,
    max_keylen: usize,
}

#[derive(PartialEq)]
pub enum CipherDirection {
    Encrypt,
    Decrypt
}

impl Drop for Cipher {
    fn drop(&mut self) {
        unsafe { botan_cipher_destroy(self.obj); }
    }
}

impl Cipher {
    pub fn new(name: &str, dir: CipherDirection) -> Result<Cipher> {
        let mut obj = ptr::null_mut();
        let flag = if dir == CipherDirection::Encrypt { 0u32 } else { 1u32 };
        call_botan! { botan_cipher_init(&mut obj, CString::new(name).unwrap().as_ptr(), flag) };

        let mut tag_length = 0;
        call_botan! { botan_cipher_get_tag_length(obj, &mut tag_length) };

        let mut default_nonce_length = 0;
        call_botan! { botan_cipher_get_default_nonce_length(obj, &mut default_nonce_length) };

        let mut min_keylen = 0;
        let mut max_keylen = 0;
        call_botan! { botan_cipher_query_keylen(obj, &mut min_keylen, &mut max_keylen) };

        Ok(Cipher {
            obj,
            tag_length,
            default_nonce_length,
            min_keylen,
            max_keylen
        })
    }

    pub fn valid_nonce_length(&self, l: usize) -> Result<bool> {
        let rc = unsafe { botan_cipher_valid_nonce_length(self.obj, l) };

        if rc == 1 {
            Ok(true)
        }
        else if rc == 0 {
            Ok(false)
        }
        else {
            Err(Error::from(rc))
        }
    }

    pub fn tag_length(&self) -> usize {
        self.tag_length
    }

    pub fn default_nonce_length(&self) -> usize {
        self.default_nonce_length
    }

    pub fn query_keylength(&self) -> (usize, usize) {
        (self.min_keylen, self.max_keylen)
    }

    pub fn set_key(&self, key: &[u8]) -> Result<()> {
        call_botan! { botan_cipher_set_key(self.obj, key.as_ptr(), key.len()) };
        Ok(())
    }

    pub fn set_associated_data(&self, ad: &[u8]) -> Result<()> {
        call_botan! { botan_cipher_set_associated_data(self.obj, ad.as_ptr(), ad.len()) };
        Ok(())
    }

    pub fn process(&self, nonce: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        call_botan! { botan_cipher_start(self.obj, nonce.as_ptr(), nonce.len()) };

        let flags = 1u32; // only supporting one-shot processing here

        // FIXME(2.8): need botan_cipher_output_len to size this correctly
        let mut output = vec![0; msg.len() + 64];
        let mut output_written = 0;
        let mut input_consumed = 0;

        call_botan! {
            botan_cipher_update(self.obj,
                                flags,
                                output.as_mut_ptr(),
                                output.len(),
                                &mut output_written,
                                msg.as_ptr(),
                                msg.len(),
                                &mut input_consumed)
        }

        assert!(input_consumed == msg.len());
        assert!(output_written <= output.len());

        output.resize(output_written, 0);

        Ok(output)
    }

    pub fn clear(&self) -> Result<()> {
        call_botan! { botan_cipher_clear(self.obj) };
        Ok(())
    }
}
