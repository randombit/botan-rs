
use botan_sys::*;
use utils::*;

use pubkey::{Privkey, Pubkey};
use rng::RandomNumberGenerator;

#[derive(Debug)]
pub struct Signer {
    obj: botan_pk_op_sign_t,
    sig_len: usize,
}

impl Drop for Signer {
    fn drop(&mut self) {
        unsafe { botan_pk_op_sign_destroy(self.obj) };
    }
}

impl Signer {

    pub fn new(key: &Privkey, padding: &str) -> Result<Signer> {
        let padding = CString::new(padding).unwrap();
        let mut obj = ptr::null_mut();
        call_botan! { botan_pk_op_sign_create(&mut obj, key.handle(), padding.as_ptr(), 0u32) };
        let mut sig_len = 0;
        call_botan! { botan_pk_op_sign_output_length(obj, &mut sig_len) };
        Ok(Signer { obj, sig_len })
    }

    pub fn update(&self, data: &[u8]) -> Result<()> {
        call_botan! { botan_pk_op_sign_update(self.obj, data.as_ptr(), data.len()) };
        Ok(())
    }

    pub fn finish(&self, rng: &RandomNumberGenerator) -> Result<Vec<u8>> {
        call_botan_ffi_returning_vec_u8(self.sig_len, &|out_buf, out_len| {
            unsafe { botan_pk_op_sign_finish(self.obj, rng.handle(), out_buf, out_len) }
        })
    }
}

#[derive(Debug)]
pub struct Decryptor {
    obj: botan_pk_op_decrypt_t
}

impl Drop for Decryptor {
    fn drop(&mut self) {
        unsafe { botan_pk_op_decrypt_destroy(self.obj) };
    }
}

impl Decryptor {

    pub fn new(key: &Privkey, padding: &str) -> Result<Decryptor> {
        let padding = CString::new(padding).unwrap();
        let mut obj = ptr::null_mut();
        call_botan! { botan_pk_op_decrypt_create(&mut obj, key.handle(), padding.as_ptr(), 0u32) }
        Ok(Decryptor { obj })
    }

    pub fn decrypt(&self, ctext: &[u8]) -> Result<Vec<u8>> {
        let mut ptext_len = 0;

        call_botan! { botan_pk_op_decrypt_output_length(self.obj, ctext.len(), &mut ptext_len) };

        call_botan_ffi_returning_vec_u8(ptext_len, &|out_buf, out_len| {
            unsafe { botan_pk_op_decrypt(self.obj, out_buf, out_len, ctext.as_ptr(), ctext.len()) }
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
        let padding = CString::new(padding).unwrap();
        let mut obj = ptr::null_mut();
        call_botan! { botan_pk_op_verify_create(&mut obj, key.handle(), padding.as_ptr(), 0u32) }
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

#[derive(Debug)]
pub struct Encryptor {
    obj: botan_pk_op_encrypt_t
}

impl Drop for Encryptor {
    fn drop(&mut self) {
        unsafe { botan_pk_op_encrypt_destroy(self.obj) };
    }
}

impl Encryptor {

    pub fn new(key: &Pubkey, padding: &str) -> Result<Encryptor> {
        let padding = CString::new(padding).unwrap();
        let mut obj = ptr::null_mut();
        call_botan! { botan_pk_op_encrypt_create(&mut obj, key.handle(), padding.as_ptr(), 0u32) }
        Ok(Encryptor { obj })
    }

    pub fn encrypt(&self, ptext: &[u8], rng: &RandomNumberGenerator) -> Result<Vec<u8>> {
        let mut ctext_len = 0;

        call_botan! { botan_pk_op_encrypt_output_length(self.obj, ptext.len(), &mut ctext_len) };

        call_botan_ffi_returning_vec_u8(ctext_len, &|out_buf, out_len| {
            unsafe { botan_pk_op_encrypt(self.obj, rng.handle(), out_buf, out_len, ptext.as_ptr(), ptext.len()) }
        })
    }
}

#[derive(Debug)]
pub struct KeyAgreement {
    obj: botan_pk_op_ka_t
}

impl Drop for KeyAgreement {
    fn drop(&mut self) {
        unsafe { botan_pk_op_key_agreement_destroy(self.obj) };
    }
}

impl KeyAgreement {

    pub fn new(key: &Privkey, kdf: &str) -> Result<KeyAgreement> {
        let kdf = CString::new(kdf).unwrap();
        let mut obj = ptr::null_mut();
        call_botan! { botan_pk_op_key_agreement_create(&mut obj, key.handle(), kdf.as_ptr(), 0u32) }
        Ok(KeyAgreement { obj })
    }

    pub fn agree(&self, counterparty_key: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
        let ka_len = 128; // FIXME!!
        call_botan_ffi_returning_vec_u8(ka_len, &|out_buf, out_len| {
            unsafe { botan_pk_op_key_agreement(self.obj, out_buf, out_len,
                                               counterparty_key.as_ptr(), counterparty_key.len(),
                                               salt.as_ptr(), salt.len()) }
        })
    }
}

