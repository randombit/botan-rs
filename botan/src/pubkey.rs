
use botan_sys::*;
use utils::*;

use rng::RandomNumberGenerator;

#[derive(Debug)]
/// A public key object
pub struct Pubkey {
    obj: botan_pubkey_t
}

#[derive(Debug)]
/// A private key object
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

    /// Create a new private key
    ///
    pub fn create(alg: &str, params: &str, rng: &RandomNumberGenerator) -> Result<Privkey> {

        let mut obj = ptr::null_mut();

        call_botan! { botan_privkey_create(&mut obj,
                                           make_cstr(alg)?.as_ptr(),
                                           make_cstr(params)?.as_ptr(),
                                           rng.handle()) }

        Ok(Privkey { obj })
    }

    /// Load DER bytes as an unencrypted PKCS#8 private key
    pub fn load_der(der: &[u8]) -> Result<Privkey> {
        let mut obj = ptr::null_mut();

        call_botan! { botan_privkey_load(&mut obj, ptr::null_mut(), der.as_ptr(), der.len(), ptr::null()) }

        Ok(Privkey { obj })
    }

    /// Load PEM string as an unencrypted PKCS#8 private key
    pub fn load_pem(pem: &str) -> Result<Privkey> {
        let mut obj = ptr::null_mut();

        let cpem = make_cstr(pem)?;
        call_botan! { botan_privkey_load(&mut obj, ptr::null_mut(), cpem.as_ptr() as *const u8, pem.len(), ptr::null()) }

        Ok(Privkey { obj })
    }

    /// Load DER bytes as an encrypted PKCS#8 private key
    pub fn load_encrypted_der(der: &[u8], passphrase: &str) -> Result<Privkey> {
        let mut obj = ptr::null_mut();

        let passphrase = make_cstr(passphrase)?;
        call_botan! { botan_privkey_load(&mut obj, ptr::null_mut(), der.as_ptr(), der.len(), passphrase.as_ptr()) }

        Ok(Privkey { obj })
    }

    /// Load PEM string as an encrypted PKCS#8 private key
    pub fn load_encrypted_pem(pem: &str, passphrase: &str) -> Result<Privkey> {
        let mut obj = ptr::null_mut();

        let passphrase = make_cstr(passphrase)?;
        let cpem = make_cstr(pem)?;
        call_botan! { botan_privkey_load(&mut obj, ptr::null_mut(), cpem.as_ptr() as *const u8, pem.len(), passphrase.as_ptr()) }

        Ok(Privkey { obj })
    }

    /// Check if the key seems to be valid
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

    /// Return the public key associated with this private key
    pub fn pubkey(&self) -> Result<Pubkey> {
        let mut obj = ptr::null_mut();
        call_botan! { botan_privkey_export_pubkey(&mut obj, self.obj) }
        Ok(Pubkey { obj })
    }

    /// Return the name of the algorithm
    pub fn algo_name(&self) -> Result<String> {
        let name_len = 32;
        call_botan_ffi_returning_string(name_len, &|out_buf, out_len| {
            unsafe { botan_privkey_algo_name(self.obj, out_buf as *mut c_char, out_len) }
        })
    }

    /// DER encode the key (unencrypted)
    pub fn der_encode(&self) -> Result<Vec<u8>> {
        let der_len = 4096; // fixme
        call_botan_ffi_returning_vec_u8(der_len, &|out_buf, out_len| {
            unsafe { botan_privkey_export(self.obj, out_buf, out_len, 0u32) }
        })
    }

    /// DER encode the key (encrypted)
    pub fn der_encode_encrypted(&self, passphrase: &str, rng: &RandomNumberGenerator) -> Result<Vec<u8>> {
        self.der_encode_encrypted_with_options(passphrase, "AES-256/CBC", "SHA-512", 150000, rng)
    }

    /// DER encode the key (encrypted), specifying cipher/hash options
    pub fn der_encode_encrypted_with_options(&self,
                                             passphrase: &str,
                                             cipher: &str,
                                             pbkdf: &str,
                                             pbkdf_iter: usize,
                                             rng: &RandomNumberGenerator) -> Result<Vec<u8>> {
        let der_len = 4096; // fixme
        let passphrase = make_cstr(passphrase)?;
        let cipher = make_cstr(cipher)?;
        let pbkdf = make_cstr(pbkdf)?;

        call_botan_ffi_returning_vec_u8(der_len, &|out_buf, out_len| {
            unsafe {
                botan_privkey_export_encrypted_pbkdf_iter(
                    self.obj, out_buf, out_len, rng.handle(),
                    passphrase.as_ptr(),
                    pbkdf_iter,
                    cipher.as_ptr(),
                    pbkdf.as_ptr(),
                    0u32)
            }
        })
    }

    /// PEM encode the key (encrypted)
    pub fn pem_encode_encrypted(&self, passphrase: &str, rng: &RandomNumberGenerator) -> Result<String> {
        self.pem_encode_encrypted_with_options(passphrase, "AES-256/CBC", "SHA-512", 150000, rng)
    }

    /// PEM encode the key (encrypted), specifying cipher/hash options
    pub fn pem_encode_encrypted_with_options(&self,
                                             passphrase: &str,
                                             cipher: &str,
                                             pbkdf: &str,
                                             pbkdf_iter: usize,
                                             rng: &RandomNumberGenerator) -> Result<String> {
        let pem_len = 4096; // fixme

        let passphrase = make_cstr(passphrase)?;
        let cipher = make_cstr(cipher)?;
        let pbkdf = make_cstr(pbkdf)?;

        call_botan_ffi_returning_string(pem_len, &|out_buf, out_len| {
            unsafe {
                botan_privkey_export_encrypted_pbkdf_iter(
                    self.obj, out_buf, out_len, rng.handle(),
                    passphrase.as_ptr(),
                    pbkdf_iter,
                    cipher.as_ptr(),
                    pbkdf.as_ptr(),
                    1u32)
            }
        })
    }

    /// PEM encode the private key (unencrypted)
    pub fn pem_encode(&self) -> Result<String> {
        let pem_len = 4096; // fixme
        call_botan_ffi_returning_string(pem_len, &|out_buf, out_len| {
            unsafe { botan_privkey_export(self.obj, out_buf, out_len, 1u32) }
        })
    }

    /// Return the key agrement key, only valid for DH/ECDH
    pub fn key_agreement_key(&self) -> Result<Vec<u8>> {
        let ka_key_len = 512; // fixme
        call_botan_ffi_returning_vec_u8(ka_key_len, &|out_buf, out_len| {
            unsafe { botan_pk_op_key_agreement_export_public(self.obj, out_buf, out_len) }
        })
    }
}

impl Pubkey {

    pub(crate) fn from_handle(obj: botan_pubkey_t) -> Pubkey { Pubkey { obj } }

    pub(crate) fn handle(&self) -> botan_pubkey_t { self.obj }

    /// Load a DER encoded public key
    pub fn load_der(der: &[u8]) -> Result<Pubkey> {
        let mut obj = ptr::null_mut();
        call_botan! { botan_pubkey_load(&mut obj, der.as_ptr(), der.len()) }
        Ok(Pubkey { obj })
    }

    /// Return estimated bit strength of this key
    pub fn estimated_strength(&self) -> Result<usize> {
        let mut strength = 0;
        call_botan! { botan_pubkey_estimated_strength(self.obj, &mut strength) };
        Ok(strength)
    }

    /// Check key for problems
    pub fn check_key(&self, rng: &RandomNumberGenerator) -> Result<bool> {

        let flags = 1u32;
        let rc = unsafe { botan_pubkey_check_key(self.obj, rng.handle(), flags) };

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

    /// Return hash of the public key data
    pub fn fingerprint(&self, hash: &str) -> Result<String> {
        let hash = make_cstr(hash)?;
        let fprint_len = 64; // hashes > 512 bits are rare
        call_botan_ffi_returning_string(fprint_len, &|out_buf, out_len| {
            unsafe { botan_pubkey_fingerprint(self.obj, hash.as_ptr(), out_buf, out_len) }
        })
    }

    // TODO load_pem
    // TODO get_field (needs mp)

    /// DER encode this public key
    pub fn der_encode(&self) -> Result<Vec<u8>> {
        let der_len = 4096; // fixme
        call_botan_ffi_returning_vec_u8(der_len, &|out_buf, out_len| {
            unsafe { botan_pubkey_export(self.obj, out_buf, out_len, 0u32) }
        })
    }

    /// PEM encode this public key
    pub fn pem_encode(&self) -> Result<String> {
        let pem_len = 4096; // fixme
        call_botan_ffi_returning_string(pem_len, &|out_buf, out_len| {
            unsafe { botan_pubkey_export(self.obj, out_buf, out_len, 1u32) }
        })
    }

    /// Return the name of the algorithm
    pub fn algo_name(&self) -> Result<String> {
        let name_len = 32;
        call_botan_ffi_returning_string(name_len, &|out_buf, out_len| {
            unsafe { botan_pubkey_algo_name(self.obj, out_buf as *mut c_char, out_len) }
        })
    }

}

/// Return the identifier used for PKCS1 v1.5 signatures for the specified hash
pub fn pkcs_hash_id(hash_algo: &str) -> Result<Vec<u8>> {
    let hash_algo = make_cstr(hash_algo)?;
    let id_len = 32; // largest currently is 20 bytes
    call_botan_ffi_returning_vec_u8(id_len, &|out_buf, out_len| {
        unsafe { botan_pkcs_hash_id(hash_algo.as_ptr(), out_buf, out_len) }
    })

}
