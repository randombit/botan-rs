use crate::utils::*;
use botan_sys::*;

#[derive(Debug)]
/// Message authentication code
pub struct MsgAuthCode {
    obj: botan_mac_t,
    output_length: usize,
    min_keylen: usize,
    max_keylen: usize,
    mod_keylen: usize,
}

unsafe impl Sync for MsgAuthCode {}
unsafe impl Send for MsgAuthCode {}

botan_impl_drop!(MsgAuthCode, botan_mac_destroy);

impl MsgAuthCode {
    /// Create a new message authentication code
    ///
    /// # Examples
    /// ```
    /// let hmac = botan::MsgAuthCode::new("HMAC(SHA-256)").unwrap();
    /// ```
    /// ```
    /// let poly1305 = botan::MsgAuthCode::new("Poly1305").unwrap();
    /// ```
    pub fn new(name: &str) -> Result<MsgAuthCode> {
        let obj = botan_init!(botan_mac_init, make_cstr(name)?.as_ptr(), 0u32)?;
        let output_length = botan_usize!(botan_mac_output_length, obj)?;

        let (min_keylen, max_keylen, mod_keylen) = botan_usize3!(botan_mac_get_keyspec, obj)?;

        Ok(MsgAuthCode {
            obj,
            output_length,
            min_keylen,
            max_keylen,
            mod_keylen,
        })
    }

    /// Return the name of this algorithm which may or may not exactly
    /// match what was provided to new()
    ///
    /// # Examples
    ///
    /// ```
    /// let mac = botan::MsgAuthCode::new("HMAC(SHA-384)").unwrap();
    /// assert_eq!(mac.algo_name().unwrap(), "HMAC(SHA-384)");
    /// ```
    pub fn algo_name(&self) -> Result<String> {
        call_botan_ffi_returning_string(32, &|out_buf, out_len| unsafe {
            botan_mac_name(self.obj, out_buf as *mut c_char, out_len)
        })
    }

    /// Return information about the key lengths supported by this object
    pub fn key_spec(&self) -> Result<KeySpec> {
        KeySpec::new(self.min_keylen, self.max_keylen, self.mod_keylen)
    }

    /// Return the output length of the authentication code, in bytes
    /// # Examples
    /// ```
    /// let hmac = botan::MsgAuthCode::new("HMAC(SHA-256)").unwrap();
    /// assert_eq!(hmac.output_length().unwrap(), 32);
    /// ```
    pub fn output_length(&self) -> Result<usize> {
        Ok(self.output_length)
    }

    /// Set the key for the authentication code object
    /// # Examples
    /// ```
    /// let mut hmac = botan::MsgAuthCode::new("HMAC(SHA-256)").unwrap();
    /// hmac.set_key(&vec![0; 16]).unwrap();
    /// ```
    pub fn set_key(&mut self, key: &[u8]) -> Result<()> {
        botan_call!(botan_mac_set_key, self.obj, key.as_ptr(), key.len())
    }

    #[cfg(botan_ffi_20230403)]
    /// Set the nonce for the authentication code object
    ///
    /// Only a few MACs support this; currently only GMAC
    ///
    /// # Examples
    /// ```
    /// let mut gmac = botan::MsgAuthCode::new("GMAC(AES-128)").unwrap();
    /// gmac.set_key(&vec![0; 16]).unwrap();
    /// gmac.set_nonce(&vec![0; 12]);
    /// ```
    pub fn set_nonce(&mut self, nonce: &[u8]) -> Result<()> {
        botan_call!(botan_mac_set_nonce, self.obj, nonce.as_ptr(), nonce.len())
    }

    /// Add data to a MAC computation, may be called many times
    ///
    /// # Examples
    /// ```
    /// let mut hmac = botan::MsgAuthCode::new("HMAC(SHA-256)").unwrap();
    /// assert!(hmac.update(&[23]).is_err()); // key not set yet
    /// hmac.set_key(&vec![0; 16]).unwrap();
    /// hmac.update(&[1,2,3]).unwrap();
    /// hmac.update(&[4,5,6]).unwrap();
    /// ```
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        botan_call!(botan_mac_update, self.obj, data.as_ptr(), data.len())
    }

    /// Complete a MAC computation, after which the object is reset to
    /// MAC a new message with the same key.
    ///
    /// # Examples
    /// ```
    /// let mut hmac = botan::MsgAuthCode::new("HMAC(SHA-256)").unwrap();
    /// assert!(hmac.update(&[23]).is_err()); // key not set yet
    /// hmac.set_key(&vec![0; 16]).unwrap();
    /// hmac.update(&[1,2,3]).unwrap();
    /// hmac.update(&[4,5,6]).unwrap();
    /// let mac = hmac.finish().unwrap();
    /// ```
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        let mut output = vec![0; self.output_length];
        botan_call!(botan_mac_final, self.obj, output.as_mut_ptr())?;
        Ok(output)
    }

    /// Clear the MAC key
    ///
    /// # Examples
    /// ```
    /// let mut hmac = botan::MsgAuthCode::new("HMAC(SHA-256)").unwrap();
    /// hmac.set_key(&vec![0; 16]).unwrap();
    /// hmac.update(&[1,2,3]).unwrap();
    /// hmac.clear().unwrap();
    /// assert!(hmac.update(&[23]).is_err()); // key not set anymore
    /// ```
    pub fn clear(&mut self) -> Result<()> {
        botan_call!(botan_mac_clear, self.obj)
    }
}
