
use botan_sys::*;
use utils::*;

#[derive(Debug)]
/// Message authentication code
pub struct MsgAuthCode {
    obj: botan_mac_t,
    output_length: usize,
    min_keylen: usize,
    max_keylen: usize,
    mod_keylen: usize,
}

impl Drop for MsgAuthCode {
    fn drop(&mut self) {
        unsafe { botan_mac_destroy(self.obj); }
    }
}

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
        let mut obj = ptr::null_mut();
        call_botan! { botan_mac_init(&mut obj, make_cstr(name)?.as_ptr(), 0u32) };

        let mut output_length = 0;
        call_botan! { botan_mac_output_length(obj, &mut output_length) };

        let mut min_keylen = 0;
        let mut max_keylen = 0;
        let mut mod_keylen = 0;
        call_botan! { botan_mac_get_keyspec(obj, &mut min_keylen, &mut max_keylen, &mut mod_keylen) };

        Ok(MsgAuthCode { obj, output_length, min_keylen, max_keylen, mod_keylen })
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
        call_botan_ffi_returning_string(32, &|out_buf, out_len| {
            unsafe { botan_mac_name(self.obj, out_buf as *mut c_char, out_len) }
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
    /// let hmac = botan::MsgAuthCode::new("HMAC(SHA-256)").unwrap();
    /// hmac.set_key(&vec![0; 16]).unwrap();
    /// ```
    pub fn set_key(&self, key: &[u8]) -> Result<()> {
        call_botan! { botan_mac_set_key(self.obj, key.as_ptr(), key.len()) };
        Ok(())
    }

    /// Add data to a MAC computation, may be called many times
    ///
    /// # Examples
    /// ```
    /// let hmac = botan::MsgAuthCode::new("HMAC(SHA-256)").unwrap();
    /// assert!(hmac.update(&[23]).is_err()); // key not set yet
    /// hmac.set_key(&vec![0; 16]).unwrap();
    /// hmac.update(&[1,2,3]).unwrap();
    /// hmac.update(&[4,5,6]).unwrap();
    /// ```
    pub fn update(&self, data: &[u8]) -> Result<()> {
        call_botan! { botan_mac_update(self.obj, data.as_ptr(), data.len()) };
        Ok(())
    }

    /// Complete a MAC computation, after which the object is reset to
    /// MAC a new message with the same key.
    ///
    /// # Examples
    /// ```
    /// let hmac = botan::MsgAuthCode::new("HMAC(SHA-256)").unwrap();
    /// assert!(hmac.update(&[23]).is_err()); // key not set yet
    /// hmac.set_key(&vec![0; 16]).unwrap();
    /// hmac.update(&[1,2,3]).unwrap();
    /// hmac.update(&[4,5,6]).unwrap();
    /// let mac = hmac.finish().unwrap();
    /// ```
    pub fn finish(&self) -> Result<Vec<u8>> {
        let mut output = vec![0; self.output_length];
        call_botan! { botan_mac_final(self.obj, output.as_mut_ptr()) };
        Ok(output)
    }

    /// Clear the MAC key
    ///
    /// # Examples
    /// ```
    /// let hmac = botan::MsgAuthCode::new("HMAC(SHA-256)").unwrap();
    /// hmac.set_key(&vec![0; 16]).unwrap();
    /// hmac.update(&[1,2,3]).unwrap();
    /// hmac.clear().unwrap();
    /// assert!(hmac.update(&[23]).is_err()); // key not set anymore
    /// ```
    pub fn clear(&self) -> Result<()> {
        call_botan! { botan_mac_clear(self.obj) };
        Ok(())
    }
}
