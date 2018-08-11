
use botan_sys::*;
use utils::*;

#[derive(Debug)]
/// Message authentication code
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
        call_botan! { botan_mac_init(&mut obj, CString::new(name).unwrap().as_ptr(), 0u32) };

        let mut output_length = 0;
        call_botan! { botan_mac_output_length(obj, &mut output_length) };

        Ok(MsgAuthCode { obj, output_length })
    }

    // FIXME(2.8) need name and key length info getters

    /// Return the output length of the authentication code, in bytes
    /// # Examples
    /// ```
    /// let hmac = botan::MsgAuthCode::new("HMAC(SHA-256)").unwrap();
    /// assert_eq!(hmac.output_length(), 32);
    /// ```
    pub fn output_length(&self) -> usize { self.output_length }

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
        let mut output = vec![0; self.output_length()];
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
