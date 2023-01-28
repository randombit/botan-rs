use crate::utils::*;
use botan_sys::*;

#[derive(Debug)]
/// A symmetric cipher
pub struct Cipher {
    obj: botan_cipher_t,
    direction: CipherDirection,
    tag_length: usize,
    update_granularity: usize,
    default_nonce_length: usize,
    min_keylen: usize,
    max_keylen: usize,
    mod_keylen: usize,
}

#[derive(Eq, PartialEq, Debug, Copy, Clone)]
/// Which direction the cipher processes in
pub enum CipherDirection {
    /// Encrypt
    Encrypt,
    /// Decrypt
    Decrypt,
}

botan_impl_drop!(Cipher, botan_cipher_destroy);

impl Cipher {
    /// Create a new cipher object in the specified direction
    ///
    /// # Examples
    /// ```
    /// let aes_gcm = botan::Cipher::new("AES-128/GCM", botan::CipherDirection::Encrypt).unwrap();
    /// ```
    pub fn new(name: &str, direction: CipherDirection) -> Result<Cipher> {
        let mut flag = 0u32;

        if direction == CipherDirection::Decrypt {
            flag |= 1u32;
        };

        let obj = botan_init!(botan_cipher_init, make_cstr(name)?.as_ptr(), flag)?;

        let tag_length = botan_usize!(botan_cipher_get_tag_length, obj)?;
        let update_granularity = botan_usize!(botan_cipher_get_update_granularity, obj)?;
        let default_nonce_length = botan_usize!(botan_cipher_get_default_nonce_length, obj)?;

        let (min_keylen, max_keylen, mod_keylen) = botan_usize3!(botan_cipher_get_keyspec, obj)?;

        Ok(Cipher {
            obj,
            direction,
            tag_length,
            update_granularity,
            default_nonce_length,
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
    /// let cipher = botan::Cipher::new("AES-128/GCM", botan::CipherDirection::Encrypt).unwrap();
    /// assert_eq!(cipher.algo_name().unwrap(), "AES-128/GCM(16)");
    /// ```
    pub fn algo_name(&self) -> Result<String> {
        call_botan_ffi_returning_string(32, &|out_buf, out_len| unsafe {
            botan_cipher_name(self.obj, out_buf as *mut c_char, out_len)
        })
    }

    /// Return the direction this cipher object is operating in
    ///
    /// # Examples
    ///
    /// ```
    /// let cipher = botan::Cipher::new("AES-128/GCM", botan::CipherDirection::Encrypt).unwrap();
    /// assert_eq!(cipher.direction().unwrap(), botan::CipherDirection::Encrypt);
    /// ```
    pub fn direction(&self) -> Result<CipherDirection> {
        Ok(self.direction)
    }

    /// Query if a particular nonce size is valid for this cipher
    ///
    /// # Examples
    /// ```
    /// let aes_cbc = botan::Cipher::new("AES-128/CBC", botan::CipherDirection::Encrypt).unwrap();
    /// assert_eq!(aes_cbc.valid_nonce_length(16), Ok(true));
    /// assert_eq!(aes_cbc.valid_nonce_length(1), Ok(false));
    /// ```
    pub fn valid_nonce_length(&self, l: usize) -> Result<bool> {
        botan_bool_in_rc!(botan_cipher_valid_nonce_length, self.obj, l)
    }

    /// For an AEAD, return the tag length of the cipher
    ///
    /// # Examples
    /// ```
    /// let aes_cbc = botan::Cipher::new("AES-128/CBC", botan::CipherDirection::Encrypt).unwrap();
    /// assert_eq!(aes_cbc.tag_length(), 0);
    /// let aes_gcm = botan::Cipher::new("AES-128/GCM", botan::CipherDirection::Encrypt).unwrap();
    /// assert_eq!(aes_gcm.tag_length(), 16);
    /// ```
    #[must_use]
    pub fn tag_length(&self) -> usize {
        self.tag_length
    }

    /// update_granularity
    pub fn update_granularity(&self) -> usize {
        self.update_granularity
    }

    /// Return the default nonce length for the cipher. Some ciphers only
    /// support a single nonce size. Others support variable sizes, but some
    /// particular size (typically 96 bits) is handled particularly efficiently.
    ///
    /// # Examples
    /// ```
    /// let aes_gcm = botan::Cipher::new("AES-128/GCM", botan::CipherDirection::Encrypt).unwrap();
    /// assert_eq!(aes_gcm.default_nonce_length(), 12);
    /// ```
    #[must_use]
    pub fn default_nonce_length(&self) -> usize {
        self.default_nonce_length
    }

    /// Return information about the key lengths supported by this object
    pub fn key_spec(&self) -> Result<KeySpec> {
        KeySpec::new(self.min_keylen, self.max_keylen, self.mod_keylen)
    }

    /// Set the key for the cipher
    ///
    /// # Examples
    /// ```
    /// let mut aes_gcm = botan::Cipher::new("AES-128/GCM", botan::CipherDirection::Encrypt).unwrap();
    /// aes_gcm.set_key(&vec![0; 16]).unwrap();
    /// ```
    pub fn set_key(&mut self, key: &[u8]) -> Result<()> {
        botan_call!(botan_cipher_set_key, self.obj, key.as_ptr(), key.len())?;
        Ok(())
    }

    /// Set the associated data for the cipher. This only works for AEAD modes.
    /// The key must already be set to set the AD.
    ///
    /// # Examples
    /// ```
    /// let mut aes_gcm = botan::Cipher::new("AES-128/GCM", botan::CipherDirection::Encrypt).unwrap();
    /// aes_gcm.set_key(&vec![0; 16]).unwrap();
    /// aes_gcm.set_associated_data(&[1,2,3]).unwrap();
    /// ```
    pub fn set_associated_data(&mut self, ad: &[u8]) -> Result<()> {
        botan_call!(
            botan_cipher_set_associated_data,
            self.obj,
            ad.as_ptr(),
            ad.len()
        )?;
        Ok(())
    }

    /// Encrypt or decrypt a message with the provided nonce. The key must
    /// already have been set.
    ///
    /// # Examples
    /// ```
    /// let mut aes_gcm = botan::Cipher::new("AES-128/GCM", botan::CipherDirection::Encrypt).unwrap();
    /// aes_gcm.set_key(&vec![0; 16]).unwrap();
    /// let nonce = vec![0; aes_gcm.default_nonce_length()];
    /// let msg = vec![0; 48];
    /// let ctext = aes_gcm.process(&nonce, &msg);
    /// ```
    pub fn process(&mut self, nonce: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        botan_call!(botan_cipher_start, self.obj, nonce.as_ptr(), nonce.len())?;

        let flags = 1u32; // only supporting one-shot processing here

        // FIXME(2.8): need botan_cipher_output_len to size this correctly
        let mut output = vec![0; msg.len() + 64];
        let mut output_written = 0;
        let mut input_consumed = 0;

        botan_call!(
            botan_cipher_update,
            self.obj,
            flags,
            output.as_mut_ptr(),
            output.len(),
            &mut output_written,
            msg.as_ptr(),
            msg.len(),
            &mut input_consumed
        )?;

        assert!(input_consumed == msg.len());
        assert!(output_written <= output.len());

        output.resize(output_written, 0);

        Ok(output)
    }

    /// start processing a message
    pub fn start(&mut self, nonce: &[u8]) -> Result<()> {
        botan_call!(botan_cipher_start, self.obj, nonce.as_ptr(), nonce.len())
    }

    /// Encrypt or decrypt a message with the provided nonce. The key must
    /// incremental update
    fn _update(&mut self, msg: &[u8], end: bool) -> Result<Vec<u8>> {
        let flags = u32::from(end);
        let mut output = vec![0; msg.len() + if end { self.tag_length() } else { 0 }];
        let mut output_written = 0;
        let mut input_consumed = 0;

        botan_call!(
            botan_cipher_update,
            self.obj,
            flags,
            output.as_mut_ptr(),
            output.len(),
            &mut output_written,
            msg.as_ptr(),
            msg.len(),
            &mut input_consumed
        )?;

        assert!(input_consumed == msg.len());
        assert!(output_written <= output.len());

        output.resize(output_written, 0);

        Ok(output)
    }

    /// incremental update
    pub fn update(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        self._update(msg, false)
    }

    /// finish function
    pub fn finish(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        self._update(msg, true)
    }

    /// Clear all state associated with the key
    pub fn clear(&mut self) -> Result<()> {
        botan_call!(botan_cipher_clear, self.obj)
    }
}
