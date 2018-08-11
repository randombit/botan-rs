
use botan_sys::*;
use utils::*;

#[derive(Debug)]
/// A symmetric cipher
pub struct Cipher {
    obj: botan_cipher_t,
    tag_length: usize,
    default_nonce_length: usize,
    min_keylen: usize,
    max_keylen: usize,
    mod_keylen: usize
}

#[derive(PartialEq)]
/// Which direction the cipher processes in
pub enum CipherDirection {
    /// Encrypt
    Encrypt,
    /// Decrypt
    Decrypt
}

impl Drop for Cipher {
    fn drop(&mut self) {
        unsafe { botan_cipher_destroy(self.obj); }
    }
}

impl Cipher {
    /// Create a new cipher object in the specified direction
    ///
    /// # Examples
    /// ```
    /// let aes_gcm = botan::Cipher::new("AES-128/GCM", botan::CipherDirection::Encrypt).unwrap();
    /// ```
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
        let mut mod_keylen = 0;
        call_botan! { botan_cipher_get_keyspec(obj, &mut min_keylen, &mut max_keylen, &mut mod_keylen) };

        Ok(Cipher {
            obj,
            tag_length,
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
        call_botan_ffi_returning_string(32, &|out_buf, out_len| {
            unsafe { botan_cipher_name(self.obj, out_buf as *mut c_char, out_len) }
        })
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

    /// For an AEAD, return the tag length of the cipher
    ///
    /// # Examples
    /// ```
    /// let aes_cbc = botan::Cipher::new("AES-128/CBC", botan::CipherDirection::Encrypt).unwrap();
    /// assert_eq!(aes_cbc.tag_length(), 0);
    /// let aes_gcm = botan::Cipher::new("AES-128/GCM", botan::CipherDirection::Encrypt).unwrap();
    /// assert_eq!(aes_gcm.tag_length(), 16);
    /// ```
    pub fn tag_length(&self) -> usize {
        self.tag_length
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
    pub fn default_nonce_length(&self) -> usize {
        self.default_nonce_length
    }

    /// Return information about the key lengths supported by this object
    pub fn key_spec(&self) -> KeySpec {
        KeySpec::new(self.min_keylen, self.max_keylen, self.mod_keylen)
    }

    /// Set the key for the cipher
    ///
    /// # Examples
    /// ```
    /// let aes_gcm = botan::Cipher::new("AES-128/GCM", botan::CipherDirection::Encrypt).unwrap();
    /// aes_gcm.set_key(&vec![0; 16]).unwrap();
    /// ```
    pub fn set_key(&self, key: &[u8]) -> Result<()> {
        call_botan! { botan_cipher_set_key(self.obj, key.as_ptr(), key.len()) };
        Ok(())
    }

    /// Set the associated data for the cipher. This only works for AEAD modes.
    /// The key must already be set to set the AD.
    ///
    /// # Examples
    /// ```
    /// let aes_gcm = botan::Cipher::new("AES-128/GCM", botan::CipherDirection::Encrypt).unwrap();
    /// aes_gcm.set_key(&vec![0; 16]).unwrap();
    /// aes_gcm.set_associated_data(&[1,2,3]).unwrap();
    /// ```
    pub fn set_associated_data(&self, ad: &[u8]) -> Result<()> {
        call_botan! { botan_cipher_set_associated_data(self.obj, ad.as_ptr(), ad.len()) };
        Ok(())
    }

    /// Encrypt or decrypt a message with the provided nonce. The key must
    /// already have been set.
    ///
    /// # Examples
    /// ```
    /// let aes_gcm = botan::Cipher::new("AES-128/GCM", botan::CipherDirection::Encrypt).unwrap();
    /// aes_gcm.set_key(&vec![0; 16]).unwrap();
    /// let nonce = vec![0; aes_gcm.default_nonce_length()];
    /// let msg = vec![0; 48];
    /// let ctext = aes_gcm.process(&nonce, &msg);
    /// ```
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

    /// Clear all state associated with the key
    pub fn clear(&self) -> Result<()> {
        call_botan! { botan_cipher_clear(self.obj) };
        Ok(())
    }
}
