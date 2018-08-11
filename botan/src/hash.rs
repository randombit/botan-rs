use botan_sys::*;
use utils::*;

#[derive(Debug)]
/// A hash function object
pub struct HashFunction {
    obj: botan_hash_t,
    output_length: usize
}

impl Clone for HashFunction {
    fn clone(&self) -> HashFunction {
        self.duplicate().expect("copying hash object state failed")
    }
}

impl Drop for HashFunction {
    fn drop(&mut self) {
        unsafe { botan_hash_destroy(self.obj); }
    }
}

impl HashFunction {
    /// Create a new hash function
    ///
    /// # Errors
    /// Will fail if the named hash is not known
    /// # Examples
    /// ```
    /// assert!(botan::HashFunction::new("SHA-256").is_ok());
    /// assert!(botan::HashFunction::new("Hash9000").is_err());
    /// ```
    pub fn new(name: &str) -> Result<HashFunction> {
        let mut obj = ptr::null_mut();
        call_botan! { botan_hash_init(&mut obj, CString::new(name).unwrap().as_ptr(), 0u32) };

        let mut output_length = 0;
        call_botan! { botan_hash_output_length(obj, &mut output_length) };

        Ok(HashFunction { obj, output_length })
    }

    // FIXME(2.8) need name getters

    /// Return the output length of the hash function, in bytes
    ///
    /// # Examples
    /// ```
    /// let hash = botan::HashFunction::new("SHA-256").unwrap();
    /// assert_eq!(hash.output_length(), 32);
    /// ```
    pub fn output_length(&self) -> usize { self.output_length }

    /// Add data to a hash computation, may be called many times
    ///
    /// # Examples
    /// ```
    /// let hash = botan::HashFunction::new("SHA-256").unwrap();
    /// hash.update(&[1,2,3]).unwrap();
    /// hash.update(&[4,5,6]).unwrap();
    /// ```
    pub fn update(&self, data: &[u8]) -> Result<()> {
        call_botan! { botan_hash_update(self.obj, data.as_ptr(), data.len()) };
        Ok(())
    }

    /// Finalize the computation, returning the hash of the message
    ///
    /// # Examples
    /// ```
    /// let hash = botan::HashFunction::new("SHA-256").unwrap();
    /// hash.update(&[1,2,3]).unwrap();
    /// hash.update(&[4,5,6]).unwrap();
    /// let digest = hash.finish().unwrap();
    /// ```
    pub fn finish(&self) -> Result<Vec<u8>> {
        let mut output = vec![0; self.output_length()];
        call_botan! { botan_hash_final(self.obj, output.as_mut_ptr()) };
        Ok(output)
    }

    /// Clear the internal state of the hash function. It acts as if it
    /// was newly created, and is ready to compute a new digest.
    /// Basically the same as calling final, but without returning a
    /// result.
    pub fn clear(&self) -> Result<()> {
        call_botan! { botan_hash_clear(self.obj) };
        Ok(())
    }

    /// Copy hash object state to a new object, allowing prefixes of
    /// messages to be hashed. This function is also called by clone.
    ///
    /// # Errors
    /// Should not fail but might due to unexpected error
    /// # Examples
    /// ```
    /// let hash = botan::HashFunction::new("SHA-256").unwrap();
    /// hash.update(&[1,2,3]);
    /// let hash2 = hash.duplicate().unwrap();
    /// hash2.update(&[4,5,6]);
    /// let result1 = hash.finish().unwrap(); // hash of 1,2,3
    /// let result2 = hash2.finish().unwrap(); // hash of 1,2,3,4,5,6
    /// ```

    pub fn duplicate(&self) -> Result<HashFunction> {
        let mut obj = ptr::null_mut();
        call_botan! { botan_hash_copy_state(&mut obj, self.obj) };
        Ok(HashFunction { obj: obj, output_length: self.output_length })
    }
}
