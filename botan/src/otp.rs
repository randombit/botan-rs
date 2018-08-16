
use botan_sys::*;
use utils::*;

#[derive(Debug)]
/// Generate or check HOTP tokens
pub struct HOTP {
    obj: botan_hotp_t,
}

#[derive(Debug)]
/// Generate or check TOTP tokens
pub struct TOTP {
    obj: botan_totp_t,
}

impl Drop for HOTP {
    fn drop(&mut self) {
        unsafe { botan_hotp_destroy(self.obj); }
    }
}

impl Drop for TOTP {
    fn drop(&mut self) {
        unsafe { botan_totp_destroy(self.obj); }
    }
}

impl HOTP {

    /// Instantiate a new HOTP instance with the given parameters
    ///
    /// # Examples
    ///
    /// ```
    /// let hotp = botan::HOTP::new(&[1,2,3,4], "SHA-1", 6);
    /// ```
    pub fn new(key: &[u8], hash_algo: &str, digits: usize) -> Result<HOTP> {
        let mut obj = ptr::null_mut();

        let hash_algo = make_cstr(hash_algo)?;

        call_botan! {
            botan_hotp_init(&mut obj, key.as_ptr(), key.len(), hash_algo.as_ptr(), digits)
        }

        Ok(HOTP { obj })
    }

    /// Generate an HOTP code
    pub fn generate(&self, counter: u64) -> Result<u32> {
        let mut code = 0;
        call_botan! { botan_hotp_generate(self.obj, &mut code, counter) }
        Ok(code)
    }

    /// Check an HOTP code
    pub fn check(&self, code: u32, counter: u64) -> Result<bool> {
        let cmp_code = self.generate(counter)?;
        println!("{} {}", code, cmp_code);
        Ok(cmp_code == code)
    }

    /// Check an HOTP code, allowing counter resync
    pub fn check_with_resync(&self,
                             code: u32,
                             counter: u64,
                             resync_range: usize) -> Result<(bool, u64)> {

        let mut new_ctr = 0;

        let rc = unsafe {
            botan_hotp_check(self.obj, &mut new_ctr, code, counter, resync_range)
        };

        if rc == 0 {
            Ok((true, new_ctr))
        }
        else if rc == 1 {
            Ok((false, counter))
        }
        else {
            Err(Error::from(rc))
        }
    }


}

impl TOTP {

    /// Instantiate a new TOTP instance with the given parameters
    ///
    /// # Examples
    ///
    /// ```
    /// let totp = botan::TOTP::new(&[1,2,3,4], "SHA-1", 6, 30);
    /// ```
    pub fn new(key: &[u8], hash_algo: &str, digits: usize, time_step: usize) -> Result<TOTP> {
        let mut obj = ptr::null_mut();

        let hash_algo = make_cstr(hash_algo)?;

        call_botan! {
            botan_totp_init(&mut obj, key.as_ptr(), key.len(), hash_algo.as_ptr(), digits, time_step)
        }

        Ok(TOTP { obj })
    }

    /// Generate an TOTP code
    pub fn generate(&self, timestamp: u64) -> Result<u32> {
        let mut code = 0;
        call_botan! { botan_totp_generate(self.obj, &mut code, timestamp) }
        Ok(code)
    }

    /// Check an TOTP code
    pub fn check(&self,
                 code: u32,
                 timestamp: u64,
                 allowed_drift: usize) -> Result<bool> {

        let rc = unsafe {
            botan_totp_check(self.obj, code, timestamp, allowed_drift)
        };

        if rc == 0 {
            Ok(true)
        }
        else if rc == 1 {
            Ok(false)
        }
        else {
            Err(Error::from(rc))
        }
    }
}
