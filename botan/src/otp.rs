use crate::utils::*;
use botan_sys::*;

#[derive(Debug)]
/// Generate or check HOTP tokens
pub struct HOTP {
    obj: botan_hotp_t,
}

botan_impl_drop!(HOTP, botan_hotp_destroy);

#[derive(Debug)]
/// Generate or check TOTP tokens
pub struct TOTP {
    obj: botan_totp_t,
}

botan_impl_drop!(TOTP, botan_totp_destroy);

impl HOTP {
    /// Instantiate a new HOTP instance with the given parameters
    ///
    /// # Examples
    ///
    /// ```
    /// let hotp = botan::HOTP::new(&[1,2,3,4], "SHA-1", 6);
    /// ```
    pub fn new(key: &[u8], hash_algo: &str, digits: usize) -> Result<HOTP> {
        let hash_algo = make_cstr(hash_algo)?;

        let obj = botan_init!(
            botan_hotp_init,
            key.as_ptr(),
            key.len(),
            hash_algo.as_ptr(),
            digits
        )?;

        Ok(HOTP { obj })
    }

    /// Generate an HOTP code
    pub fn generate(&self, counter: u64) -> Result<u32> {
        let mut code = 0;
        botan_call!(botan_hotp_generate, self.obj, &mut code, counter)?;
        Ok(code)
    }

    /// Check an HOTP code
    pub fn check(&self, code: u32, counter: u64) -> Result<bool> {
        let cmp_code = self.generate(counter)?;
        Ok(cmp_code == code)
    }

    /// Check an HOTP code, allowing counter resync
    pub fn check_with_resync(
        &self,
        code: u32,
        counter: u64,
        resync_range: usize,
    ) -> Result<(bool, u64)> {
        let mut new_ctr = 0;
        let res = botan_bool_in_rc!(
            botan_hotp_check,
            self.obj,
            &mut new_ctr,
            code,
            counter,
            resync_range
        )?;

        // Return value is inverted
        if res == false {
            Ok((true, new_ctr))
        } else {
            Ok((false, counter))
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
        let hash_algo = make_cstr(hash_algo)?;

        let obj = botan_init!(
            botan_totp_init,
            key.as_ptr(),
            key.len(),
            hash_algo.as_ptr(),
            digits,
            time_step
        )?;

        Ok(TOTP { obj })
    }

    /// Generate an TOTP code
    pub fn generate(&self, timestamp: u64) -> Result<u32> {
        let mut code = 0;
        botan_call!(botan_totp_generate, self.obj, &mut code, timestamp)?;
        Ok(code)
    }

    /// Check an TOTP code
    pub fn check(&self, code: u32, timestamp: u64, allowed_drift: usize) -> Result<bool> {
        // Return value is inverted
        Ok(!botan_bool_in_rc!(
            botan_totp_check,
            self.obj,
            code,
            timestamp,
            allowed_drift
        )?)
    }
}
