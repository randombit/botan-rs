use botan_sys::*;
use utils::*;

#[derive(Debug)]
/// A cryptographic random number generator
pub struct RandomNumberGenerator {
    obj: botan_rng_t
}

impl Drop for RandomNumberGenerator {
    fn drop(&mut self) {
        unsafe { botan_rng_destroy(self.obj); }
    }
}

impl RandomNumberGenerator {

    fn new_of_type(typ: &str) -> Result<RandomNumberGenerator> {
        let mut obj = ptr::null_mut();
        call_botan! { botan_rng_init(&mut obj, CString::new(typ).unwrap().as_ptr()) }
        Ok(RandomNumberGenerator { obj })
    }

    pub(crate) fn handle(&self) -> botan_rng_t { self.obj }

    /// Create a new userspace RNG object
    ///
    /// # Examples
    /// ```
    /// let userspace_rng = botan::RandomNumberGenerator::new_userspace().unwrap();
    /// ```
    pub fn new_userspace() -> Result<RandomNumberGenerator> {
        RandomNumberGenerator::new_of_type("user")
    }

    /// Create a new reference to the system PRNG
    ///
    /// # Examples
    /// ```
    /// let system_rng = botan::RandomNumberGenerator::new_system().unwrap();
    /// ```
    pub fn new_system() -> Result<RandomNumberGenerator> {
        RandomNumberGenerator::new_of_type("system")
    }

    /// Create a new reference to an RNG of some arbitrary type
    ///
    /// # Examples
    /// ```
    /// let a_rng = botan::RandomNumberGenerator::new().unwrap();
    /// ```
    pub fn new() -> Result<RandomNumberGenerator> {
        RandomNumberGenerator::new_userspace()
    }

    /// Read bytes from an RNG
    ///
    /// # Examples
    /// ```
    /// let rng = botan::RandomNumberGenerator::new().unwrap();
    /// let output = rng.read(32).unwrap();
    /// assert_eq!(output.len(), 32);
    /// ```
    pub fn read(&self, len: usize) -> Result<Vec<u8>> {
        let mut result = vec![0; len];
        call_botan! { botan_rng_get(self.obj, result.as_mut_ptr(), result.len()) }
        Ok(result)
    }

    /// Attempt to reseed the RNG by unspecified means
    ///
    /// # Examples
    /// ```
    /// let rng = botan::RandomNumberGenerator::new().unwrap();
    /// rng.reseed(256).unwrap();
    /// ```
    pub fn reseed(&self, bits: usize) -> Result<()> {
        call_botan! { botan_rng_reseed(self.obj, bits) }
        Ok(())
    }

}
