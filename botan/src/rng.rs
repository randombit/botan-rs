use crate::utils::*;
use botan_sys::*;

#[derive(Debug)]
/// A cryptographic random number generator
pub struct RandomNumberGenerator {
    obj: botan_rng_t,
}

unsafe impl Sync for RandomNumberGenerator {}
unsafe impl Send for RandomNumberGenerator {}

botan_impl_drop!(RandomNumberGenerator, botan_rng_destroy);

impl RandomNumberGenerator {
    fn new_of_type(typ: &str) -> Result<RandomNumberGenerator> {
        let typ = make_cstr(typ)?;
        let obj = botan_init!(botan_rng_init, typ.as_ptr())?;
        Ok(RandomNumberGenerator { obj })
    }

    pub(crate) fn handle(&self) -> botan_rng_t {
        self.obj
    }

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
    /// let mut rng = botan::RandomNumberGenerator::new().unwrap();
    /// let output = rng.read(32).unwrap();
    /// assert_eq!(output.len(), 32);
    /// ```
    pub fn read(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut result = vec![0; len];
        self.fill(&mut result)?;
        Ok(result)
    }

    /// Store bytes from the RNG into the passed slice
    ///
    /// # Examples
    /// ```
    /// let mut rng = botan::RandomNumberGenerator::new().unwrap();
    /// let mut output = vec![0; 32];
    /// rng.fill(&mut output).unwrap();
    /// ```
    pub fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        botan_call!(botan_rng_get, self.obj, out.as_mut_ptr(), out.len())
    }

    /// Attempt to reseed the RNG by unspecified means
    ///
    /// # Examples
    /// ```
    /// let mut rng = botan::RandomNumberGenerator::new().unwrap();
    /// rng.reseed(256).unwrap();
    /// ```
    pub fn reseed(&mut self, bits: usize) -> Result<()> {
        botan_call!(botan_rng_reseed, self.obj, bits)
    }

    /// Attempt to reseed the RNG by getting data from source RNG
    ///
    /// # Examples
    /// ```
    /// let mut system_rng = botan::RandomNumberGenerator::new_system().unwrap();
    /// let mut rng = botan::RandomNumberGenerator::new_userspace().unwrap();
    /// rng.reseed_from_rng(&mut system_rng, 256).unwrap();
    /// ```
    pub fn reseed_from_rng(
        &mut self,
        source: &mut RandomNumberGenerator,
        bits: usize,
    ) -> Result<()> {
        botan_call!(botan_rng_reseed_from_rng, self.obj, source.handle(), bits)
    }

    /// Add some seed material to the RNG
    ///
    /// # Examples
    /// ```
    /// let mut rng = botan::RandomNumberGenerator::new_userspace().unwrap();
    /// let my_seed = vec![0x42, 0x6F, 0x62];
    /// rng.add_entropy(&my_seed);
    /// ```
    pub fn add_entropy(&mut self, seed: &[u8]) -> Result<()> {
        botan_call!(botan_rng_add_entropy, self.obj, seed.as_ptr(), seed.len())
    }
}
