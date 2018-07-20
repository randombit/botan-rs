use botan_sys::*;
use super::{Error, Result};
use std::ptr;

#[derive(Debug)]
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
        call_botan! { botan_rng_init(&mut obj, typ.as_ptr() as *const i8) }
        Ok(RandomNumberGenerator { obj })
    }

    pub fn new_userspace() -> Result<RandomNumberGenerator> {
        RandomNumberGenerator::new_of_type("user")
    }

    pub fn new_system() -> Result<RandomNumberGenerator> {
        RandomNumberGenerator::new_of_type("system")
    }

    pub fn new() -> Result<RandomNumberGenerator> {
        RandomNumberGenerator::new_userspace()
    }

    pub fn read(&self, len: usize) -> Result<Vec<u8>> {
        let mut result = vec![0; len];
        call_botan! { botan_rng_get(self.obj, result.as_mut_ptr(), result.len()) }
        Ok(result)
    }

    pub fn reseed(&self, bits: usize) -> Result<()> {
        call_botan! { botan_rng_reseed(self.obj, bits) }
        Ok(())
    }

}
