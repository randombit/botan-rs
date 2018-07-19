use super::{Error, Result};

use botan_sys::*;

use std::ffi::CString;
use std::ptr;

#[derive(Debug)]
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
    pub fn new(name: &str) -> Result<HashFunction> {
        let mut obj = ptr::null_mut();
        call_botan! { botan_hash_init(&mut obj, CString::new(name).unwrap().as_ptr(), 0u32) };

        let mut output_length = 0;
        call_botan! { botan_hash_output_length(obj, &mut output_length) };

        Ok(HashFunction { obj, output_length })
    }

    pub fn duplicate(&self) -> Result<HashFunction> {
        let mut obj = ptr::null_mut();
        call_botan! { botan_hash_copy_state(&mut obj, self.obj) };
        Ok(HashFunction { obj: obj, output_length: self.output_length })
    }

    pub fn output_length(&self) -> usize { self.output_length }

    pub fn update(&self, data: &[u8]) -> Result<()> {
        call_botan! { botan_hash_update(self.obj, data.as_ptr(), data.len()) };
        Ok(())
    }

    pub fn finish(&self) -> Result<Vec<u8>> {
        let mut output = vec![0; self.output_length()];
        call_botan! { botan_hash_final(self.obj, output.as_mut_ptr()) };
        Ok(output)
    }

    pub fn clear(&self) -> Result<()> {
        call_botan! { botan_hash_clear(self.obj) };
        Ok(())
    }
}
