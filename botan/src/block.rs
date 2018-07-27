use super::{Error, Result};

use botan_sys::*;

use std::ffi::CString;
use std::ptr;

#[derive(Debug)]
pub struct BlockCipher {
    obj: botan_block_cipher_t,
    block_size: usize
}

impl Drop for BlockCipher {
    fn drop(&mut self) {
        unsafe { botan_block_cipher_destroy(self.obj); }
    }
}

impl BlockCipher {
    pub fn new(name: &str) -> Result<BlockCipher> {
        let mut obj = ptr::null_mut();
        call_botan! { botan_block_cipher_init(&mut obj, CString::new(name).unwrap().as_ptr()) };

        let block_size = unsafe { botan_block_cipher_block_size(obj) };

        if block_size < 0 {
            return Err(Error::from(block_size));
        }

        Ok(BlockCipher { obj, block_size: block_size as usize })
    }

    pub fn block_size(&self) -> usize { self.block_size }

    pub fn set_key(&self, key: &[u8]) -> Result<()> {
        call_botan! { botan_block_cipher_set_key(self.obj, key.as_ptr(), key.len()) };
        Ok(())
    }

    pub fn encrypt_blocks(&self, input: &[u8]) -> Result<Vec<u8>> {
        if input.len() % self.block_size != 0 {
            return Err(Error::InvalidInput);
        }

        let blocks = input.len() / self.block_size;

        let mut output = vec![0; input.len()];

        call_botan! { botan_block_cipher_encrypt_blocks(self.obj, input.as_ptr(), output.as_mut_ptr(), blocks) };
        Ok(output)
    }

    pub fn decrypt_blocks(&self, input: &[u8]) -> Result<Vec<u8>> {
        if input.len() % self.block_size != 0 {
            return Err(Error::InvalidInput);
        }

        let blocks = input.len() / self.block_size;

        let mut output = vec![0; input.len()];

        call_botan! { botan_block_cipher_decrypt_blocks(self.obj, input.as_ptr(), output.as_mut_ptr(), blocks) };
        Ok(output)
    }

    pub fn clear(&self) -> Result<()> {
        call_botan! { botan_block_cipher_clear(self.obj) };
        Ok(())
    }
}
