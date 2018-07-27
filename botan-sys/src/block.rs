use std::os::raw::{c_int, c_char};

pub enum botan_block_cipher_struct {}
pub type botan_block_cipher_t = *mut botan_block_cipher_struct;

extern "C" {

    pub fn botan_block_cipher_init(bc: *mut botan_block_cipher_t,
                                   cipher_name: *const c_char) -> c_int;

    pub fn botan_block_cipher_destroy(bc: botan_block_cipher_t) -> c_int;

    pub fn botan_block_cipher_clear(bc: botan_block_cipher_t) -> c_int;

    pub fn botan_block_cipher_set_key(bc: botan_block_cipher_t,
                                      key: *const u8,
                                      len: usize) -> c_int;

    pub fn botan_block_cipher_block_size(bc: botan_block_cipher_t) -> c_int;

    pub fn botan_block_cipher_encrypt_blocks(bc: botan_block_cipher_t,
                                             input: *const u8,
                                             output: *mut u8,
                                             blocks: usize) -> c_int;

    pub fn botan_block_cipher_decrypt_blocks(bc: botan_block_cipher_t,
                                             input: *const u8,
                                             output: *mut u8,
                                             blocks: usize) -> c_int;

}
