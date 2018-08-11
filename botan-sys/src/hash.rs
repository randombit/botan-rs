use std::os::raw::{c_int, c_char};

pub enum botan_hash_struct {}
pub type botan_hash_t = *mut botan_hash_struct;

extern "C" {

    pub fn botan_hash_init(hash: *mut botan_hash_t,
                           hash_name: *const c_char,
                           flags: u32) -> c_int;

    pub fn botan_hash_copy_state(dest: *mut botan_hash_t, source: botan_hash_t) -> c_int;

    pub fn botan_hash_name(hash: botan_hash_t, name: *mut c_char, name_len: *mut usize) -> c_int;

    pub fn botan_hash_output_length(hash: botan_hash_t, output_length: *mut usize) -> c_int;
    pub fn botan_hash_block_size(hash: botan_hash_t, block_size: *mut usize) -> c_int;

    pub fn botan_hash_update(hash: botan_hash_t, data: *const u8, len: usize) -> c_int;
    pub fn botan_hash_final(hash: botan_hash_t, digest: *mut u8) -> c_int;
    pub fn botan_hash_clear(hash: botan_hash_t) -> c_int;

    pub fn botan_hash_destroy(hash: botan_hash_t) -> c_int;

}
