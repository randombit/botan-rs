use crate::ffi_types::{c_char, c_int};

pub enum botan_xof_struct {}
pub type botan_xof_t = *mut botan_xof_struct;

#[cfg(botan_ffi_20260303)]
extern "C" {
    pub fn botan_xof_init(xof: *mut botan_xof_t, xof_name: *const c_char, flags: u32) -> c_int;

    pub fn botan_xof_copy_state(dest: *mut botan_xof_t, source: botan_xof_t) -> c_int;

    pub fn botan_xof_block_size(xof: botan_xof_t, block_size: *mut usize) -> c_int;

    pub fn botan_xof_name(xof: botan_xof_t, name: *mut c_char, name_len: *mut usize) -> c_int;

    pub fn botan_xof_accepts_input(xof: botan_xof_t) -> c_int;

    pub fn botan_xof_clear(xof: botan_xof_t) -> c_int;

    pub fn botan_xof_update(xof: botan_xof_t, input: *const u8, in_len: usize) -> c_int;

    pub fn botan_xof_output(xof: botan_xof_t, out: *mut u8, out_len: usize) -> c_int;

    pub fn botan_xof_destroy(xof: botan_xof_t) -> c_int;
}
