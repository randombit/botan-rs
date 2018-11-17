use libc::{c_int};

extern "C" {

    pub fn botan_key_wrap3394(input: *const u8, input_len: usize,
                              kek: *const u8, kek_len: usize,
                              wrapped_key: *mut u8, wrapped_key_len: *mut usize) -> c_int;

    pub fn botan_key_unwrap3394(wrapped_key: *const u8, wrapped_key_len: usize,
                                kek: *const u8, kek_len: usize,
                                unwrapped_key: *mut u8, unwrapped_key_len: *mut usize) -> c_int;

}
