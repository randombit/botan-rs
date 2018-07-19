use std::os::raw::{c_int, c_char, c_void};

extern "C" {

    pub fn botan_constant_time_compare(x: *const u8, y: *const u8, len: usize) -> c_int;

    pub fn botan_scrub_mem(mem: *mut c_void, bytes: usize)-> c_int;

    pub fn botan_hex_encode(
        x: *const u8,
        len: usize,
        out: *mut c_char,
        flags: u32,
    ) -> c_int;

    pub fn botan_hex_decode(
        hex_str: *const c_char,
        in_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;

    pub fn botan_base64_encode(
        x: *const u8,
        len: usize,
        out: *mut c_char,
        out_len: *mut usize,
    ) -> c_int;

    pub fn botan_base64_decode(
        base64_str: *const c_char,
        in_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;

}
