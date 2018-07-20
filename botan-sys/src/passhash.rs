use std::os::raw::{c_int, c_char};

use rng::botan_rng_t;

extern "C" {

    pub fn botan_bcrypt_generate(out: *mut u8,
                                 out_len: *mut usize,
                                 password: *const c_char,
                                 rng: botan_rng_t,
                                 work_factor: usize,
                                 flags: u32) -> c_int;

    pub fn botan_bcrypt_is_valid(pass: *const c_char,
                                 hash: *const c_char) -> c_int;

}
