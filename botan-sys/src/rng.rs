use std::os::raw::{c_int, c_char};

pub enum botan_rng_t {}

extern "C" {

    pub fn botan_rng_init(rng: *mut *mut botan_rng_t, rng_type: *const c_char) -> c_int;

    pub fn botan_rng_get(rng: *mut botan_rng_t, out: *mut u8, out_len: usize) -> c_int;

    pub fn botan_rng_reseed(rng: *mut botan_rng_t, bits: usize) -> c_int;

    pub fn botan_rng_destroy(rng: *mut botan_rng_t) -> c_int;

}
