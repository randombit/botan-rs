use crate::ffi_types::{c_char, c_int, c_void};

pub enum botan_rng_struct {}
pub type botan_rng_t = *mut botan_rng_struct;

extern "C" {

    pub fn botan_rng_init(rng: *mut botan_rng_t, rng_type: *const c_char) -> c_int;

    #[cfg(botan_ffi_20230403)]
    pub fn botan_rng_init_custom(
        rng_out: *mut botan_rng_t,
        rng_name: *const c_char,
        context: *mut c_void,
        get_cb: Option<extern "C" fn(context: *mut c_void, out: *mut u8, out_len: usize) -> c_int>,
        add_entropy_cb: Option<
            extern "C" fn(context: *mut c_void, input: *const u8, length: usize) -> c_int,
        >,
        destroy_cb: Option<extern "C" fn(context: *mut c_void)>,
    ) -> c_int;

    pub fn botan_rng_get(rng: botan_rng_t, out: *mut u8, out_len: usize) -> c_int;

    #[cfg(botan_ffi_20230403)]
    pub fn botan_system_rng_get(out: *mut u8, out_len: usize) -> c_int;

    pub fn botan_rng_reseed(rng: botan_rng_t, bits: usize) -> c_int;

    pub fn botan_rng_reseed_from_rng(rng: botan_rng_t, src: botan_rng_t, bits: usize) -> c_int;

    pub fn botan_rng_add_entropy(rng: botan_rng_t, data: *const u8, len: usize) -> c_int;

    pub fn botan_rng_destroy(rng: botan_rng_t) -> c_int;

}
