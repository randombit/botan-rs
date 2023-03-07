use crate::ffi_types::{c_char, c_int};

pub enum botan_hotp_struct {}
pub type botan_hotp_t = *mut botan_hotp_struct;

pub enum botan_totp_struct {}
pub type botan_totp_t = *mut botan_totp_struct;

extern "C" {

    pub fn botan_hotp_init(
        hotp: *mut botan_hotp_t,
        key: *const u8,
        key_len: usize,
        hash_algo: *const c_char,
        digits: usize,
    ) -> c_int;

    pub fn botan_hotp_destroy(hotp: botan_hotp_t) -> c_int;

    pub fn botan_hotp_generate(hotp: botan_hotp_t, hotp_code: *mut u32, hotp_counter: u64)
        -> c_int;

    pub fn botan_hotp_check(
        hotp: botan_hotp_t,
        next_counter: *mut u64,
        hotp_code: u32,
        hotp_counter: u64,
        resync_range: usize,
    ) -> c_int;

    pub fn botan_totp_init(
        totp: *mut botan_totp_t,
        key: *const u8,
        key_len: usize,
        hash_algo: *const c_char,
        digits: usize,
        time_step: usize,
    ) -> c_int;

    pub fn botan_totp_destroy(totp: botan_totp_t) -> c_int;

    pub fn botan_totp_generate(totp: botan_totp_t, totp_code: *mut u32, timestamp: u64) -> c_int;

    pub fn botan_totp_check(
        totp: botan_totp_t,
        totp_code: u32,
        timestamp: u64,
        acceptable_drift: usize,
    ) -> c_int;

}
