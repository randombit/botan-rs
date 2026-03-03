use crate::ffi_types::{c_char, c_int};
use crate::rng::botan_rng_t;

pub enum botan_srp6_server_session_struct {}
pub type botan_srp6_server_session_t = *mut botan_srp6_server_session_struct;

#[cfg(botan_ffi_20230403)]
extern "C" {
    pub fn botan_srp6_server_session_init(srp6: *mut botan_srp6_server_session_t) -> c_int;

    pub fn botan_srp6_server_session_destroy(srp6: botan_srp6_server_session_t) -> c_int;

    pub fn botan_srp6_server_session_step1(
        srp6: botan_srp6_server_session_t,
        verifier: *const u8,
        verifier_len: usize,
        group_id: *const c_char,
        hash_id: *const c_char,
        rng_obj: botan_rng_t,
        B_pub: *mut u8,
        B_pub_len: *mut usize,
    ) -> c_int;

    pub fn botan_srp6_server_session_step2(
        srp6: botan_srp6_server_session_t,
        A: *const u8,
        A_len: usize,
        key: *mut u8,
        key_len: *mut usize,
    ) -> c_int;

    pub fn botan_srp6_generate_verifier(
        identifier: *const c_char,
        password: *const c_char,
        salt: *const u8,
        salt_len: usize,
        group_id: *const c_char,
        hash_id: *const c_char,
        verifier: *mut u8,
        verifier_len: *mut usize,
    ) -> c_int;

    pub fn botan_srp6_client_agree(
        username: *const c_char,
        password: *const c_char,
        group_id: *const c_char,
        hash_id: *const c_char,
        salt: *const u8,
        salt_len: usize,
        B: *const u8,
        B_len: usize,
        rng_obj: botan_rng_t,
        A: *mut u8,
        A_len: *mut usize,
        K: *mut u8,
        K_len: *mut usize,
    ) -> c_int;

    pub fn botan_srp6_group_size(group_id: *const c_char, group_p_bytes: *mut usize) -> c_int;
}
