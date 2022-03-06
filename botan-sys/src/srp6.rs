#![allow(non_camel_case_types)]

use cty::{c_char, c_int};
use rng::botan_rng_t;

pub enum botan_srp6_server_session_struct {}
pub type botan_srp6_server_session_t = *mut botan_srp6_server_session_struct;

extern "C" {
    pub fn botan_srp6_server_session_init(srp6: *mut botan_srp6_server_session_t) -> c_int;
    pub fn botan_srp6_server_session_destroy(srp6: botan_srp6_server_session_t) -> c_int;
    pub fn botan_srp6_server_session_step1(
        srp6: botan_srp6_server_session_t,
        v: *const u8,
        v_len: usize,
        group_id: *const c_char,
        hash_id: *const c_char,
        rng_obj: botan_rng_t,
        b_pub: *mut u8,
        b_pub_len: *mut usize
    ) -> c_int;
    pub fn botan_srp6_server_session_step2(
        srp6: botan_srp6_server_session_t,
        a: *const u8,
        a_len: usize,
        key: *mut u8,
        key_len: *mut usize,
    ) -> c_int;
    pub fn botan_generate_srp6_verifier(
        identifier: *const c_char,
        password: *const c_char,
        salt: *const u8,
        salt_len: usize,
        group_id: *const c_char,
        hash_id: *const c_char,
        verifier: *mut u8,
        verifier_len: *mut usize
    ) -> c_int;
    pub fn botan_srp6_client_agree(
        username: *const c_char,
        password: *const c_char,
        group_id: *const c_char,
        hash_id: *const c_char,
        salt: *const u8,
        salt_len: usize,
        b: *const u8,
        b_len: usize,
        rng_obj: botan_rng_t,
        a: *mut u8,
        a_len: *mut usize,
        key: *mut u8,
        key_len: *mut usize,
    ) -> c_int;
}
