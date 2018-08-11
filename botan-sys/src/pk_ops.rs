use std::os::raw::{c_int, c_char};

use rng::botan_rng_t;
use pubkey::{botan_pubkey_t, botan_privkey_t};

pub enum botan_pk_op_encrypt_struct {}
pub type botan_pk_op_encrypt_t = *mut botan_pk_op_encrypt_struct;

pub enum botan_pk_op_decrypt_struct {}
pub type botan_pk_op_decrypt_t = *mut botan_pk_op_decrypt_struct;

pub enum botan_pk_op_sign_struct {}
pub type botan_pk_op_sign_t = *mut botan_pk_op_sign_struct;

pub enum botan_pk_op_verify_struct {}
pub type botan_pk_op_verify_t = *mut botan_pk_op_verify_struct;

pub enum botan_pk_op_ka_struct {}
pub type botan_pk_op_ka_t = *mut botan_pk_op_ka_struct;

extern "C" {
    pub fn botan_pk_op_encrypt_create(
        op: *mut botan_pk_op_encrypt_t,
        key: botan_pubkey_t,
        padding: *const c_char,
        flags: u32,
    ) -> c_int;
    pub fn botan_pk_op_encrypt_destroy(op: botan_pk_op_encrypt_t) -> c_int;

    pub fn botan_pk_op_encrypt_output_length(op: botan_pk_op_encrypt_t, inlen: usize, outlen: *mut usize) -> c_int;

    pub fn botan_pk_op_encrypt(
        op: botan_pk_op_encrypt_t,
        rng: botan_rng_t,
        out: *mut u8,
        out_len: *mut usize,
        plaintext: *const u8,
        plaintext_len: usize,
    ) -> c_int;

    pub fn botan_pk_op_decrypt_create(
        op: *mut botan_pk_op_decrypt_t,
        key: botan_privkey_t,
        padding: *const c_char,
        flags: u32,
    ) -> c_int;
    pub fn botan_pk_op_decrypt_output_length(op: botan_pk_op_decrypt_t, inlen: usize, outlen: *mut usize) -> c_int;
    pub fn botan_pk_op_decrypt_destroy(op: botan_pk_op_decrypt_t) -> c_int;
    pub fn botan_pk_op_decrypt(
        op: botan_pk_op_decrypt_t,
        out: *mut u8,
        out_len: *mut usize,
        ciphertext: *const u8,
        ciphertext_len: usize,
    ) -> c_int;

    pub fn botan_pk_op_sign_create(
        op: *mut botan_pk_op_sign_t,
        key: botan_privkey_t,
        hash_and_padding: *const c_char,
        flags: u32,
    ) -> c_int;
    pub fn botan_pk_op_sign_output_length(op: botan_pk_op_sign_t, siglen: *mut usize) -> c_int;
    pub fn botan_pk_op_sign_destroy(op: botan_pk_op_sign_t) -> c_int;
    pub fn botan_pk_op_sign_update(
        op: botan_pk_op_sign_t,
        in_: *const u8,
        in_len: usize,
    ) -> c_int;
    pub fn botan_pk_op_sign_finish(
        op: botan_pk_op_sign_t,
        rng: botan_rng_t,
        sig: *mut u8,
        sig_len: *mut usize,
    ) -> c_int;

    pub fn botan_pk_op_verify_create(
        op: *mut botan_pk_op_verify_t,
        key: botan_pubkey_t,
        hash_and_padding: *const c_char,
        flags: u32,
    ) -> c_int;
    pub fn botan_pk_op_verify_destroy(op: botan_pk_op_verify_t) -> c_int;
    pub fn botan_pk_op_verify_update(
        op: botan_pk_op_verify_t,
        in_: *const u8,
        in_len: usize,
    ) -> c_int;
    pub fn botan_pk_op_verify_finish(
        op: botan_pk_op_verify_t,
        sig: *const u8,
        sig_len: usize,
    ) -> c_int;

    pub fn botan_pk_op_key_agreement_create(
        op: *mut botan_pk_op_ka_t,
        key: botan_privkey_t,
        kdf: *const c_char,
        flags: u32,
    ) -> c_int;
    pub fn botan_pk_op_key_agreement_destroy(op: botan_pk_op_ka_t) -> c_int;
    pub fn botan_pk_op_key_agreement_export_public(
        key: botan_privkey_t,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_pk_op_key_agreement(
        op: botan_pk_op_ka_t,
        out: *mut u8,
        out_len: *mut usize,
        other_key: *const u8,
        other_key_len: usize,
        salt: *const u8,
        salt_len: usize,
    ) -> c_int;
    pub fn botan_pkcs_hash_id(
        hash_name: *const c_char,
        pkcs_id: *mut u8,
        pkcs_id_len: *mut usize,
    ) -> c_int;

}
