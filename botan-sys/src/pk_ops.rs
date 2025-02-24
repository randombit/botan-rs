use crate::ffi_types::*;

use crate::pubkey::{botan_privkey_t, botan_pubkey_t};
use crate::rng::botan_rng_t;

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

pub enum botan_pk_op_kem_encrypt_struct {}
pub type botan_pk_op_kem_encrypt_t = *mut botan_pk_op_kem_encrypt_struct;

pub enum botan_pk_op_kem_decrypt_struct {}
pub type botan_pk_op_kem_decrypt_t = *mut botan_pk_op_kem_decrypt_struct;

extern "C" {
    pub fn botan_pk_op_encrypt_create(
        op: *mut botan_pk_op_encrypt_t,
        key: botan_pubkey_t,
        padding: *const c_char,
        flags: u32,
    ) -> c_int;
    pub fn botan_pk_op_encrypt_destroy(op: botan_pk_op_encrypt_t) -> c_int;

    pub fn botan_pk_op_encrypt_output_length(
        op: botan_pk_op_encrypt_t,
        inlen: usize,
        outlen: *mut usize,
    ) -> c_int;

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
    pub fn botan_pk_op_decrypt_output_length(
        op: botan_pk_op_decrypt_t,
        inlen: usize,
        outlen: *mut usize,
    ) -> c_int;
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
    pub fn botan_pk_op_sign_update(op: botan_pk_op_sign_t, in_: *const u8, in_len: usize) -> c_int;
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
    pub fn botan_pk_op_key_agreement_size(op: botan_pk_op_ka_t, agreed_len: *mut usize) -> c_int;
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

    #[cfg(botan_ffi_20230403)]
    pub fn botan_pk_op_key_agreement_view_public(
        key: botan_privkey_t,
        view_ctx: botan_view_ctx,
        view_fn: botan_view_bin_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20230403)]
    pub fn botan_pk_op_kem_encrypt_create(
        op: *mut botan_pk_op_kem_encrypt_t,
        key: botan_pubkey_t,
        kdf: *const c_char,
    ) -> c_int;

    #[cfg(botan_ffi_20230403)]
    pub fn botan_pk_op_kem_encrypt_destroy(op: botan_pk_op_kem_encrypt_t) -> c_int;

    #[cfg(botan_ffi_20230403)]
    pub fn botan_pk_op_kem_encrypt_shared_key_length(
        op: botan_pk_op_kem_encrypt_t,
        desired_shared_key_length: usize,
        output_shared_key_length: *mut usize,
    ) -> c_int;

    #[cfg(botan_ffi_20230403)]
    pub fn botan_pk_op_kem_encrypt_encapsulated_key_length(
        op: botan_pk_op_kem_encrypt_t,
        output_encapsulated_key_length: *mut usize,
    ) -> c_int;

    #[cfg(botan_ffi_20230403)]
    pub fn botan_pk_op_kem_encrypt_create_shared_key(
        op: botan_pk_op_kem_encrypt_t,
        rng: botan_rng_t,
        salt: *const u8,
        salt_len: usize,
        desired_shared_key_len: usize,
        shared_key: *mut u8,
        shared_key_len: *mut usize,
        encapsulated_key: *mut u8,
        encapsulated_key_len: *mut usize,
    ) -> c_int;

    #[cfg(botan_ffi_20230403)]
    pub fn botan_pk_op_kem_decrypt_destroy(op: botan_pk_op_kem_decrypt_t) -> c_int;

    #[cfg(botan_ffi_20230403)]
    pub fn botan_pk_op_kem_decrypt_create(
        op: *mut botan_pk_op_kem_decrypt_t,
        key: botan_privkey_t,
        kdf: *const c_char,
    ) -> c_int;

    #[cfg(botan_ffi_20230403)]
    pub fn botan_pk_op_kem_decrypt_shared_key_length(
        op: botan_pk_op_kem_decrypt_t,
        desired_shared_key_length: usize,
        output_shared_key_length: *mut usize,
    ) -> c_int;

    #[cfg(botan_ffi_20230403)]
    pub fn botan_pk_op_kem_decrypt_shared_key(
        op: botan_pk_op_kem_decrypt_t,
        salt: *const u8,
        salt_len: usize,
        encapsulated_key: *const u8,
        encapsulated_key_len: usize,
        desired_shared_key_len: usize,
        shared_key: *mut u8,
        shared_key_len: *mut usize,
    ) -> c_int;
}
