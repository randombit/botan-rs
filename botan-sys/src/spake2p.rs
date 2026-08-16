use crate::ec_group::botan_ec_group_t;
use crate::ffi_types::{botan_view_bin_fn, botan_view_ctx, c_char, c_int};
use crate::rng::botan_rng_t;

pub enum botan_spake2p_params_struct {}
pub type botan_spake2p_params_t = *mut botan_spake2p_params_struct;

pub enum botan_spake2p_prover_struct {}
pub type botan_spake2p_prover_t = *mut botan_spake2p_prover_struct;

pub enum botan_spake2p_verifier_struct {}
pub type botan_spake2p_verifier_t = *mut botan_spake2p_verifier_struct;

botan_ffi_functions! {
    #[cfg(botan_ffi_20260811)]
    pub fn botan_spake2p_params_init(
        params: *mut botan_spake2p_params_t,
        ciphersuite: *const c_char,
    ) -> c_int;

    #[cfg(botan_ffi_20260811)]
    pub fn botan_spake2p_params_init_custom(
        params: *mut botan_spake2p_params_t,
        group: botan_ec_group_t,
        seed: *const u8,
        seed_len: usize,
        hash_fn: *const c_char,
    ) -> c_int;

    #[cfg(botan_ffi_20260811)]
    pub fn botan_spake2p_params_destroy(params: botan_spake2p_params_t) -> c_int;

    #[cfg(botan_ffi_20260811)]
    pub fn botan_spake2p_params_share_size(
        params: botan_spake2p_params_t,
        share_size: *mut usize,
    ) -> c_int;

    #[cfg(botan_ffi_20260811)]
    pub fn botan_spake2p_params_confirmation_size(
        params: botan_spake2p_params_t,
        confirmation_size: *mut usize,
    ) -> c_int;

    #[cfg(botan_ffi_20260811)]
    pub fn botan_spake2p_derive_secret(
        params: botan_spake2p_params_t,
        password: *const c_char,
        prover_id: *const u8,
        prover_id_len: usize,
        verifier_id: *const u8,
        verifier_id_len: usize,
        salt: *const u8,
        salt_len: usize,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20260811)]
    pub fn botan_spake2p_registration_record(
        params: botan_spake2p_params_t,
        rng: botan_rng_t,
        secret: *const u8,
        secret_len: usize,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20260811)]
    pub fn botan_spake2p_prover_init(
        prover: *mut botan_spake2p_prover_t,
        params: botan_spake2p_params_t,
        secret: *const u8,
        secret_len: usize,
        prover_id: *const u8,
        prover_id_len: usize,
        verifier_id: *const u8,
        verifier_id_len: usize,
        context: *const u8,
        context_len: usize,
    ) -> c_int;

    #[cfg(botan_ffi_20260811)]
    pub fn botan_spake2p_prover_destroy(prover: botan_spake2p_prover_t) -> c_int;

    #[cfg(botan_ffi_20260811)]
    pub fn botan_spake2p_prover_generate_message(
        prover: botan_spake2p_prover_t,
        rng: botan_rng_t,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20260811)]
    pub fn botan_spake2p_prover_process_message(
        prover: botan_spake2p_prover_t,
        rng: botan_rng_t,
        peer_message: *const u8,
        peer_message_len: usize,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20260811)]
    pub fn botan_spake2p_prover_shared_secret(
        prover: botan_spake2p_prover_t,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20260811)]
    pub fn botan_spake2p_verifier_init(
        verifier: *mut botan_spake2p_verifier_t,
        params: botan_spake2p_params_t,
        record: *const u8,
        record_len: usize,
        prover_id: *const u8,
        prover_id_len: usize,
        verifier_id: *const u8,
        verifier_id_len: usize,
        context: *const u8,
        context_len: usize,
    ) -> c_int;

    #[cfg(botan_ffi_20260811)]
    pub fn botan_spake2p_verifier_destroy(verifier: botan_spake2p_verifier_t) -> c_int;

    #[cfg(botan_ffi_20260811)]
    pub fn botan_spake2p_verifier_process_message(
        verifier: botan_spake2p_verifier_t,
        rng: botan_rng_t,
        peer_message: *const u8,
        peer_message_len: usize,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20260811)]
    pub fn botan_spake2p_verifier_verify_confirmation(
        verifier: botan_spake2p_verifier_t,
        confirmation: *const u8,
        confirmation_len: usize,
    ) -> c_int;

    #[cfg(botan_ffi_20260811)]
    pub fn botan_spake2p_verifier_skip_confirmation(verifier: botan_spake2p_verifier_t) -> c_int;

    #[cfg(botan_ffi_20260811)]
    pub fn botan_spake2p_verifier_shared_secret(
        verifier: botan_spake2p_verifier_t,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;
}
