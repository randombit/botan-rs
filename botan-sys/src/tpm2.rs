use crate::ffi_types::{c_char, c_int};
use crate::rng::botan_rng_t;

pub enum botan_tpm2_ctx_struct {}
pub type botan_tpm2_ctx_t = *mut botan_tpm2_ctx_struct;

pub enum botan_tpm2_session_struct {}
pub type botan_tpm2_session_t = *mut botan_tpm2_session_struct;

pub enum botan_tpm2_crypto_backend_state_struct {}
pub type botan_tpm2_crypto_backend_state_t = *mut botan_tpm2_crypto_backend_state_struct;

// Opaque ESYS_CONTEXT from tss2
#[repr(C)]
pub struct ESYS_CONTEXT {
    _private: [u8; 0],
}

#[cfg(botan_ffi_20250506)]
extern "C" {
    pub fn botan_tpm2_supports_crypto_backend() -> c_int;

    pub fn botan_tpm2_ctx_init(
        ctx_out: *mut botan_tpm2_ctx_t,
        tcti_nameconf: *const c_char,
    ) -> c_int;

    pub fn botan_tpm2_ctx_init_ex(
        ctx_out: *mut botan_tpm2_ctx_t,
        tcti_name: *const c_char,
        tcti_conf: *const c_char,
    ) -> c_int;

    pub fn botan_tpm2_ctx_from_esys(
        ctx_out: *mut botan_tpm2_ctx_t,
        esys_ctx: *mut ESYS_CONTEXT,
    ) -> c_int;

    pub fn botan_tpm2_ctx_enable_crypto_backend(ctx: botan_tpm2_ctx_t, rng: botan_rng_t) -> c_int;

    pub fn botan_tpm2_ctx_destroy(ctx: botan_tpm2_ctx_t) -> c_int;

    pub fn botan_tpm2_enable_crypto_backend(
        cbs_out: *mut botan_tpm2_crypto_backend_state_t,
        esys_ctx: *mut ESYS_CONTEXT,
        rng: botan_rng_t,
    ) -> c_int;

    pub fn botan_tpm2_crypto_backend_state_destroy(cbs: botan_tpm2_crypto_backend_state_t)
        -> c_int;

    pub fn botan_tpm2_rng_init(
        rng_out: *mut botan_rng_t,
        ctx: botan_tpm2_ctx_t,
        s1: botan_tpm2_session_t,
        s2: botan_tpm2_session_t,
        s3: botan_tpm2_session_t,
    ) -> c_int;

    pub fn botan_tpm2_unauthenticated_session_init(
        session_out: *mut botan_tpm2_session_t,
        ctx: botan_tpm2_ctx_t,
    ) -> c_int;

    pub fn botan_tpm2_session_destroy(session: botan_tpm2_session_t) -> c_int;
}
