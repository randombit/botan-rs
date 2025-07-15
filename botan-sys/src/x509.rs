#[cfg(botan_ffi_20250805)]
use crate::botan_asn1_oid_t;
use crate::ffi_types::*;

use crate::pubkey::{botan_privkey_t, botan_pubkey_t};
use crate::rng::botan_rng_t;
#[cfg(botan_ffi_20250805)]
use crate::x509_rpki::{botan_x509_ext_as_blocks_t, botan_x509_ext_ip_addr_blocks_t};

pub enum botan_x509_cert_struct {}
pub type botan_x509_cert_t = *mut botan_x509_cert_struct;

pub enum botan_x509_crl_struct {}
pub type botan_x509_crl_t = *mut botan_x509_crl_struct;

#[cfg(botan_ffi_20250805)]
pub enum botan_x509_cert_params_builder_struct {}
#[cfg(botan_ffi_20250805)]
pub type botan_x509_cert_params_builder_t = *mut botan_x509_cert_params_builder_struct;

#[cfg(botan_ffi_20250805)]
pub enum botan_x509_pkcs10_req_struct {}
#[cfg(botan_ffi_20250805)]
pub type botan_x509_pkcs10_req_t = *mut botan_x509_pkcs10_req_struct;

#[repr(u32)]
#[allow(clippy::upper_case_acronyms)]
#[cfg_attr(botan_ffi_20250805, derive(Copy, Clone))]
pub enum X509KeyConstraints {
    NO_CONSTRAINTS = 0,
    DIGITAL_SIGNATURE = 32768,
    NON_REPUDIATION = 16384,
    KEY_ENCIPHERMENT = 8192,
    DATA_ENCIPHERMENT = 4096,
    KEY_AGREEMENT = 2048,
    KEY_CERT_SIGN = 1024,
    CRL_SIGN = 512,
    ENCIPHER_ONLY = 256,
    DECIPHER_ONLY = 128,
}

extern "C" {
    pub fn botan_x509_cert_load(
        cert_obj: *mut botan_x509_cert_t,
        cert: *const u8,
        cert_len: usize,
    ) -> c_int;
    pub fn botan_x509_cert_dup(cert_obj: *mut botan_x509_cert_t, cert: botan_x509_cert_t) -> c_int;
    pub fn botan_x509_cert_load_file(
        cert_obj: *mut botan_x509_cert_t,
        filename: *const c_char,
    ) -> c_int;
    pub fn botan_x509_cert_destroy(cert: botan_x509_cert_t) -> c_int;
    pub fn botan_x509_cert_gen_selfsigned(
        cert: *mut botan_x509_cert_t,
        key: botan_privkey_t,
        rng: botan_rng_t,
        common_name: *const c_char,
        org_name: *const c_char,
    ) -> c_int;
    pub fn botan_x509_cert_get_time_starts(
        cert: botan_x509_cert_t,
        out: *mut c_char,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_get_time_expires(
        cert: botan_x509_cert_t,
        out: *mut c_char,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_not_before(cert: botan_x509_cert_t, timestamp: *mut u64) -> c_int;
    pub fn botan_x509_cert_not_after(cert: botan_x509_cert_t, timestamp: *mut u64) -> c_int;
    pub fn botan_x509_cert_get_fingerprint(
        cert: botan_x509_cert_t,
        hash: *const c_char,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_get_serial_number(
        cert: botan_x509_cert_t,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_get_authority_key_id(
        cert: botan_x509_cert_t,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_get_subject_key_id(
        cert: botan_x509_cert_t,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_get_basic_constraints(
        cert: botan_x509_cert_t,
        is_ca: *mut c_int,
        limit: *mut usize,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_get_key_constraints(cert: botan_x509_cert_t, usage: *mut u32) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_get_ocsp_responder(
        cert: botan_x509_cert_t,
        view_ctx: botan_view_ctx,
        view_fn: botan_view_str_fn,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_is_self_signed(cert: botan_x509_cert_t, out: *mut c_int) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_get_public_key_bits(
        cert: botan_x509_cert_t,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_get_public_key(
        cert: botan_x509_cert_t,
        key: *mut botan_pubkey_t,
    ) -> c_int;
    pub fn botan_x509_cert_get_issuer_dn(
        cert: botan_x509_cert_t,
        key: *const c_char,
        index: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_get_subject_dn(
        cert: botan_x509_cert_t,
        key: *const c_char,
        index: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_to_string(
        cert: botan_x509_cert_t,
        out: *mut c_char,
        out_len: *mut usize,
    ) -> c_int;

    pub fn botan_x509_cert_allowed_usage(cert: botan_x509_cert_t, key_usage: c_uint) -> c_int;
    pub fn botan_x509_cert_hostname_match(
        cert: botan_x509_cert_t,
        hostname: *const c_char,
    ) -> c_int;

    pub fn botan_x509_cert_verify(
        validation_result: *mut c_int,
        ee_cert: botan_x509_cert_t,
        intermediates: *const botan_x509_cert_t,
        intermediates_len: usize,
        trusted: *const botan_x509_cert_t,
        trusted_len: usize,
        trusted_path: *const c_char,
        required_key_strength: usize,
        hostname: *const c_char,
        reference_time: u64,
    ) -> c_int;

    pub fn botan_x509_cert_validation_status(code: c_int) -> *const c_char;

    #[cfg(botan_ffi_20230403)]
    pub fn botan_x509_cert_view_public_key_bits(
        cert: botan_x509_cert_t,
        view_ctx: botan_view_ctx,
        view_fn: botan_view_bin_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20230403)]
    pub fn botan_x509_cert_view_as_string(
        cert: botan_x509_cert_t,
        view_ctx: botan_view_ctx,
        view_fn: botan_view_str_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_view_pem(
        cert: botan_x509_cert_t,
        view_ctx: botan_view_ctx,
        view_fn: botan_view_str_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_destroy(opts: botan_x509_cert_params_builder_t) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_create_cert_params_builder(
        builder: *mut botan_x509_cert_params_builder_t,
        opts: *const c_char,
        expire_time: *const u32,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_common_name(
        builder: botan_x509_cert_params_builder_t,
        name: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_country(
        builder: botan_x509_cert_params_builder_t,
        country: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_organization(
        builder: botan_x509_cert_params_builder_t,
        organization: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_org_unit(
        builder: botan_x509_cert_params_builder_t,
        org_unit: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_locality(
        builder: botan_x509_cert_params_builder_t,
        locality: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_state(
        builder: botan_x509_cert_params_builder_t,
        state: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_serial_number(
        builder: botan_x509_cert_params_builder_t,
        serial_number: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_email(
        builder: botan_x509_cert_params_builder_t,
        email: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_uri(
        builder: botan_x509_cert_params_builder_t,
        uri: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_ip(
        builder: botan_x509_cert_params_builder_t,
        ip: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_dns(
        builder: botan_x509_cert_params_builder_t,
        dns: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_xmpp(
        builder: botan_x509_cert_params_builder_t,
        xmpp: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_challenge(
        builder: botan_x509_cert_params_builder_t,
        challenge: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_mark_as_ca_key(
        builder: botan_x509_cert_params_builder_t,
        limit: usize,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_not_before(
        builder: botan_x509_cert_params_builder_t,
        time_since_epoch: u64,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_not_after(
        builder: botan_x509_cert_params_builder_t,
        time_since_epoch: u64,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_constraints(
        builder: botan_x509_cert_params_builder_t,
        usage: u32,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_ex_constraint(
        builder: botan_x509_cert_params_builder_t,
        oid: botan_asn1_oid_t,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_ext_ip_addr_blocks(
        builder: botan_x509_cert_params_builder_t,
        ip_addr_blocks: botan_x509_ext_ip_addr_blocks_t,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_cert_params_builder_add_ext_as_blocks(
        builder: botan_x509_cert_params_builder_t,
        as_blocks: botan_x509_ext_as_blocks_t,
    ) -> c_int;

    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_create_self_signed_cert(
        cert_obj: *mut botan_x509_cert_t,
        key: botan_privkey_t,
        builder: botan_x509_cert_params_builder_t,
        hash_fn: *const c_char,
        padding: *const c_char,
        rng: botan_rng_t,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_pkcs10_req_destroy(req: botan_x509_pkcs10_req_t) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_create_pkcs10_req(
        req_obj: *mut botan_x509_pkcs10_req_t,
        builder: botan_x509_cert_params_builder_t,
        key: botan_privkey_t,
        hash_fn: *const c_char,
        rng: botan_rng_t,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_pkcs10_req_view_pem(
        req: botan_x509_pkcs10_req_t,
        view_ctx: botan_view_ctx,
        view_fn: botan_view_str_fn,
    ) -> c_int;
    #[cfg(botan_ffi_20250805)]
    pub fn botan_x509_sign_req(
        subject_cert: *mut botan_x509_cert_t,
        subject_req: botan_x509_pkcs10_req_t,
        issuing_cert: botan_x509_cert_t,
        issuing_key: botan_privkey_t,
        rng: botan_rng_t,
        not_before: u64,
        not_after: u64,
        hash_fn: *const c_char,
        padding: *const c_char,
    ) -> c_int;

    pub fn botan_x509_crl_load_file(crl: *mut botan_x509_crl_t, file_path: *const c_char) -> c_int;

    pub fn botan_x509_crl_load(
        crl: *mut botan_x509_crl_t,
        data: *const u8,
        data_len: usize,
    ) -> c_int;

    pub fn botan_x509_crl_destroy(crl: botan_x509_crl_t) -> c_int;

    pub fn botan_x509_is_revoked(crl: botan_x509_crl_t, cert: botan_x509_cert_t) -> c_int;

    // TODO: botan_x509_cert_verify_with_crl

}
