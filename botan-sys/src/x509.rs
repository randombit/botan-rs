#[cfg(botan_ffi_20251104)]
use crate::botan_mp_t;
use crate::ffi_types::*;
#[cfg(botan_ffi_20251104)]
use crate::oid::botan_asn1_oid_t;

use crate::pubkey::{botan_privkey_t, botan_pubkey_t};
use crate::rng::botan_rng_t;
#[cfg(botan_ffi_20251104)]
use crate::x509_ext::{botan_x509_ext_as_blocks_t, botan_x509_ext_ip_addr_blocks_t};

pub enum botan_x509_cert_struct {}
pub type botan_x509_cert_t = *mut botan_x509_cert_struct;

pub enum botan_x509_crl_struct {}
pub type botan_x509_crl_t = *mut botan_x509_crl_struct;

#[cfg(botan_ffi_20251104)]
pub enum botan_x509_cert_params_builder_struct {}
#[cfg(botan_ffi_20251104)]
pub type botan_x509_cert_params_builder_t = *mut botan_x509_cert_params_builder_struct;

#[cfg(botan_ffi_20251104)]
pub enum botan_x509_pkcs10_req_struct {}
#[cfg(botan_ffi_20251104)]
pub type botan_x509_pkcs10_req_t = *mut botan_x509_pkcs10_req_struct;

#[repr(u32)]
#[allow(clippy::upper_case_acronyms)]
#[cfg_attr(botan_ffi_20251104, derive(Copy, Clone))]
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

#[repr(u8)]
#[allow(clippy::upper_case_acronyms)]
#[cfg_attr(botan_ffi_20251104, derive(Copy, Clone))]
pub enum X509CrlCode {
    UNSPECIFIED = 0,
    KEY_COMPROMISE = 1,
    CA_COMPROMISE = 2,
    AFFILIATION_CHANGED = 3,
    SUPERSEDED = 4,
    CESSATION_OF_OPERATION = 5,
    CERTIFICATE_HOLD = 6,
    REMOVE_FROM_CRL = 8,
    PRIVILIGE_WITHDRAWN = 9,
    AA_COMPROMISE = 10,
}

impl TryFrom<u8> for X509CrlCode {
    type Error = ();

    fn try_from(value: u8) -> core::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(X509CrlCode::UNSPECIFIED),
            1 => Ok(X509CrlCode::KEY_COMPROMISE),
            2 => Ok(X509CrlCode::CA_COMPROMISE),
            3 => Ok(X509CrlCode::AFFILIATION_CHANGED),
            4 => Ok(X509CrlCode::SUPERSEDED),
            5 => Ok(X509CrlCode::CESSATION_OF_OPERATION),
            6 => Ok(X509CrlCode::CERTIFICATE_HOLD),
            8 => Ok(X509CrlCode::REMOVE_FROM_CRL),
            9 => Ok(X509CrlCode::PRIVILIGE_WITHDRAWN),
            10 => Ok(X509CrlCode::AA_COMPROMISE),
            _ => Err(()),
        }
    }
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
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_is_ca(
        cert: botan_x509_cert_t,
        is_ca: *mut c_int,
        limit: *mut usize,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_get_allowed_usage(cert: botan_x509_cert_t, usage: *mut u32) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_get_ocsp_responder(
        cert: botan_x509_cert_t,
        view_ctx: botan_view_ctx,
        view_fn: botan_view_str_fn,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_is_self_signed(cert: botan_x509_cert_t, out: *mut c_int) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_get_public_key_bits(
        cert: botan_x509_cert_t,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_get_public_key(
        cert: botan_x509_cert_t,
        key: *mut botan_pubkey_t,
    ) -> c_int;
    pub fn botan_x509_cert_get_issuer_dn_count(
        cert: botan_x509_cert_t,
        key: *const c_char,
        len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_get_issuer_dn(
        cert: botan_x509_cert_t,
        key: *const c_char,
        index: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_get_subject_dn_count(
        cert: botan_x509_cert_t,
        key: *const c_char,
        len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_get_subject_dn(
        cert: botan_x509_cert_t,
        key: *const c_char,
        index: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_get_subject_name(
        cert: botan_x509_cert_t,
        view_ctx: botan_view_ctx,
        view_fn: botan_view_str_fn,
    ) -> c_int;
    pub fn botan_x509_cert_get_issuer_name(
        cert: botan_x509_cert_t,
        view_ctx: botan_view_ctx,
        view_fn: botan_view_str_fn,
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

    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_view_pem(
        cert: botan_x509_cert_t,
        view_ctx: botan_view_ctx,
        view_fn: botan_view_str_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_destroy(opts: botan_x509_cert_params_builder_t) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_create(
        builder: *mut botan_x509_cert_params_builder_t,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_add_common_name(
        builder: botan_x509_cert_params_builder_t,
        name: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_add_country(
        builder: botan_x509_cert_params_builder_t,
        country: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_add_state(
        builder: botan_x509_cert_params_builder_t,
        state: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_add_locality(
        builder: botan_x509_cert_params_builder_t,
        locality: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_add_serial_number(
        builder: botan_x509_cert_params_builder_t,
        serial_number: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_add_organization(
        builder: botan_x509_cert_params_builder_t,
        organization: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_add_organizational_unit(
        builder: botan_x509_cert_params_builder_t,
        org_unit: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_add_email(
        builder: botan_x509_cert_params_builder_t,
        email: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_add_dns(
        builder: botan_x509_cert_params_builder_t,
        dns: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_add_uri(
        builder: botan_x509_cert_params_builder_t,
        uri: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_add_xmpp(
        builder: botan_x509_cert_params_builder_t,
        xmpp: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_add_ipv4(
        builder: botan_x509_cert_params_builder_t,
        ip: u32,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_add_allowed_usage(
        builder: botan_x509_cert_params_builder_t,
        usage: u32,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_add_allowed_extended_usage(
        builder: botan_x509_cert_params_builder_t,
        oid: botan_asn1_oid_t,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_set_as_ca_certificate(
        builder: botan_x509_cert_params_builder_t,
        limit: *const usize,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_add_ext_ip_addr_blocks(
        builder: botan_x509_cert_params_builder_t,
        ip_addr_blocks: botan_x509_ext_ip_addr_blocks_t,
        is_critical: c_int,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_add_ext_as_blocks(
        builder: botan_x509_cert_params_builder_t,
        as_blocks: botan_x509_ext_as_blocks_t,
        is_critical: c_int,
    ) -> c_int;

    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_into_self_signed(
        cert_obj: *mut botan_x509_cert_t,
        key: botan_privkey_t,
        builder: botan_x509_cert_params_builder_t,
        rng: botan_rng_t,
        not_before: u64,
        not_after: u64,
        serial_number: *const botan_mp_t,
        hash_fn: *const c_char,
        padding: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_cert_params_builder_into_pkcs10_req(
        req_obj: *mut botan_x509_pkcs10_req_t,
        key: botan_privkey_t,
        builder: botan_x509_cert_params_builder_t,
        rng: botan_rng_t,
        hash_fn: *const c_char,
        padding: *const c_char,
        challenge_password: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_pkcs10_req_destroy(req: botan_x509_pkcs10_req_t) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_pkcs10_req_load_file(
        req_obj: *mut botan_x509_pkcs10_req_t,
        req_path: *const c_char,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_pkcs10_req_load(
        req_obj: *mut botan_x509_pkcs10_req_t,
        req_bits: *const u8,
        req_bits_len: usize,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_pkcs10_req_get_public_key(
        req: botan_x509_pkcs10_req_t,
        key: *mut botan_pubkey_t,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_pkcs10_req_get_allowed_usage(
        req: botan_x509_pkcs10_req_t,
        usage: *mut u32,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_pkcs10_req_is_ca(
        req: botan_x509_pkcs10_req_t,
        is_ca: *mut c_int,
        limit: *mut usize,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_pkcs10_req_verify_signature(
        req: botan_x509_pkcs10_req_t,
        key: botan_pubkey_t,
        result: *mut c_int,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_pkcs10_req_view_pem(
        req: botan_x509_pkcs10_req_t,
        view_ctx: botan_view_ctx,
        view_fn: botan_view_str_fn,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_pkcs10_req_view_der(
        req: botan_x509_pkcs10_req_t,
        view_ctx: botan_view_ctx,
        view_fn: botan_view_bin_fn,
    ) -> c_int;
    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_pkcs10_req_sign(
        subject_cert: *mut botan_x509_cert_t,
        subject_req: botan_x509_pkcs10_req_t,
        issuing_cert: botan_x509_cert_t,
        issuing_key: botan_privkey_t,
        rng: botan_rng_t,
        not_before: u64,
        not_after: u64,
        serial_number: *const botan_mp_t,
        hash_fn: *const c_char,
        padding: *const c_char,
    ) -> c_int;

    pub fn botan_x509_crl_load_file(crl: *mut botan_x509_crl_t, file_path: *const c_char) -> c_int;

    pub fn botan_x509_crl_load(
        crl: *mut botan_x509_crl_t,
        data: *const u8,
        data_len: usize,
    ) -> c_int;

    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_crl_create(
        crl_obj: *mut botan_x509_crl_t,
        rng: botan_rng_t,
        ca_cert: botan_x509_cert_t,
        ca_key: botan_privkey_t,
        issue_time: u64,
        next_update: u32,
        hash_fn: *const c_char,
        padding: *const c_char,
    ) -> c_int;

    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_crl_update(
        crl_obj: *mut botan_x509_crl_t,
        last_crl: botan_x509_crl_t,
        rng: botan_rng_t,
        ca_cert: botan_x509_cert_t,
        ca_key: botan_privkey_t,
        issue_time: u64,
        next_update: u32,
        revoked: *const botan_x509_cert_t,
        revoked_len: usize,
        reason: u8,
        hash_fn: *const c_char,
        padding: *const c_char,
    ) -> c_int;

    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_crl_get_count(crl: botan_x509_crl_t, count: *mut usize) -> c_int;

    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_crl_get_entry(
        crl: botan_x509_crl_t,
        i: usize,
        serial: botan_mp_t,
        expire_time: *mut u64,
        reason: *mut u8,
    ) -> c_int;

    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_crl_verify_signature(
        crl: botan_x509_crl_t,
        key: botan_pubkey_t,
        result: *mut c_int,
    ) -> c_int;

    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_crl_view_pem(
        crl: botan_x509_crl_t,
        view_ctx: botan_view_ctx,
        view_fn: botan_view_str_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20251104)]
    pub fn botan_x509_crl_view_der(
        crl: botan_x509_crl_t,
        view_ctx: botan_view_ctx,
        view_fn: botan_view_bin_fn,
    ) -> c_int;

    pub fn botan_x509_crl_destroy(crl: botan_x509_crl_t) -> c_int;

    pub fn botan_x509_is_revoked(crl: botan_x509_crl_t, cert: botan_x509_cert_t) -> c_int;

    pub fn botan_x509_cert_verify_with_crl(
        validation_result: *mut c_int,
        cert: botan_x509_cert_t,
        intermediates: *const botan_x509_cert_t,
        intermediates_len: usize,
        trusted: *const botan_x509_cert_t,
        trusted_len: usize,
        crls: *const botan_x509_crl_t,
        crls_len: usize,
        trusted_path: *const c_char,
        required_strength: usize,
        hostname: *const c_char,
        reference_time: u64,
    ) -> c_int;
}
