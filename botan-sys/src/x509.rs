use crate::ffi_types::*;

use crate::pubkey::{botan_privkey_t, botan_pubkey_t};
use crate::rng::botan_rng_t;

#[cfg(botan_ffi_20260303)]
use crate::mp::botan_mp_t;

#[cfg(botan_ffi_20260303)]
use crate::oid::botan_asn1_oid_t;

pub enum botan_x509_cert_struct {}
pub type botan_x509_cert_t = *mut botan_x509_cert_struct;

pub enum botan_x509_crl_struct {}
pub type botan_x509_crl_t = *mut botan_x509_crl_struct;

#[cfg(botan_ffi_20260303)]
pub enum botan_x509_crl_entry_struct {}
#[cfg(botan_ffi_20260303)]
pub type botan_x509_crl_entry_t = *mut botan_x509_crl_entry_struct;

#[cfg(botan_ffi_20260303)]
pub enum botan_x509_general_name_struct {}
#[cfg(botan_ffi_20260303)]
pub type botan_x509_general_name_t = *mut botan_x509_general_name_struct;

#[repr(u32)]
#[allow(clippy::upper_case_acronyms)]
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

#[cfg(botan_ffi_20260303)]
#[repr(i32)]
pub enum X509ValueType {
    BOTAN_X509_SERIAL_NUMBER = 0,
    BOTAN_X509_SUBJECT_DN_BITS = 1,
    BOTAN_X509_ISSUER_DN_BITS = 2,
    BOTAN_X509_SUBJECT_KEY_IDENTIFIER = 3,
    BOTAN_X509_AUTHORITY_KEY_IDENTIFIER = 4,
    BOTAN_X509_PUBLIC_KEY_PKCS8_BITS = 200,
    BOTAN_X509_TBS_DATA_BITS = 201,
    BOTAN_X509_SIGNATURE_SCHEME_BITS = 202,
    BOTAN_X509_SIGNATURE_BITS = 203,
    BOTAN_X509_DER_ENCODING = 300,
    BOTAN_X509_PEM_ENCODING = 301,
    BOTAN_X509_CRL_DISTRIBUTION_URLS = 400,
    BOTAN_X509_OCSP_RESPONDER_URLS = 401,
    BOTAN_X509_CA_ISSUERS_URLS = 402,
}

#[cfg(botan_ffi_20260303)]
#[repr(i32)]
pub enum X509GeneralNameType {
    BOTAN_X509_OTHER_NAME = 0,
    BOTAN_X509_EMAIL_ADDRESS = 1,
    BOTAN_X509_DNS_NAME = 2,
    BOTAN_X509_DIRECTORY_NAME = 4,
    BOTAN_X509_URI = 6,
    BOTAN_X509_IP_ADDRESS = 7,
}

#[cfg(botan_ffi_20260303)]
#[repr(i32)]
pub enum X509CrlReasonCode {
    BOTAN_CRL_ENTRY_UNSPECIFIED = 0,
    BOTAN_CRL_ENTRY_KEY_COMPROMISE = 1,
    BOTAN_CRL_ENTRY_CA_COMPROMISE = 2,
    BOTAN_CRL_ENTRY_AFFILIATION_CHANGED = 3,
    BOTAN_CRL_ENTRY_SUPERSEDED = 4,
    BOTAN_CRL_ENTRY_CESSATION_OF_OPERATION = 5,
    BOTAN_CRL_ENTRY_CERTIFICATE_HOLD = 6,
    BOTAN_CRL_ENTRY_REMOVE_FROM_CRL = 8,
    BOTAN_CRL_ENTRY_PRIVILEGE_WITHDRAWN = 9,
    BOTAN_CRL_ENTRY_AA_COMPROMISE = 10,
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

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_view_binary_values(
        cert: botan_x509_cert_t,
        value_type: c_int,
        index: usize,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_view_binary_values_count(
        cert: botan_x509_cert_t,
        value_type: c_int,
        count: *mut usize,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_view_string_values(
        cert: botan_x509_cert_t,
        value_type: c_int,
        index: usize,
        ctx: botan_view_ctx,
        view: botan_view_str_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_view_string_values_count(
        cert: botan_x509_cert_t,
        value_type: c_int,
        count: *mut usize,
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

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_serial_number(
        cert: botan_x509_cert_t,
        serial_number: *mut botan_mp_t,
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
    pub fn botan_x509_cert_get_public_key_bits(
        cert: botan_x509_cert_t,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;

    #[cfg(botan_ffi_20230403)]
    pub fn botan_x509_cert_view_public_key_bits(
        cert: botan_x509_cert_t,
        view_ctx: botan_view_ctx,
        view_fn: botan_view_bin_fn,
    ) -> c_int;

    pub fn botan_x509_cert_get_public_key(
        cert: botan_x509_cert_t,
        key: *mut botan_pubkey_t,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_is_ca(cert: botan_x509_cert_t) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_get_path_length_constraint(
        cert: botan_x509_cert_t,
        path_limit: *mut usize,
    ) -> c_int;

    pub fn botan_x509_cert_get_issuer_dn(
        cert: botan_x509_cert_t,
        key: *const c_char,
        index: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_get_issuer_dn_count(
        cert: botan_x509_cert_t,
        key: *const c_char,
        count: *mut usize,
    ) -> c_int;

    pub fn botan_x509_cert_get_subject_dn(
        cert: botan_x509_cert_t,
        key: *const c_char,
        index: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_get_subject_dn_count(
        cert: botan_x509_cert_t,
        key: *const c_char,
        count: *mut usize,
    ) -> c_int;

    pub fn botan_x509_cert_to_string(
        cert: botan_x509_cert_t,
        out: *mut c_char,
        out_len: *mut usize,
    ) -> c_int;

    #[cfg(botan_ffi_20230403)]
    pub fn botan_x509_cert_view_as_string(
        cert: botan_x509_cert_t,
        view_ctx: botan_view_ctx,
        view_fn: botan_view_str_fn,
    ) -> c_int;

    pub fn botan_x509_cert_allowed_usage(cert: botan_x509_cert_t, key_usage: c_uint) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_allowed_extended_usage_str(
        cert: botan_x509_cert_t,
        oid: *const c_char,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_allowed_extended_usage_oid(
        cert: botan_x509_cert_t,
        oid: botan_asn1_oid_t,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_general_name_get_type(
        name: botan_x509_general_name_t,
        name_type: *mut c_uint,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_general_name_view_string_value(
        name: botan_x509_general_name_t,
        ctx: botan_view_ctx,
        view: botan_view_str_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_general_name_view_binary_value(
        name: botan_x509_general_name_t,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_general_name_destroy(alt_names: botan_x509_general_name_t) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_permitted_name_constraints(
        cert: botan_x509_cert_t,
        index: usize,
        constraint: *mut botan_x509_general_name_t,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_permitted_name_constraints_count(
        cert: botan_x509_cert_t,
        count: *mut usize,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_excluded_name_constraints(
        cert: botan_x509_cert_t,
        index: usize,
        constraint: *mut botan_x509_general_name_t,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_excluded_name_constraints_count(
        cert: botan_x509_cert_t,
        count: *mut usize,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_subject_alternative_names(
        cert: botan_x509_cert_t,
        index: usize,
        alt_name: *mut botan_x509_general_name_t,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_subject_alternative_names_count(
        cert: botan_x509_cert_t,
        count: *mut usize,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_issuer_alternative_names(
        cert: botan_x509_cert_t,
        index: usize,
        alt_name: *mut botan_x509_general_name_t,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_cert_issuer_alternative_names_count(
        cert: botan_x509_cert_t,
        count: *mut usize,
    ) -> c_int;

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

    pub fn botan_x509_crl_load_file(crl: *mut botan_x509_crl_t, file_path: *const c_char) -> c_int;

    pub fn botan_x509_crl_load(
        crl: *mut botan_x509_crl_t,
        data: *const u8,
        data_len: usize,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_crl_this_update(crl: botan_x509_crl_t, time_since_epoch: *mut u64) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_crl_next_update(crl: botan_x509_crl_t, time_since_epoch: *mut u64) -> c_int;

    #[cfg(botan_ffi_20260303)]
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

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_crl_entry_create(
        entry: *mut botan_x509_crl_entry_t,
        cert: botan_x509_cert_t,
        reason_code: c_int,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_crl_update(
        crl_obj: *mut botan_x509_crl_t,
        last_crl: botan_x509_crl_t,
        rng: botan_rng_t,
        ca_cert: botan_x509_cert_t,
        ca_key: botan_privkey_t,
        issue_time: u64,
        next_update: u32,
        new_entries: *const botan_x509_crl_entry_t,
        new_entries_len: usize,
        hash_fn: *const c_char,
        padding: *const c_char,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_crl_verify_signature(crl: botan_x509_crl_t, key: botan_pubkey_t) -> c_int;

    pub fn botan_x509_crl_destroy(crl: botan_x509_crl_t) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_crl_view_binary_values(
        crl_obj: botan_x509_crl_t,
        value_type: c_int,
        index: usize,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_crl_view_binary_values_count(
        crl_obj: botan_x509_crl_t,
        value_type: c_int,
        count: *mut usize,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_crl_view_string_values(
        crl_obj: botan_x509_crl_t,
        value_type: c_int,
        index: usize,
        ctx: botan_view_ctx,
        view: botan_view_str_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_crl_view_string_values_count(
        crl_obj: botan_x509_crl_t,
        value_type: c_int,
        count: *mut usize,
    ) -> c_int;

    pub fn botan_x509_is_revoked(crl: botan_x509_crl_t, cert: botan_x509_cert_t) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_crl_entries(
        crl: botan_x509_crl_t,
        index: usize,
        entry: *mut botan_x509_crl_entry_t,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_crl_entries_count(crl: botan_x509_crl_t, count: *mut usize) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_crl_entry_reason(
        entry: botan_x509_crl_entry_t,
        reason_code: *mut c_int,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_crl_entry_revocation_date(
        entry: botan_x509_crl_entry_t,
        time_since_epoch: *mut u64,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_crl_entry_serial_number(
        entry: botan_x509_crl_entry_t,
        serial_number: *mut botan_mp_t,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_crl_entry_view_serial_number(
        entry: botan_x509_crl_entry_t,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_x509_crl_entry_destroy(entry: botan_x509_crl_entry_t) -> c_int;

    pub fn botan_x509_cert_verify_with_crl(
        validation_result: *mut c_int,
        ee_cert: botan_x509_cert_t,
        intermediates: *const botan_x509_cert_t,
        intermediates_len: usize,
        trusted: *const botan_x509_cert_t,
        trusted_len: usize,
        crls: *const botan_x509_crl_t,
        crls_len: usize,
        trusted_path: *const c_char,
        required_key_strength: usize,
        hostname: *const c_char,
        reference_time: u64,
    ) -> c_int;
}
