#[cfg(botan_ffi_20250506)]
use crate::ffi_types::{botan_view_ctx, botan_view_str_fn, c_char, c_int};

#[cfg(botan_ffi_20250506)]
pub enum botan_asn1_oid_struct {}

#[cfg(botan_ffi_20250506)]
pub type botan_asn1_oid_t = *mut botan_asn1_oid_struct;

#[cfg(botan_ffi_20250506)]
extern "C" {
    pub fn botan_oid_destroy(bc: botan_asn1_oid_t) -> c_int;

    pub fn botan_oid_from_string(oid: *mut botan_asn1_oid_t, oid_str: *const c_char) -> c_int;

    pub fn botan_oid_register(oid: botan_asn1_oid_t, name: *const c_char) -> c_int;

    pub fn botan_oid_view_string(
        oid: botan_asn1_oid_t,
        ctx: botan_view_ctx,
        view_fn: botan_view_str_fn,
    ) -> c_int;

    pub fn botan_oid_view_name(
        oid: botan_asn1_oid_t,
        ctx: botan_view_ctx,
        view_fn: botan_view_str_fn,
    ) -> c_int;

    pub fn botan_oid_equal(oid1: botan_asn1_oid_t, oid2: botan_asn1_oid_t) -> c_int;

    pub fn botan_oid_cmp(
        result: *mut c_int,
        oid1: botan_asn1_oid_t,
        oid2: botan_asn1_oid_t,
    ) -> c_int;
}
