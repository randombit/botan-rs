#[cfg(botan_ffi_20250506)]
use crate::ffi_types::{botan_view_bin_fn, botan_view_ctx, botan_view_str_fn, c_char, c_int};
#[cfg(botan_ffi_20250506)]
use crate::{botan_asn1_oid_t, botan_mp_t};

#[cfg(botan_ffi_20260506)]
use crate::rng::botan_rng_t;

#[cfg(botan_ffi_20250506)]
pub enum botan_ec_group_struct {}

#[cfg(botan_ffi_20250506)]
pub type botan_ec_group_t = *mut botan_ec_group_struct;

#[cfg(botan_ffi_20260506)]
pub enum botan_ec_scalar_struct {}
#[cfg(botan_ffi_20260506)]
pub type botan_ec_scalar_t = *mut botan_ec_scalar_struct;

#[cfg(botan_ffi_20260506)]
pub enum botan_ec_point_struct {}
#[cfg(botan_ffi_20260506)]
pub type botan_ec_point_t = *mut botan_ec_point_struct;

#[cfg(botan_ffi_20250506)]
extern "C" {
    pub fn botan_ec_group_destroy(bc: botan_ec_group_t) -> c_int;

    pub fn botan_ec_group_supports_application_specific_group(res: *mut c_int) -> c_int;

    pub fn botan_ec_group_supports_named_group(name: *const c_char, res: *mut c_int) -> c_int;

    pub fn botan_ec_group_from_params(
        group: *mut botan_ec_group_t,
        oid: botan_asn1_oid_t,
        p: botan_mp_t,
        a: botan_mp_t,
        b: botan_mp_t,
        g_x: botan_mp_t,
        g_y: botan_mp_t,
        order: botan_mp_t,
    ) -> c_int;

    pub fn botan_ec_group_from_ber(
        group: *mut botan_ec_group_t,
        ber: *const u8,
        ber_len: usize,
    ) -> c_int;
    pub fn botan_ec_group_from_pem(group: *mut botan_ec_group_t, pem: *const c_char) -> c_int;
    pub fn botan_ec_group_from_oid(group: *mut botan_ec_group_t, oid: botan_asn1_oid_t) -> c_int;
    pub fn botan_ec_group_from_name(group: *mut botan_ec_group_t, name: *const c_char) -> c_int;

    pub fn botan_ec_group_view_der(
        group: botan_ec_group_t,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;
    pub fn botan_ec_group_view_pem(
        group: botan_ec_group_t,
        ctx: botan_view_ctx,
        view: botan_view_str_fn,
    ) -> c_int;
    pub fn botan_ec_group_get_curve_oid(
        oid: *mut botan_asn1_oid_t,
        group: botan_ec_group_t,
    ) -> c_int;
    pub fn botan_ec_group_get_p(p: *mut botan_mp_t, group: botan_ec_group_t) -> c_int;

    pub fn botan_ec_group_get_a(a: *mut botan_mp_t, group: botan_ec_group_t) -> c_int;

    pub fn botan_ec_group_get_b(b: *mut botan_mp_t, group: botan_ec_group_t) -> c_int;

    pub fn botan_ec_group_get_g_x(g_x: *mut botan_mp_t, group: botan_ec_group_t) -> c_int;

    pub fn botan_ec_group_get_g_y(g_y: *mut botan_mp_t, group: botan_ec_group_t) -> c_int;

    pub fn botan_ec_group_get_order(order: *mut botan_mp_t, group: botan_ec_group_t) -> c_int;

    pub fn botan_ec_group_equal(group1: botan_ec_group_t, group2: botan_ec_group_t) -> c_int;

    #[cfg(botan_ffi_20260303)]
    pub fn botan_ec_group_unregister(oid: botan_asn1_oid_t) -> c_int;
}

#[cfg(botan_ffi_20260506)]
extern "C" {
    pub fn botan_ec_scalar_destroy(ec_scalar: botan_ec_scalar_t) -> c_int;

    pub fn botan_ec_scalar_random(
        ec_scalar: *mut botan_ec_scalar_t,
        ec_group: botan_ec_group_t,
        rng: botan_rng_t,
    ) -> c_int;

    pub fn botan_ec_scalar_from_mp(
        ec_scalar: *mut botan_ec_scalar_t,
        ec_group: botan_ec_group_t,
        mp: botan_mp_t,
    ) -> c_int;

    pub fn botan_ec_scalar_to_mp(ec_scalar: botan_ec_scalar_t, mp: *mut botan_mp_t) -> c_int;

    pub fn botan_ec_point_destroy(ec_point: botan_ec_point_t) -> c_int;

    pub fn botan_ec_point_identity(
        ec_point: *mut botan_ec_point_t,
        ec_group: botan_ec_group_t,
    ) -> c_int;

    pub fn botan_ec_point_generator(
        ec_point: *mut botan_ec_point_t,
        ec_group: botan_ec_group_t,
    ) -> c_int;

    pub fn botan_ec_point_from_xy(
        ec_point: *mut botan_ec_point_t,
        ec_group: botan_ec_group_t,
        x: botan_mp_t,
        y: botan_mp_t,
    ) -> c_int;

    pub fn botan_ec_point_from_bytes(
        ec_point: *mut botan_ec_point_t,
        ec_group: botan_ec_group_t,
        bytes: *const u8,
        bytes_len: usize,
    ) -> c_int;

    pub fn botan_ec_point_view_x_bytes(
        ec_point: botan_ec_point_t,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    pub fn botan_ec_point_view_y_bytes(
        ec_point: botan_ec_point_t,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    pub fn botan_ec_point_view_xy_bytes(
        ec_point: botan_ec_point_t,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    pub fn botan_ec_point_view_uncompressed(
        ec_point: botan_ec_point_t,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    pub fn botan_ec_point_view_compressed(
        ec_point: botan_ec_point_t,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    pub fn botan_ec_point_is_identity(ec_point: botan_ec_point_t) -> c_int;

    pub fn botan_ec_point_equal(x: botan_ec_point_t, y: botan_ec_point_t) -> c_int;

    pub fn botan_ec_point_negate(
        result: *mut botan_ec_point_t,
        ec_point: botan_ec_point_t,
    ) -> c_int;

    pub fn botan_ec_point_add(
        result: *mut botan_ec_point_t,
        x: botan_ec_point_t,
        y: botan_ec_point_t,
    ) -> c_int;

    pub fn botan_ec_point_mul(
        result: *mut botan_ec_point_t,
        ec_point: botan_ec_point_t,
        ec_scalar: botan_ec_scalar_t,
        rng: botan_rng_t,
    ) -> c_int;
}
