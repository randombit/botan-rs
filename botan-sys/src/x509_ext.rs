#[cfg(botan_ffi_20251104)]
use crate::{botan_x509_cert_t, ffi_types::*};

#[cfg(botan_ffi_20251104)]
pub enum botan_x509_ext_as_blocks_struct {}
#[cfg(botan_ffi_20251104)]
pub type botan_x509_ext_as_blocks_t = *mut botan_x509_ext_as_blocks_struct;

#[cfg(botan_ffi_20251104)]
pub enum botan_x509_ext_ip_addr_blocks_struct {}
#[cfg(botan_ffi_20251104)]
pub type botan_x509_ext_ip_addr_blocks_t = *mut botan_x509_ext_ip_addr_blocks_struct;

#[cfg(botan_ffi_20251104)]
extern "C" {
    pub fn botan_x509_ext_ip_addr_blocks_destroy(
        ip_addr_blocks: botan_x509_ext_ip_addr_blocks_t,
    ) -> c_int;
    pub fn botan_x509_ext_as_blocks_destroy(as_blocks: botan_x509_ext_as_blocks_t) -> c_int;
    pub fn botan_x509_ext_ip_addr_blocks_create(
        ip_addr_blocks: *mut botan_x509_ext_ip_addr_blocks_t,
    ) -> c_int;
    pub fn botan_x509_ext_ip_addr_blocks_create_from_cert(
        ip_addr_blocks: *mut botan_x509_ext_ip_addr_blocks_t,
        cert: botan_x509_cert_t,
    ) -> c_int;
    pub fn botan_x509_ext_ip_addr_blocks_add_ip_addr(
        ip_addr_blocks: botan_x509_ext_ip_addr_blocks_t,
        min: *const u8,
        max: *const u8,
        ipv6: c_int,
        safi: *const u8,
    ) -> c_int;
    pub fn botan_x509_ext_ip_addr_blocks_restrict(
        ip_addr_blocks: botan_x509_ext_ip_addr_blocks_t,
        ipv6: c_int,
        safi: *const u8,
    ) -> c_int;
    pub fn botan_x509_ext_ip_addr_blocks_inherit(
        ip_addr_blocks: botan_x509_ext_ip_addr_blocks_t,
        ipv6: c_int,
        safi: *const u8,
    ) -> c_int;
    pub fn botan_x509_ext_ip_addr_blocks_get_counts(
        ip_addr_blocks: botan_x509_ext_ip_addr_blocks_t,
        v4_count: *mut usize,
        v6_count: *mut usize,
    ) -> c_int;
    pub fn botan_x509_ext_ip_addr_blocks_get_family(
        ip_addr_blocks: botan_x509_ext_ip_addr_blocks_t,
        ipv6: c_int,
        i: usize,
        has_safi: *mut c_int,
        safi: *mut u8,
        present: *mut c_int,
        count: *mut usize,
    ) -> c_int;
    pub fn botan_x509_ext_ip_addr_blocks_get_address(
        ip_addr_blocks: botan_x509_ext_ip_addr_blocks_t,
        ipv6: c_int,
        i: usize,
        entry: usize,
        min_out: *mut u8,
        max_out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;

    pub fn botan_x509_ext_as_blocks_create(as_blocks: *mut botan_x509_ext_as_blocks_t) -> c_int;
    pub fn botan_x509_ext_as_blocks_create_from_cert(
        as_blocks: *mut botan_x509_ext_as_blocks_t,
        cert: botan_x509_cert_t,
    ) -> c_int;
    pub fn botan_x509_ext_as_blocks_add_asnum(
        as_blocks: botan_x509_ext_as_blocks_t,
        min: u32,
        max: u32,
    ) -> c_int;
    pub fn botan_x509_ext_as_blocks_restrict_asnum(as_blocks: botan_x509_ext_as_blocks_t) -> c_int;
    pub fn botan_x509_ext_as_blocks_inherit_asnum(as_blocks: botan_x509_ext_as_blocks_t) -> c_int;
    pub fn botan_x509_ext_as_blocks_add_rdi(
        as_blocks: botan_x509_ext_as_blocks_t,
        min: u32,
        max: u32,
    ) -> c_int;
    pub fn botan_x509_ext_as_blocks_restrict_rdi(as_blocks: botan_x509_ext_as_blocks_t) -> c_int;
    pub fn botan_x509_ext_as_blocks_inherit_rdi(as_blocks: botan_x509_ext_as_blocks_t) -> c_int;
    pub fn botan_x509_ext_as_blocks_get_asnum(
        as_blocks: botan_x509_ext_as_blocks_t,
        present: *mut c_int,
        count: *mut usize,
    ) -> c_int;
    pub fn botan_x509_ext_as_blocks_get_asnum_at(
        as_blocks: botan_x509_ext_as_blocks_t,
        i: usize,
        min: *mut u32,
        max: *mut u32,
    ) -> c_int;
    pub fn botan_x509_ext_as_blocks_get_rdi(
        as_blocks: botan_x509_ext_as_blocks_t,
        present: *mut c_int,
        count: *mut usize,
    ) -> c_int;
    pub fn botan_x509_ext_as_blocks_get_rdi_at(
        as_blocks: botan_x509_ext_as_blocks_t,
        i: usize,
        min: *mut u32,
        max: *mut u32,
    ) -> c_int;
}
