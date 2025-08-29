#![no_std]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]

mod block;
mod cipher;
mod ec_group;
mod errors;
mod fpe;
mod hash;
mod kdf;
mod keywrap;
mod mac;
mod mp;
mod oid;
mod otp;
mod passhash;
mod pk_ops;
mod pubkey;
mod rng;
mod utils;
mod version;
mod x509;
mod x509_ext;
mod zfec;

pub mod ffi_types {
    pub use core::ffi::{c_char, c_int, c_uint, c_void};

    #[cfg(botan_ffi_20230403)]
    pub type botan_view_ctx = *mut c_void;

    #[cfg(botan_ffi_20230403)]
    pub type botan_view_bin_fn =
        extern "C" fn(view_ctx: botan_view_ctx, data: *const u8, len: usize) -> c_int;

    #[cfg(botan_ffi_20230403)]
    pub type botan_view_str_fn =
        extern "C" fn(view_ctx: botan_view_ctx, data: *const c_char, len: usize) -> c_int;
}

pub use block::*;
pub use cipher::*;
pub use ec_group::*;
pub use errors::*;
pub use fpe::*;
pub use hash::*;
pub use kdf::*;
pub use keywrap::*;
pub use mac::*;
pub use mp::*;
pub use oid::*;
pub use otp::*;
pub use passhash::*;
pub use pk_ops::*;
pub use pubkey::*;
pub use rng::*;
pub use utils::*;
pub use version::*;
pub use x509::*;
pub use x509_ext::*;
pub use zfec::*;
