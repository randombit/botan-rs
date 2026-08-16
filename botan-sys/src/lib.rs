#![no_std]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]

#[macro_use]
mod macros;

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
mod spake2p;
mod srp6;
mod tpm2;
mod utils;
mod version;
mod x509;
mod xof;
mod zfec;

pub mod ffi_types {
    pub use core::ffi::{c_char, c_int, c_uint, c_void};

    pub type botan_view_ctx = *mut c_void;

    pub type botan_view_bin_fn =
        extern "C" fn(view_ctx: botan_view_ctx, data: *const u8, len: usize) -> c_int;

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
pub use spake2p::*;
pub use srp6::*;
pub use tpm2::*;
pub use utils::*;
pub use version::*;
pub use x509::*;
pub use xof::*;
pub use zfec::*;

/// Returns a description of why the Botan library could not be loaded
///
/// This is only ever `Some` when the `dynamic-loading` feature is enabled and
/// loading the Botan shared library failed; in the linked build modes it
/// always returns `None`.
pub fn last_load_error() -> Option<&'static str> {
    None
}
