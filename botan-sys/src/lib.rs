#![allow(non_camel_case_types)]
#![cfg_attr(feature = "no-std", no_std)]

mod block;
mod cipher;
mod errors;
mod fpe;
mod hash;
mod kdf;
mod keywrap;
mod mac;
mod mp;
mod otp;
mod passhash;
mod pk_ops;
mod pubkey;
mod rng;
mod utils;
mod version;
mod x509;
mod zfec;

pub mod ffi_types {
    #[cfg(feature = "no-std")]
    pub use core::ffi::{c_char, c_int, c_uint, c_void};

    #[cfg(not(feature = "no-std"))]
    pub use std::os::raw::{c_char, c_int, c_uint, c_void};

    #[cfg(feature = "botan3")]
    pub type botan_view_ctx = *mut c_void;

    #[cfg(feature = "botan3")]
    pub type botan_view_bin_fn =
        extern "C" fn(view_ctx: botan_view_ctx, data: *const u8, len: usize) -> c_int;

    #[cfg(feature = "botan3")]
    pub type botan_view_str_fn =
        extern "C" fn(view_ctx: botan_view_ctx, data: *const c_char, len: usize) -> c_int;
}

pub use block::*;
pub use cipher::*;
pub use errors::*;
pub use fpe::*;
pub use hash::*;
pub use kdf::*;
pub use keywrap::*;
pub use mac::*;
pub use mp::*;
pub use otp::*;
pub use passhash::*;
pub use pk_ops::*;
pub use pubkey::*;
pub use rng::*;
pub use utils::*;
pub use version::*;
pub use x509::*;
pub use zfec::*;
