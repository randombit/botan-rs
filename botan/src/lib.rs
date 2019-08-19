#![deny(warnings)]

#![warn(missing_docs)]
#![deny(missing_docs)]

//! A wrapper for the Botan cryptography library

#![cfg_attr(feature = "no-std", feature(alloc))]
#![cfg_attr(feature = "no-std", no_std)]

#[cfg(feature = "no-std")]
#[macro_use]
extern crate alloc;

#[cfg(feature = "no-std")]
extern crate cstr_core;

extern crate botan_sys;
extern crate cty;

macro_rules! call_botan {
    ($x:expr) => {
        let rc = unsafe { $x };
        if rc != 0 {
            return Err(Error::from(rc));
        }
    }
}

mod bcrypt;
mod block;
mod cipher;
mod fpe;
mod hash;
mod keywrap;
mod kdf;
mod mac;
mod memutils;
mod mp;
mod otp;
mod pbkdf;
mod pk_ops;
mod pubkey;
mod rng;
mod x509;
mod version;
mod utils;

pub use bcrypt::*;
pub use block::*;
pub use cipher::*;
pub use fpe::*;
pub use hash::*;
pub use kdf::*;
pub use keywrap::*;
pub use mac::*;
pub use memutils::*;
pub use crate::mp::*;
pub use otp::*;
pub use pbkdf::*;
pub use pk_ops::*;
pub use pubkey::*;
pub use crate::rng::*;
pub use x509::*;
pub use version::*;
pub use crate::utils::*;
