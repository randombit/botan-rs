#![warn(missing_docs)]
#![deny(missing_docs)]

//! A wrapper for the Botan cryptography library

#![cfg_attr(feature = "no-std", feature(alloc_prelude))]
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
    };
}

macro_rules! call_botan_destroy {
    ($fn:expr) => {
        let rc = unsafe { $fn };
        if rc != 0 {
            let err = Error::from(rc);
            panic!("{} failed: {}", core::stringify!($fn), err);
        }
    };
}

macro_rules! botan_usize {
    ($fn:path, $obj:expr) => {{
        let mut val = 0;
        let rc = unsafe { $fn($obj, &mut val) };
        if rc != 0 {
            Err(Error::from(rc))
        } else {
            Ok(val)
        }
    }};
}

macro_rules! botan_usize3 {
    ($fn:path, $obj:expr) => {{
        let mut val1 = 0;
        let mut val2 = 0;
        let mut val3 = 0;
        let rc = unsafe { $fn($obj, &mut val1, &mut val2, &mut val3) };
        if rc != 0 {
            Err(Error::from(rc))
        } else {
            Ok((val1, val2, val3))
        }
    }};
}

mod bcrypt;
mod block;
mod cipher;
mod fpe;
mod hash;
mod kdf;
mod keywrap;
mod mac;
mod memutils;
mod mp;
mod otp;
mod pbkdf;
mod pk_ops;
mod pubkey;
mod rng;
mod utils;
mod version;
mod x509;

pub use crate::mp::*;
pub use crate::rng::*;
pub use crate::utils::*;
pub use bcrypt::*;
pub use block::*;
pub use cipher::*;
pub use fpe::*;
pub use hash::*;
pub use kdf::*;
pub use keywrap::*;
pub use mac::*;
pub use memutils::*;
pub use otp::*;
pub use pbkdf::*;
pub use pk_ops::*;
pub use pubkey::*;
pub use version::*;
pub use x509::*;
