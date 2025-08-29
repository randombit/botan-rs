#![warn(missing_docs)]
#![deny(missing_docs)]
#![allow(unused_imports)]

//! A wrapper for the Botan cryptography library

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

extern crate botan_sys;

macro_rules! botan_call {
    ($fn:path, $($args:expr),*) => {{
        let rc = unsafe { $fn($($args),*) };
        if rc == 0 {
            Ok(())
        } else {
            Err(Error::from_rc(rc))
        }
    }};
}

macro_rules! botan_init {
    ($fn:path) => {{
        let mut obj = ptr::null_mut();
        let rc = unsafe { $fn(&mut obj) };
        if rc == 0 {
            Ok(obj)
        } else {
            Err(Error::from_rc(rc))
        }
    }};
    ($fn:path, $($args:expr),*) => {{
        let mut obj = ptr::null_mut();
        let rc = unsafe { $fn(&mut obj, $($args),*) };
        if rc == 0 {
            Ok(obj)
        } else {
            Err(Error::from_rc(rc))
        }
    }};
}

macro_rules! botan_impl_drop {
    ($typ:ty, $fn:path) => {
        impl Drop for $typ {
            fn drop(&mut self) {
                let rc = unsafe { $fn(self.obj) };
                if rc != 0 {
                    let err = Error::from_rc(rc);
                    panic!("{} failed: {}", core::stringify!($fn), err);
                }
            }
        }
    };
}

macro_rules! botan_usize {
    ($fn:path, $obj:expr) => {{
        let mut val = 0;
        let rc = unsafe { $fn($obj, &mut val) };
        if rc != 0 {
            Err(Error::from_rc(rc))
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
            Err(Error::from_rc(rc))
        } else {
            Ok((val1, val2, val3))
        }
    }};
}

macro_rules! botan_bool_in_rc {
    ($fn:path, $($args:expr),*) => {{
        let rc = unsafe { $fn($($args),*) };

        match rc {
            0 => Ok(false),
            1 => Ok(true),
            e => Err(Error::from_rc(e)),
        }
    }};
}

mod asn1;
mod bcrypt;
mod block;
mod cipher;
mod ec_group;
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
mod x509_cert;
mod x509_crl;
mod x509_ext;
mod zfec;

pub use asn1::*;
pub use bcrypt::*;
pub use block::*;
pub use cipher::*;
pub use ec_group::*;
pub use fpe::*;
pub use hash::*;
pub use kdf::*;
pub use keywrap::*;
pub use mac::*;
pub use memutils::*;
pub use mp::*;
pub use otp::*;
pub use pbkdf::*;
pub use pk_ops::*;
pub use pubkey::*;
pub use rng::*;
pub use utils::*;
pub use version::*;
pub use x509_cert::*;
pub use x509_crl::*;
pub use x509_ext::*;
pub use zfec::*;

#[cfg(botan_ffi_20230403)]
mod pk_ops_kem;

#[cfg(botan_ffi_20230403)]
pub use pk_ops_kem::*;
