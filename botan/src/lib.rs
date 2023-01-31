#![warn(missing_docs)]
#![deny(missing_docs)]

//! A wrapper for the Botan cryptography library

#![cfg_attr(feature = "no-std", no_std)]

#[cfg(feature = "no-std")]
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
#[cfg(feature="botan3")]
mod srp6;

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
#[cfg(feature="botan3")]
pub use srp6::*;
