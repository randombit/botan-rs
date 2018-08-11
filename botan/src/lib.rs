#![warn(missing_docs)]
//#![deny(warnings)]
#![deny(missing_docs)]

//! A wrapper for the Botan cryptography library

extern crate botan_sys;

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
mod hash;
mod kdf;
mod mac;
mod memutils;
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
pub use hash::*;
pub use kdf::*;
pub use mac::*;
pub use memutils::*;
pub use pbkdf::*;
pub use pk_ops::*;
pub use pubkey::*;
pub use rng::*;
pub use x509::*;
pub use version::*;
pub use utils::*;
