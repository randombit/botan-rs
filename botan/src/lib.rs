#![warn(missing_docs)]
#![deny(missing_docs)]
#![allow(unused_imports)]

//! A wrapper for the Botan cryptography library
//!
//! # Linking to Botan
//!
//! By default the crate links against an installed Botan shared library
//! (or a static library with the `static` feature, or one built from source
//! with the `vendored` feature). Which functions the Botan headers declare
//! is detected at build time.
//!
//! With the `dynamic-loading` feature nothing is linked at build time and no
//! Botan installation is required to build. Instead the Botan shared library
//! is located and loaded the first time it is needed (see `load_library`
//! for how to control this), and functions are resolved from it as they are
//! used. This means an application can be built once and pick up newer
//! features when run against a newer Botan, without being rebuilt.
//!
//! # Availability of newer APIs
//!
//! Every wrapper in this crate exists regardless of the version of Botan it
//! is built or run against. When an operation requires a function that the
//! Botan library in use does not provide, an error of type
//! [`ErrorType::NotImplemented`] is returned and [`Error::is_function_unavailable`]
//! returns true. The documentation of each affected item notes the minimum
//! version of Botan required. [`Version::current`] and
//! [`Version::supports_version`] report on the library in use.

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
            Err(Error::from_named_rc(core::stringify!($fn), rc))
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
            Err(Error::from_named_rc(core::stringify!($fn), rc))
        }
    }};
    ($fn:path, $($args:expr),*) => {{
        let mut obj = ptr::null_mut();
        let rc = unsafe { $fn(&mut obj, $($args),*) };
        if rc == 0 {
            Ok(obj)
        } else {
            Err(Error::from_named_rc(core::stringify!($fn), rc))
        }
    }};
}

/// `botan_init_at!(func, before ; after)`
///
/// `;` specifies the point at which the `out_t*` pointer is inserted
#[allow(unused)]
macro_rules! botan_init_at {
    ($fn:path, $($before:expr),* ; $($after:expr),*) => {{
        let mut obj = ptr::null_mut();
        let rc = unsafe {
            $fn($($before,)* &mut obj $(, $after)*)
        };
        if rc == 0 {
            Ok(obj)
        } else {
            Err(Error::from_named_rc(core::stringify!($fn), rc))
        }
    }};
}

macro_rules! botan_impl_drop {
    ($typ:ty, $fn:path) => {
        impl Drop for $typ {
            fn drop(&mut self) {
                let rc = unsafe { $fn(self.obj) };
                if rc != 0 {
                    let err = Error::from_named_rc(core::stringify!($fn), rc);
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
            Err(Error::from_named_rc(core::stringify!($fn), rc))
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
            Err(Error::from_named_rc(core::stringify!($fn), rc))
        } else {
            Ok((val1, val2, val3))
        }
    }};
}

/// `botan_view_vec!(func, args...)` invokes a Botan 3.0+ "view" function,
/// which returns its output through a callback, and returns it as a `Vec<u8>`.
/// The view context and callback are appended to the provided arguments.
macro_rules! botan_view_vec {
    ($fn:path $(, $args:expr)*) => {
        crate::utils::call_botan_ffi_viewing_vec_u8(core::stringify!($fn), &|ctx, cb| unsafe {
            $fn($($args,)* ctx, cb)
        })
    };
}

/// Like `botan_view_vec!` but for view functions returning a string
macro_rules! botan_view_str {
    ($fn:path $(, $args:expr)*) => {
        crate::utils::call_botan_ffi_viewing_str_fn(core::stringify!($fn), &|ctx, cb| unsafe {
            $fn($($args,)* ctx, cb)
        })
    };
}

macro_rules! botan_bool_in_rc {
    ($fn:path, $($args:expr),*) => {{
        let rc = unsafe { $fn($($args),*) };

        match rc {
            0 => Ok(false),
            1 => Ok(true),
            e => Err(Error::from_named_rc(core::stringify!($fn), e)),
        }
    }};
}

mod algo;
mod asn1;
mod bcrypt;
mod block;
mod cipher;
mod ec_group;
mod ec_point;
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
mod zfec;

pub use algo::*;
pub use asn1::*;
pub use bcrypt::*;
pub use block::*;
pub use cipher::*;
pub use ec_group::*;
pub use ec_point::*;
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
pub use zfec::*;

mod pk_ops_kem;
mod spake2p;

pub use pk_ops_kem::*;
pub use spake2p::*;

#[cfg(feature = "dynamic-loading")]
mod dynamic_loading;

#[cfg(feature = "dynamic-loading")]
pub use dynamic_loading::*;
