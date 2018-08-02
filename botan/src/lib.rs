extern crate botan_sys;

use botan_sys::*;

pub type Result<T> = ::std::result::Result<T, Error>;

macro_rules! call_botan {
    ($x:expr) => {
        let rc = unsafe { $x };
        if rc != 0 {
            return Err(Error::from(rc));
        }
    }
}

#[derive(Clone,Debug,PartialEq)]
pub enum Error {
    BadAuthCode,
    BadFlag,
    BadParameter,
    ExceptionThrown,
    InsufficientBufferSpace,
    InvalidInput,
    InvalidObject,
    InvalidVerifier,
    NotImplemented,
    NullPointer,
    UnknownError,
}

impl From<i32> for Error {
    fn from(err: i32) -> Error {
        match err {
            BOTAN_FFI_ERROR_BOTAN_FFI_INVALID_VERIFIER => Error::InvalidVerifier,
            BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_INVALID_INPUT => Error::InvalidInput,
            BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_BAD_MAC => Error::BadAuthCode,
            BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE => Error::InsufficientBufferSpace,
            BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_EXCEPTION_THROWN => Error::ExceptionThrown,
            BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_BAD_FLAG => Error::BadFlag,
            BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_NULL_POINTER => Error::NullPointer,
            BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_BAD_PARAMETER => Error::BadParameter,
            BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_NOT_IMPLEMENTED => Error::NotImplemented,
            BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_INVALID_OBJECT => Error::InvalidObject,
            BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_UNKNOWN_ERROR => Error::UnknownError,
            _ => Error::UnknownError,
        }
    }
}

mod bcrypt;
mod block;
mod hash;
mod kdf;
mod mac;
mod memutils;
mod pbkdf;
mod rng;
mod version;

pub use bcrypt::*;
pub use block::*;
pub use hash::*;
pub use kdf::*;
pub use mac::*;
pub use memutils::*;
pub use pbkdf::*;
pub use rng::*;
pub use version::*;

