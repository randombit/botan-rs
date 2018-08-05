#![warn(missing_docs)]

//! A wrapper for the Botan cryptography library

extern crate botan_sys;

use botan_sys::*;
use std::os::raw::{c_int};
use std::ffi::CStr;

/// The result of calling an operation on the library
pub type Result<T> = ::std::result::Result<T, Error>;

macro_rules! call_botan {
    ($x:expr) => {
        let rc = unsafe { $x };
        if rc != 0 {
            return Err(Error::from(rc));
        }
    }
}

fn call_botan_ffi_returning_vec_u8(cb: &Fn(*mut u8, *mut usize) -> c_int) -> Result<Vec<u8>> {

    let mut output = vec![0; 4096]; // make this initial size configurable?
    let mut out_len = output.len();

    let rc = cb(output.as_mut_ptr(), &mut out_len);
    if rc == 0 {
        assert!(out_len <= output.len());
        output.resize(out_len, 0);
        return Ok(output);
    }
    else if rc != BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE {
        return Err(Error::from(rc));
    }

    output.resize(out_len, 0);
    let rc = cb(output.as_mut_ptr(), &mut out_len);

    if rc != 0 {
        return Err(Error::from(rc));
    }

    output.resize(out_len, 0);
    Ok(output)
}

fn call_botan_ffi_returning_string(cb: &Fn(*mut u8, *mut usize) -> c_int) -> Result<String> {
    let v = call_botan_ffi_returning_vec_u8(cb)?;

    let cstr = CStr::from_bytes_with_nul(&v).map_err(|_| Error::ConversionError)?;
    let ostr = cstr.to_str().map_err(|_| Error::ConversionError)?.to_owned();
    Ok(ostr)
}

#[derive(Clone,Debug,PartialEq)]
/// Possible errors
pub enum Error {
    /// A provided authentication code was incorrect
    BadAuthCode,
    /// A bad flag was passed to the library
    BadFlag,
    /// An invalid parameter was provided to the library
    BadParameter,
    /// An exception was thrown will processing this request
    ExceptionThrown,
    /// There was insufficient buffer space to write the output
    InsufficientBufferSpace,
    /// Something about the input was invalid
    InvalidInput,
    /// An invalid object was provided to the library
    InvalidObject,
    /// A verifier was incorrect
    InvalidVerifier,
    /// Some functionality is not implemented in the current library version
    NotImplemented,
    /// A null pointer was incorrectly provided
    NullPointer,
    /// Some unknown error occurred
    UnknownError,
    /// An error occured while converting data to C
    ConversionError
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

