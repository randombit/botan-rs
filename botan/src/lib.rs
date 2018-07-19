extern crate botan_sys;

use botan_sys::*;
use std::ffi::CString;

pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Clone,Debug)]
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

pub struct HashFunction {
    obj: botan_hash_t
}

impl Drop for HashFunction {
    fn drop(&mut self) {
        unsafe { botan_hash_destroy(self.obj); }
    }
}

impl HashFunction {
    pub fn new(name: &str) -> Result<HashFunction> {

        let mut obj = std::ptr::null_mut();

        let rc = unsafe { botan_hash_init(&mut obj, CString::new(name).unwrap().as_ptr(), 0u32) };
        if rc != 0 {
            return Err(Error::from(rc));
        }

        Ok(HashFunction { obj })
    }

    pub fn output_length(&self) -> Result<usize> {
        let mut output_len = 0;
        let rc = unsafe { botan_hash_output_length(self.obj, &mut output_len) };
        if rc != 0 {
            return Err(Error::from(rc));
        }

        Ok(output_len)
    }
}
