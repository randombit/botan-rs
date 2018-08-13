use botan_sys::*;

pub(crate) use std::os::raw::{c_char, c_int, c_void};
pub(crate) use std::ffi::{CStr, CString};
pub(crate) use std::ptr;
pub(crate) use std::mem;

/// The result of calling an operation on the library
pub type Result<T> = ::std::result::Result<T, Error>;

pub(crate) fn make_cstr(input: &str) -> Result<CString> {
    let cstr = CString::new(input).map_err(|_| Error::ConversionError)?;
    Ok(cstr)
}

pub(crate) fn call_botan_ffi_returning_vec_u8(
    initial_size: usize,
    cb: &Fn(*mut u8, *mut usize) -> c_int) -> Result<Vec<u8>> {

    let mut output = vec![0; initial_size];
    let mut out_len = output.len();

    let rc = cb(output.as_mut_ptr(), &mut out_len);
    if rc == 0 {
        assert!(out_len <= output.len());
        output.resize(out_len, 0);
        return Ok(output);
    }
    else if rc != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE {
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

pub(crate) fn call_botan_ffi_returning_string(
    initial_size: usize,
    cb: &Fn(*mut u8, *mut usize) -> c_int) -> Result<String> {

    let v = call_botan_ffi_returning_vec_u8(initial_size, cb)?;

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
    /// An key of invalid length was provided
    InvalidKeyLength,
    /// An object was invoked without the key being set
    KeyNotSet,
    /// Some functionality is not implemented in the current library version
    NotImplemented,
    /// A null pointer was incorrectly provided
    NullPointer,
    /// Memory exhaustion
    OutOfMemory,
    /// Some unknown error occurred
    UnknownError,
    /// An error occured while converting data to C
    ConversionError
}

impl From<i32> for Error {
    fn from(err: i32) -> Error {
        match err {
            BOTAN_FFI_ERROR_BAD_FLAG => Error::BadFlag,
            BOTAN_FFI_ERROR_BAD_MAC => Error::BadAuthCode,
            BOTAN_FFI_ERROR_BAD_PARAMETER => Error::BadParameter,
            BOTAN_FFI_ERROR_EXCEPTION_THROWN => Error::ExceptionThrown,
            BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE => Error::InsufficientBufferSpace,
            BOTAN_FFI_ERROR_INVALID_INPUT => Error::InvalidInput,
            BOTAN_FFI_ERROR_INVALID_KEY_LENGTH => Error::InvalidKeyLength,
            BOTAN_FFI_ERROR_INVALID_OBJECT => Error::InvalidObject,
            BOTAN_FFI_ERROR_KEY_NOT_SET => Error::KeyNotSet,
            BOTAN_FFI_ERROR_NOT_IMPLEMENTED => Error::NotImplemented,
            BOTAN_FFI_ERROR_NULL_POINTER => Error::NullPointer,
            BOTAN_FFI_ERROR_OUT_OF_MEMORY => Error::OutOfMemory,
            BOTAN_FFI_ERROR_UNKNOWN_ERROR => Error::UnknownError,
            BOTAN_FFI_INVALID_VERIFIER => Error::InvalidVerifier,
            _ => Error::UnknownError,
        }
    }
}

/// Specifies valid keylengths for symmetric ciphers/MACs
pub struct KeySpec {
    min_keylen: usize,
    max_keylen: usize,
    mod_keylen: usize,
}

impl KeySpec {

    pub(crate) fn new(min_keylen: usize, max_keylen: usize, mod_keylen: usize) -> KeySpec {
        assert!(min_keylen <= max_keylen);
        assert!(mod_keylen > 0);
        KeySpec { min_keylen, max_keylen, mod_keylen }
    }

    /// Return true if the specified key length is valid for this object
    pub fn is_valid_keylength(&self, keylen: usize) -> bool {
        (keylen >= self.min_keylen &&
         keylen <= self.max_keylen &&
         keylen % self.mod_keylen == 0)
    }

    /// Return the minimum supported keylength
    pub fn minimum_keylength(&self) -> usize {
        self.min_keylen
    }

    /// Return the maximum supported keylength
    pub fn maximum_keylength(&self) -> usize {
        self.max_keylen
    }

    /// Return the required multiple of the keylength
    ///
    /// That is each key must be N*keylength_multiple() for some N
    pub fn keylength_multiple(&self) -> usize {
        self.mod_keylen
    }

}
