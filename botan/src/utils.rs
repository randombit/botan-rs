use botan_sys::*;
use core::fmt;

#[cfg(feature = "no-std")]
pub(crate) use alloc::{borrow::ToOwned, string::String, string::ToString, vec::Vec};

#[cfg(feature = "no-std")]
pub(crate) use cstr_core::{CStr, CString};

#[cfg(not(feature = "no-std"))]
pub(crate) use std::ffi::{CStr, CString};

pub(crate) use core::mem;
pub(crate) use core::ptr;
pub(crate) use cty::{c_char, c_int, c_void};

/// The result of calling an operation on the library
pub type Result<T> = ::core::result::Result<T, Error>;

pub(crate) fn make_cstr(input: &str) -> Result<CString> {
    let cstr = CString::new(input).map_err(Error::conversion_error)?;
    Ok(cstr)
}

pub(crate) fn call_botan_ffi_returning_vec_u8(
    initial_size: usize,
    cb: &dyn Fn(*mut u8, *mut usize) -> c_int,
) -> Result<Vec<u8>> {
    let mut output = vec![0; initial_size];
    let mut out_len = output.len();

    let rc = cb(output.as_mut_ptr(), &mut out_len);
    if rc == 0 {
        assert!(out_len <= output.len());
        output.resize(out_len, 0);
        return Ok(output);
    } else if rc != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE {
        return Err(Error::from_rc(rc));
    }

    output.resize(out_len, 0);
    let rc = cb(output.as_mut_ptr(), &mut out_len);

    if rc != 0 {
        return Err(Error::from_rc(rc));
    }

    output.resize(out_len, 0);
    Ok(output)
}

fn cstr_slice_to_str(raw_cstr: &[u8]) -> Result<String> {
    let cstr = CStr::from_bytes_with_nul(raw_cstr).map_err(Error::conversion_error)?;
    Ok(cstr.to_str().map_err(Error::conversion_error)?.to_owned())
}

#[cfg(feature = "botan3")]
unsafe fn cstr_to_str(raw_cstr: *const i8) -> Result<String> {
    let cstr = CStr::from_ptr(raw_cstr);
    Ok(cstr.to_str().map_err(Error::conversion_error)?.to_owned())
}

pub(crate) fn call_botan_ffi_returning_string(
    initial_size: usize,
    cb: &dyn Fn(*mut u8, *mut usize) -> c_int,
) -> Result<String> {
    let v = call_botan_ffi_returning_vec_u8(initial_size, cb)?;
    cstr_slice_to_str(&v)
}

/// The library error type
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    err_type: ErrorType,
    message: Option<String>,
}

impl Error {
    /// Return the general type of the error
    pub fn error_type(&self) -> ErrorType {
        self.err_type
    }

    /// Return an optional message specific to the error
    ///
    /// This is only available in Botan 3.x; with older versions
    /// it will always be None
    pub fn error_message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    pub(crate) fn from_rc(rc: c_int) -> Self {
        let err_type = ErrorType::from(rc);

        #[cfg(feature = "botan3")]
        let message = {
            let cptr = unsafe { botan_sys::botan_error_last_exception_message() };
            match unsafe { cstr_to_str(cptr) } {
                Err(_) => None,
                Ok(s) if s.len() > 0 => Some(s),
                Ok(_) => None,
            }
        };

        #[cfg(not(feature = "botan3"))]
        let message = None;

        Self { err_type, message }
    }

    pub(crate) fn with_message(err_type: ErrorType, message: String) -> Self {
        Self {
            err_type,
            message: Some(message.to_string()),
        }
    }

    #[cfg(not(feature = "no-std"))]
    pub(crate) fn conversion_error<T: std::error::Error>(e: T) -> Self {
        Self {
            err_type: ErrorType::ConversionError,
            message: Some(format!("{}", e)),
        }
    }

    // Hack to deal with missing std::error::Error in no-std
    #[cfg(feature = "no-std")]
    pub(crate) fn conversion_error<T: core::fmt::Display>(e: T) -> Self {
        Self {
            err_type: ErrorType::ConversionError,
            message: Some(format!("{}", e)),
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match &self.message {
            Some(m) => write!(f, "{} ({})", self.err_type, m),
            None => write!(f, "{}", self.err_type),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// Possible error categories
pub enum ErrorType {
    /// A provided authentication code was incorrect
    BadAuthCode,
    /// A bad flag was passed to the library
    BadFlag,
    /// An invalid parameter was provided to the library
    BadParameter,
    /// An exception was thrown while processing this request
    ExceptionThrown,
    /// There was insufficient buffer space to write the output
    InsufficientBufferSpace,
    /// An internal error occurred (this is a bug in the library)
    InternalError,
    /// Something about the input was invalid
    InvalidInput,
    /// An invalid object was provided to the library
    InvalidObject,
    /// An object was invoked in a way that is invalid for its current state
    InvalidObjectState,
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
    /// An error occurred while invoking a system API
    SystemError,
    /// Some unknown error occurred
    UnknownError,
    /// An error occured while converting data to C
    ConversionError,
    /// An error occurred in TLS
    TlsError,
    /// An error occurred during an HTTP transaction
    HttpError,
}

impl fmt::Display for ErrorType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            Self::BadAuthCode => "A provided authentication code was incorrect",
            Self::BadFlag => "A bad flag was passed to the library",
            Self::BadParameter => "An invalid parameter was provided to the library",
            Self::ExceptionThrown => "An exception was thrown while processing this request",
            Self::InsufficientBufferSpace => {
                "There was insufficient buffer space to write the output"
            }
            Self::InternalError => "An internal error occurred (this is a bug in the library)",
            Self::InvalidInput => "Something about the input was invalid",
            Self::InvalidObject => "An invalid object was provided to the library",
            Self::InvalidObjectState => {
                "An object was invoked in a way that is invalid for its current state"
            }
            Self::InvalidVerifier => "A verifier was incorrect",
            Self::InvalidKeyLength => "An key of invalid length was provided",
            Self::KeyNotSet => "An object was invoked without the key being set",
            Self::NotImplemented => {
                "Some functionality is not implemented in the current library version"
            }
            Self::NullPointer => "A null pointer was incorrectly provided",
            Self::OutOfMemory => "Memory exhaustion",
            Self::SystemError => "An error occurred while invoking a system API",
            Self::UnknownError => "Some unknown error occurred",
            Self::ConversionError => "An error occured while converting data to C",
            Self::TlsError => "An error occurred in TLS",
            Self::HttpError => "An error occurred during an HTTP transaction",
        };

        write!(f, "{}", msg)
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for Error {}

impl From<i32> for ErrorType {
    fn from(err: i32) -> Self {
        match err {
            BOTAN_FFI_ERROR_BAD_FLAG => Self::BadFlag,
            BOTAN_FFI_ERROR_BAD_MAC => Self::BadAuthCode,
            BOTAN_FFI_ERROR_BAD_PARAMETER => Self::BadParameter,
            BOTAN_FFI_ERROR_EXCEPTION_THROWN => Self::ExceptionThrown,
            BOTAN_FFI_ERROR_HTTP_ERROR => Self::HttpError,
            BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE => Self::InsufficientBufferSpace,
            BOTAN_FFI_ERROR_INTERNAL_ERROR => Self::InternalError,
            BOTAN_FFI_ERROR_INVALID_INPUT => Self::InvalidInput,
            BOTAN_FFI_ERROR_INVALID_KEY_LENGTH => Self::InvalidKeyLength,
            BOTAN_FFI_ERROR_INVALID_OBJECT => Self::InvalidObject,
            BOTAN_FFI_ERROR_INVALID_OBJECT_STATE => Self::InvalidObjectState,
            BOTAN_FFI_ERROR_KEY_NOT_SET => Self::KeyNotSet,
            BOTAN_FFI_ERROR_NOT_IMPLEMENTED => Self::NotImplemented,
            BOTAN_FFI_ERROR_NULL_POINTER => Self::NullPointer,
            BOTAN_FFI_ERROR_OUT_OF_MEMORY => Self::OutOfMemory,
            BOTAN_FFI_ERROR_SYSTEM_ERROR => Self::SystemError,
            BOTAN_FFI_ERROR_TLS_ERROR => Self::TlsError,
            BOTAN_FFI_ERROR_UNKNOWN_ERROR => Self::UnknownError,
            BOTAN_FFI_INVALID_VERIFIER => Self::InvalidVerifier,
            _ => Self::UnknownError,
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
    pub(crate) fn new(min_keylen: usize, max_keylen: usize, mod_keylen: usize) -> Result<KeySpec> {
        if min_keylen > max_keylen || mod_keylen == 0 {
            return Err(Error::with_message(
                ErrorType::ConversionError,
                "Bad key spec".to_owned(),
            ));
        }

        Ok(KeySpec {
            min_keylen,
            max_keylen,
            mod_keylen,
        })
    }

    /// Return true if the specified key length is valid for this object
    #[must_use]
    pub fn is_valid_keylength(&self, keylen: usize) -> bool {
        keylen >= self.min_keylen && keylen <= self.max_keylen && keylen % self.mod_keylen == 0
    }

    /// Return the minimum supported keylength
    #[must_use]
    pub fn minimum_keylength(&self) -> usize {
        self.min_keylen
    }

    /// Return the maximum supported keylength
    #[must_use]
    pub fn maximum_keylength(&self) -> usize {
        self.max_keylen
    }

    /// Return the required multiple of the keylength
    ///
    /// That is each key must be N*keylength_multiple() for some N
    #[must_use]
    pub fn keylength_multiple(&self) -> usize {
        self.mod_keylen
    }
}
