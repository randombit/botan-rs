use crate::ffi_types::{c_char, c_int};

#[allow(clippy::upper_case_acronyms)]
pub type BOTAN_FFI_ERROR = c_int;

pub const BOTAN_FFI_SUCCESS: BOTAN_FFI_ERROR = 0;
pub const BOTAN_FFI_INVALID_VERIFIER: BOTAN_FFI_ERROR = 1;
pub const BOTAN_FFI_ERROR_INVALID_INPUT: BOTAN_FFI_ERROR = -1;
pub const BOTAN_FFI_ERROR_BAD_MAC: BOTAN_FFI_ERROR = -2;
pub const BOTAN_FFI_ERROR_NO_VALUE: BOTAN_FFI_ERROR = -3;
pub const BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE: BOTAN_FFI_ERROR = -10;
pub const BOTAN_FFI_ERROR_STRING_CONVERSION_ERROR: BOTAN_FFI_ERROR = -11;
pub const BOTAN_FFI_ERROR_EXCEPTION_THROWN: BOTAN_FFI_ERROR = -20;
pub const BOTAN_FFI_ERROR_OUT_OF_MEMORY: BOTAN_FFI_ERROR = -21;
pub const BOTAN_FFI_ERROR_SYSTEM_ERROR: BOTAN_FFI_ERROR = -22;
pub const BOTAN_FFI_ERROR_INTERNAL_ERROR: BOTAN_FFI_ERROR = -23;
pub const BOTAN_FFI_ERROR_BAD_FLAG: BOTAN_FFI_ERROR = -30;
pub const BOTAN_FFI_ERROR_NULL_POINTER: BOTAN_FFI_ERROR = -31;
pub const BOTAN_FFI_ERROR_BAD_PARAMETER: BOTAN_FFI_ERROR = -32;
pub const BOTAN_FFI_ERROR_KEY_NOT_SET: BOTAN_FFI_ERROR = -33;
pub const BOTAN_FFI_ERROR_INVALID_KEY_LENGTH: BOTAN_FFI_ERROR = -34;
pub const BOTAN_FFI_ERROR_INVALID_OBJECT_STATE: BOTAN_FFI_ERROR = -35;
pub const BOTAN_FFI_ERROR_OUT_OF_RANGE: BOTAN_FFI_ERROR = -36;
pub const BOTAN_FFI_ERROR_NOT_IMPLEMENTED: BOTAN_FFI_ERROR = -40;
pub const BOTAN_FFI_ERROR_INVALID_OBJECT: BOTAN_FFI_ERROR = -50;
pub const BOTAN_FFI_ERROR_TLS_ERROR: BOTAN_FFI_ERROR = -75;
pub const BOTAN_FFI_ERROR_HTTP_ERROR: BOTAN_FFI_ERROR = -76;
pub const BOTAN_FFI_ERROR_ROUGHTIME_ERROR: BOTAN_FFI_ERROR = -77;
pub const BOTAN_FFI_ERROR_TPM_ERROR: BOTAN_FFI_ERROR = -78;
pub const BOTAN_FFI_ERROR_UNKNOWN_ERROR: BOTAN_FFI_ERROR = -100;

/// Not an error code returned by Botan itself.
///
/// This value is returned by `botan-sys` when the requested FFI function is
/// not provided by the Botan library this program is using: either because
/// the headers found at build time predate the function, or (with dynamic
/// loading) because the loaded library does not export the symbol.
///
/// The value is chosen well outside the range of codes used by Botan.
pub const BOTAN_FFI_ERROR_FUNCTION_NOT_AVAILABLE: BOTAN_FFI_ERROR = -1000;

/// Not an error code returned by Botan itself.
///
/// This value is returned by `botan-sys` when the Botan shared library could
/// not be loaded at runtime. It is only ever returned when the
/// `dynamic-loading` feature is in use.
pub const BOTAN_FFI_ERROR_LIBRARY_NOT_LOADED: BOTAN_FFI_ERROR = -1001;

botan_ffi_functions! {

    pub fn botan_error_description(err: BOTAN_FFI_ERROR) -> *const c_char = core::ptr::null();

    #[cfg(botan_ffi_20230403)]
    pub fn botan_error_last_exception_message() -> *const c_char = core::ptr::null();

}
