use std::os::raw::{c_int, c_char};

pub type BOTAN_FFI_ERROR = c_int;

pub const BOTAN_FFI_ERROR_BOTAN_FFI_SUCCESS: BOTAN_FFI_ERROR = 0;
pub const BOTAN_FFI_ERROR_BOTAN_FFI_INVALID_VERIFIER: BOTAN_FFI_ERROR = 1;
pub const BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_INVALID_INPUT: BOTAN_FFI_ERROR = -1;
pub const BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_BAD_MAC: BOTAN_FFI_ERROR = -2;
pub const BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE: BOTAN_FFI_ERROR = -10;
pub const BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_EXCEPTION_THROWN: BOTAN_FFI_ERROR = -20;
pub const BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_OUT_OF_MEMORY: BOTAN_FFI_ERROR = -21;
pub const BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_BAD_FLAG: BOTAN_FFI_ERROR = -30;
pub const BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_NULL_POINTER: BOTAN_FFI_ERROR = -31;
pub const BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_BAD_PARAMETER: BOTAN_FFI_ERROR = -32;
pub const BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_KEY_NOT_SET: BOTAN_FFI_ERROR = -32;
pub const BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_NOT_IMPLEMENTED: BOTAN_FFI_ERROR = -40;
pub const BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_INVALID_OBJECT: BOTAN_FFI_ERROR = -50;
pub const BOTAN_FFI_ERROR_BOTAN_FFI_ERROR_UNKNOWN_ERROR: BOTAN_FFI_ERROR = -100;

extern "C" {

    pub fn botan_error_description(err: BOTAN_FFI_ERROR) -> *const c_char;

}
