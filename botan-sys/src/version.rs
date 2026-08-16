use crate::ffi_types::{c_char, c_int};

botan_ffi_functions! {

    pub fn botan_ffi_api_version() -> u32 = 0;

    pub fn botan_ffi_supports_api(api_version: u32) -> c_int;

    pub fn botan_version_string() -> *const c_char = core::ptr::null();

    pub fn botan_version_major() -> u32 = 0;
    pub fn botan_version_minor() -> u32 = 0;
    pub fn botan_version_patch() -> u32 = 0;
    pub fn botan_version_datestamp() -> u32 = 0;
}
