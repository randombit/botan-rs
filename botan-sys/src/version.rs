use std::os::raw::{c_int, c_char};

extern "C" {

    pub fn botan_ffi_api_version() -> u32;

    pub fn botan_ffi_supports_api(api_version: u32) -> c_int;

    pub fn botan_version_string() -> *const c_char;

    pub fn botan_version_major() -> u32;
    pub fn botan_version_minor() -> u32;
    pub fn botan_version_patch() -> u32;
    pub fn botan_version_datestamp() -> u32;
}

