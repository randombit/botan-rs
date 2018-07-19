
use botan_sys::*;

use std::ffi::CStr;

#[derive(Debug)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub release_date: u32,
    pub ffi_api: u32,
    pub string: String,
}

impl Version {
    pub fn new() -> Version {

        unsafe {
            let version_str = CStr::from_ptr(botan_version_string()).to_str().unwrap().to_string();

            Version {
                major: botan_version_major(),
                minor: botan_version_minor(),
                patch: botan_version_patch(),
                release_date: botan_version_datestamp(),
                ffi_api: botan_ffi_api_version(),
                string: version_str,
            }
        }
    }

}
