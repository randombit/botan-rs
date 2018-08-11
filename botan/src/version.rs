use botan_sys::*;
use utils::*;

#[derive(Debug)]
/// Information about the library version
pub struct Version {
    /// The major version of the library
    pub major: u32,
    /// The minor version of the library
    pub minor: u32,
    /// The patch version of the library
    pub patch: u32,
    /// The release date of the library, as YYYYMMDD, for example
    /// 2.7.0 has value 20180702. Will be 0 for unreleased versions.
    pub release_date: u32,
    /// The version of the FFI API, as a YYYYMMDD field.
    pub ffi_api: u32,
    /// A free-form string describing the library version
    pub string: String,
}

impl Version {
    /// Read the version information
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
