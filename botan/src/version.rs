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

    /// Read the version information of the currently linked lib
    pub fn current() -> Result<Version> {

        unsafe {
            let version_str = CStr::from_ptr(botan_version_string()).to_str().map_err(|_| Error::ConversionError)?;

            Ok(Version {
                major: botan_version_major(),
                minor: botan_version_minor(),
                patch: botan_version_patch(),
                release_date: botan_version_datestamp(),
                ffi_api: botan_ffi_api_version(),
                string: version_str.to_string(),
            })
        }
    }

    #[must_use]
    /// Return true if the current version is at least as high as the
    /// major and minor numbers passed as arguments
    pub fn at_least(&self, major: u32, minor: u32) -> bool {
        self.major > major || (self.major == major && self.minor >= minor)
    }

    /// Return true if the specified API version is supported by this
    /// version of the library.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(botan::Version::supports_version(42), false);
    /// assert_eq!(botan::Version::supports_version(20180713), true);
    /// ```
    #[must_use]
    pub fn supports_version(version: u32) -> bool {
        let rc = unsafe { botan_ffi_supports_api(version) };
        return rc == 0;
    }

}
