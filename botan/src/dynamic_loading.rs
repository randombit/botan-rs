use crate::utils::*;

/// Load the Botan shared library from the specified path or name
///
/// This is only available with the `dynamic-loading` feature.
///
/// If this is not called, the Botan shared library is searched for under its
/// usual names (eg `libbotan-3.so.N`) the first time it is needed. Calling
/// this function first allows an application to control exactly which
/// library is used. The name is passed to `dlopen` (or `LoadLibrary`), so it
/// may be a full path or a bare filename which is searched for in the usual
/// locations.
///
/// This must be called before any other use of the library; once a library
/// has been loaded it cannot be replaced, and this function fails with
/// an error of type [`ErrorType::InvalidObjectState`].
///
/// If the library cannot be loaded, or is not a usable version of Botan, an
/// error of type [`ErrorType::LibraryNotLoaded`] is returned.
pub fn load_library<P: AsRef<std::ffi::OsStr>>(path: P) -> Result<()> {
    match botan_sys::load_library(path) {
        Ok(()) => Ok(()),
        Err(botan_sys::LoadError::AlreadyLoaded) => Err(Error::with_message(
            ErrorType::InvalidObjectState,
            "A Botan library has already been loaded".to_owned(),
        )),
        Err(e) => Err(Error::with_message(
            ErrorType::LibraryNotLoaded,
            e.to_string(),
        )),
    }
}

/// Return the name or path of the Botan shared library which was loaded
///
/// This is only available with the `dynamic-loading` feature. Returns `None`
/// if no library has been loaded yet.
pub fn loaded_library_name() -> Option<&'static str> {
    botan_sys::loaded_library_name()
}
