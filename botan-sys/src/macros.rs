//! Macro used to declare the Botan FFI functions.
//!
//! Every FFI function is declared through [`botan_ffi_functions!`]. In the
//! linked build modes (the default dynamic linking, `static`, and `vendored`)
//! this expands to an ordinary `unsafe extern "C"` declaration whenever the
//! function was found in the Botan headers detected at build time. If the
//! headers predate the function, a *stub* with the same name and signature is
//! emitted instead, which returns [`BOTAN_FFI_ERROR_FUNCTION_NOT_AVAILABLE`]
//! (or the explicitly declared unavailable value for functions that do not
//! return an error code).
//!
//! With the `dynamic-loading` feature the crate does not link against Botan
//! at all. Instead the same macro expands to a wrapper function which loads
//! the shared library on first use, resolves the symbol, and calls it,
//! returning [`BOTAN_FFI_ERROR_FUNCTION_NOT_AVAILABLE`] if the loaded
//! library does not export the symbol and
//! [`BOTAN_FFI_ERROR_LIBRARY_NOT_LOADED`] if no library could be loaded.
//!
//! As a result every function is always callable, and callers only need to
//! deal with a runtime error condition ("the library in use does not
//! provide this function") rather than a compile time one.
//!
//! [`BOTAN_FFI_ERROR_FUNCTION_NOT_AVAILABLE`]: crate::BOTAN_FFI_ERROR_FUNCTION_NOT_AVAILABLE
//! [`BOTAN_FFI_ERROR_LIBRARY_NOT_LOADED`]: crate::BOTAN_FFI_ERROR_LIBRARY_NOT_LOADED

/// Declare a set of Botan FFI functions
///
/// The syntax mirrors an `extern "C"` block. Functions that were added to
/// the FFI after the minimum supported version carry a `#[cfg(botan_ffi_X)]`
/// attribute; a stub is generated for them when that cfg is not set. Functions
/// which do not return a `c_int` error code must specify the value that the
/// stub returns using `-> Type = value`.
///
/// ```ignore
/// botan_ffi_functions! {
///     pub fn botan_hash_init(hash: *mut botan_hash_t, name: *const c_char, flags: u32) -> c_int;
///     #[cfg(botan_ffi_20260811)]
///     pub fn botan_hash_security_level(hash: botan_hash_t, level: *mut usize) -> c_int;
///     pub fn botan_version_major() -> u32 = 0;
/// }
/// ```
macro_rules! botan_ffi_functions {
    (
        $(
            $(#[cfg($cfg:ident)])?
            pub fn $name:ident ( $($arg:ident : $ty:ty),* $(,)? ) $( -> $ret:ty $( = $dflt:expr )? )? ;
        )*
    ) => {
        $(
            __botan_ffi_function! {
                @cfg [ $($cfg)? ]
                @dflt [ $( $( $dflt )? )? ]
                pub fn $name ( $($arg : $ty),* ) $( -> $ret )? ;
            }
        )*
    };
}

macro_rules! __botan_ffi_function {
    (
        @cfg [ $($cfg:ident)? ]
        @dflt [ $($dflt:expr)? ]
        pub fn $name:ident ( $($arg:ident : $ty:ty),* ) $( -> $ret:ty )? ;
    ) => {
        // Linked modes: the real declaration, if the detected headers have it
        #[cfg(not(feature = "dynamic-loading"))]
        $( #[cfg($cfg)] )?
        unsafe extern "C" {
            pub fn $name ( $($arg : $ty),* ) $( -> $ret )? ;
        }

        // Linked modes: a stub if the detected headers predate the function
        __botan_ffi_stub! {
            @cfg [ $($cfg)? ]
            @dflt [ $($dflt)? ]
            pub fn $name ( $($arg : $ty),* ) $( -> $ret )? ;
        }

        // Dynamic loading: resolve the symbol from the loaded library on
        // first use, and call it. Missing symbols and a library which could
        // not be loaded are reported via the return value.
        #[cfg(feature = "dynamic-loading")]
        #[allow(non_snake_case, clippy::missing_safety_doc)]
        pub unsafe extern "C" fn $name ( $($arg : $ty),* ) $( -> $ret )? {
            static SYM: $crate::loader::Symbol<unsafe extern "C" fn($($ty),*) $( -> $ret )?> =
                $crate::loader::Symbol::new(concat!(stringify!($name), "\0"));

            // SAFETY: the type of SYM matches the declaration of the function
            match unsafe { SYM.get() } {
                // SAFETY: calling the FFI function with its declared signature
                Ok(f) => unsafe { f($($arg),*) },
                Err($crate::loader::Unavailable::Function) => {
                    __botan_unavailable_value!( $($dflt)? )
                }
                Err($crate::loader::Unavailable::Library) => {
                    __botan_not_loaded_value!( $($dflt)? )
                }
            }
        }
    };
}

macro_rules! __botan_ffi_stub {
    // Function is available in every supported version: no stub needed
    (
        @cfg [ ]
        $($rest:tt)*
    ) => {};

    (
        @cfg [ $cfg:ident ]
        @dflt [ $($dflt:expr)? ]
        pub fn $name:ident ( $($arg:ident : $ty:ty),* ) $( -> $ret:ty )? ;
    ) => {
        #[cfg(all(not(feature = "dynamic-loading"), not($cfg)))]
        #[allow(unused_variables, non_snake_case, clippy::missing_safety_doc)]
        #[doc = concat!("Stub for `", stringify!($name), "`, which is not provided by the version of Botan detected at build time (requires `", stringify!($cfg), "`).")]
        pub unsafe extern "C" fn $name ( $($arg : $ty),* ) $( -> $ret )? {
            __botan_unavailable_value!( $($dflt)? )
        }
    };
}

macro_rules! __botan_unavailable_value {
    () => {
        $crate::BOTAN_FFI_ERROR_FUNCTION_NOT_AVAILABLE
    };
    ($dflt:expr) => {
        $dflt
    };
}

macro_rules! __botan_not_loaded_value {
    () => {
        $crate::BOTAN_FFI_ERROR_LIBRARY_NOT_LOADED
    };
    ($dflt:expr) => {
        $dflt
    };
}
