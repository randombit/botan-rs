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
//! As a result every function is always callable, and callers only need to
//! deal with a single runtime error condition ("the library in use does not
//! provide this function") rather than a compile time one.
//!
//! [`BOTAN_FFI_ERROR_FUNCTION_NOT_AVAILABLE`]: crate::BOTAN_FFI_ERROR_FUNCTION_NOT_AVAILABLE

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
        $( #[cfg($cfg)] )?
        unsafe extern "C" {
            pub fn $name ( $($arg : $ty),* ) $( -> $ret )? ;
        }

        __botan_ffi_stub! {
            @cfg [ $($cfg)? ]
            @dflt [ $($dflt)? ]
            pub fn $name ( $($arg : $ty),* ) $( -> $ret )? ;
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
        #[cfg(not($cfg))]
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
