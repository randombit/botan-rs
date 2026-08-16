//! Runtime loading of the Botan shared library
//!
//! This module is only compiled when the `dynamic-loading` feature is
//! enabled. In that mode the crate does not link against Botan at all;
//! instead the shared library is loaded with `dlopen`/`LoadLibrary` the first
//! time any FFI function is called (or when [`load_library`] is called
//! explicitly), and each function is resolved lazily on first use.

use std::boxed::Box;
use std::ffi::OsStr;
use std::fmt;
use std::format;
use std::string::{String, ToString};
use std::sync::{Mutex, OnceLock};
use std::vec::Vec;

use libloading::Library;

/// The oldest FFI API version this crate supports (Botan 2.13)
const MINIMUM_FFI_VERSION: u32 = 20191214;

/// The highest Botan 3 ABI revision (`libbotan-3.so.N`) that the default
/// search will try. New releases are quarterly, and likely the release
/// series stops around 3.17 with release of Botan4. At current pace 3.22
/// would be in Q4 2028.
const MAX_BOTAN3_ABI_REV: u32 = 22;

/// An error which occurred while loading the Botan shared library
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoadError {
    /// A Botan library has already been loaded, and cannot be replaced
    AlreadyLoaded,
    /// The library could not be loaded
    LoadFailed(String),
    /// A library was loaded, but it is not a usable version of Botan
    UnusableLibrary(String),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyLoaded => write!(f, "A Botan library has already been loaded"),
            Self::LoadFailed(msg) => write!(f, "Unable to load the Botan library: {msg}"),
            Self::UnusableLibrary(msg) => write!(f, "The loaded library is not usable: {msg}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// The reason a symbol could not be resolved
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unavailable {
    /// The library was loaded, but does not export the symbol
    Function,
    /// The library could not be loaded
    Library,
}

/// A lazily resolved function from the loaded library
///
/// Each generated FFI wrapper owns one of these in a `static`; the symbol is
/// looked up on first use and the result (including "not present") is
/// cached for the lifetime of the process.
pub(crate) struct Symbol<F: Copy + 'static> {
    name: &'static str,
    cell: OnceLock<Option<F>>,
}

impl<F: Copy + 'static> Symbol<F> {
    /// Create a symbol; `name` must be NUL terminated
    pub(crate) const fn new(name: &'static str) -> Self {
        Self {
            name,
            cell: OnceLock::new(),
        }
    }

    /// Resolve the symbol, loading the library first if necessary
    ///
    /// # Safety
    ///
    /// `F` must be the correct function pointer type for the symbol
    pub(crate) unsafe fn get(&'static self) -> Result<F, Unavailable> {
        let lib = library().map_err(|_| Unavailable::Library)?;
        let sym = self.cell.get_or_init(|| {
            // SAFETY: the caller guarantees F is the correct type; the library
            // is stored in a static and never unloaded, so the raw function
            // pointer remains valid for the life of the process
            unsafe { lib.get::<F>(self.name.as_bytes()) }
                .ok()
                .map(|s| *s)
        });
        sym.ok_or(Unavailable::Function)
    }
}

struct Loaded {
    lib: Library,
    name: String,
}

enum State {
    /// The default search has not been attempted yet
    Unattempted,
    /// The default search was attempted and failed
    AutoFailed(&'static str),
}

/// The loaded library. Once set it is never cleared or dropped, so function
/// pointers resolved from it remain valid.
static LIBRARY: OnceLock<Loaded> = OnceLock::new();

/// Guards loading attempts, and remembers a failed default search so that it
/// is not repeated on every call.
static STATE: Mutex<State> = Mutex::new(State::Unattempted);

fn lock_state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Return the loaded library, performing the default search on first call
fn library() -> Result<&'static Library, &'static str> {
    if let Some(loaded) = LIBRARY.get() {
        return Ok(&loaded.lib);
    }

    let mut state = lock_state();

    // Another thread may have loaded it while we waited for the lock
    if let Some(loaded) = LIBRARY.get() {
        return Ok(&loaded.lib);
    }

    match *state {
        State::AutoFailed(msg) => Err(msg),
        State::Unattempted => match default_search() {
            Ok(loaded) => {
                let _ = LIBRARY.set(loaded);
                Ok(&LIBRARY.get().expect("just set").lib)
            }
            Err(e) => {
                let msg: &'static str = Box::leak(e.to_string().into_boxed_str());
                *state = State::AutoFailed(msg);
                Err(msg)
            }
        },
    }
}

/// Open a shared library by name or path
///
/// # Safety
///
/// Loading a shared library runs its initialization code; this is inherent
/// to dynamic loading.
#[cfg(windows)]
unsafe fn open_library(name: &OsStr) -> Result<Library, libloading::Error> {
    use libloading::os::windows::{
        LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, Library as WinLibrary,
    };

    // The default LoadLibrary search order includes the current directory
    // and PATH, which would allow a malicious DLL placed there to be loaded
    // when searching by name. Restrict the search to the application
    // directory, System32, and directories explicitly added with
    // AddDllDirectory. When an absolute path is provided (via load_library)
    // additionally allow the DLL's own directory, so that its dependencies
    // located alongside it can be found.
    let mut flags = LOAD_LIBRARY_SEARCH_DEFAULT_DIRS;
    if std::path::Path::new(name).is_absolute() {
        flags |= LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR;
    }

    unsafe { WinLibrary::load_with_flags(name, flags) }.map(Library::from)
}

/// Open a shared library by name or path
///
/// # Safety
///
/// Loading a shared library runs its initialization code; this is inherent
/// to dynamic loading.
#[cfg(not(windows))]
unsafe fn open_library(name: &OsStr) -> Result<Library, libloading::Error> {
    // dlopen searches the standard locations (rpath, LD_LIBRARY_PATH, the
    // system cache and default directories) but not the current directory
    unsafe { Library::new(name) }
}

/// Attempt to load the named library and verify that it is a usable Botan
fn try_load(name: &OsStr) -> Result<Loaded, LoadError> {
    // SAFETY: Botan's initialization code is benign
    let lib = unsafe { open_library(name) }.map_err(|e| LoadError::LoadFailed(e.to_string()))?;

    // SAFETY: this symbol has had this signature since the FFI was introduced
    let api_version =
        unsafe { lib.get::<unsafe extern "C" fn() -> u32>(b"botan_ffi_api_version\0") }.map_err(
            |_| {
                LoadError::UnusableLibrary(format!(
                    "{} does not export botan_ffi_api_version",
                    name.to_string_lossy()
                ))
            },
        )?;

    // SAFETY: calling the FFI function with its documented signature
    let version = unsafe { api_version() };

    if version < MINIMUM_FFI_VERSION {
        return Err(LoadError::UnusableLibrary(format!(
            "{} has FFI version {} but at least {} is required",
            name.to_string_lossy(),
            version,
            MINIMUM_FFI_VERSION
        )));
    }

    Ok(Loaded {
        lib,
        name: name.to_string_lossy().into_owned(),
    })
}

/// The names tried by the default search, in order of preference
fn candidate_names() -> Vec<String> {
    let mut names = Vec::new();

    if cfg!(target_os = "windows") {
        names.push("botan-3.dll".to_string());
        names.push("botan.dll".to_string()); // Botan 2.x
    } else if cfg!(target_os = "macos") {
        // Homebrew installs outside of the default dyld search path
        let prefixes = ["", "/opt/homebrew/lib/", "/usr/local/lib/"];
        for prefix in prefixes {
            for rev in (0..=MAX_BOTAN3_ABI_REV).rev() {
                names.push(format!("{prefix}libbotan-3.{rev}.dylib"));
            }
            names.push(format!("{prefix}libbotan-3.dylib"));
        }
        for prefix in prefixes {
            for rev in (13..=19).rev() {
                names.push(format!("{prefix}libbotan-2.{rev}.dylib"));
            }
            names.push(format!("{prefix}libbotan-2.dylib"));
        }
    } else {
        // Botan 3.x: newest ABI revision first
        for rev in (0..=MAX_BOTAN3_ABI_REV).rev() {
            names.push(format!("libbotan-3.so.{rev}"));
        }
        names.push("libbotan-3.so".to_string());
        // Botan 2.13 through 2.19
        for rev in (13..=19).rev() {
            names.push(format!("libbotan-2.so.{rev}"));
        }
        names.push("libbotan-2.so".to_string());
    }

    names
}

fn default_search() -> Result<Loaded, LoadError> {
    let names = candidate_names();
    let mut last_error = String::new();

    for name in &names {
        match try_load(OsStr::new(name)) {
            Ok(loaded) => return Ok(loaded),
            Err(LoadError::LoadFailed(msg) | LoadError::UnusableLibrary(msg)) => {
                last_error = msg;
            }
            Err(e) => last_error = e.to_string(),
        }
    }

    Err(LoadError::LoadFailed(format!(
        "no Botan shared library found; tried {} names such as {} and {} (last error: {}). \
         Use botan_sys::load_library to specify the location explicitly.",
        names.len(),
        names.first().map(String::as_str).unwrap_or(""),
        names.last().map(String::as_str).unwrap_or(""),
        last_error
    )))
}

/// Load the Botan shared library from the specified path or name
///
/// This may be called before any other function in the crate is used, in
/// order to control which library is loaded. If not called, the first FFI
/// call performs a search for the library under its usual names.
///
/// The name is passed to `dlopen` (or `LoadLibrary`), so it may be either a
/// bare filename which is searched for in the usual locations, or a full path.
///
/// Fails with `LoadError::AlreadyLoaded` if a library was already loaded, since
/// the library cannot be replaced once functions have been resolved from it.
pub fn load_library<P: AsRef<OsStr>>(path: P) -> Result<(), LoadError> {
    let _state = lock_state();

    if LIBRARY.get().is_some() {
        return Err(LoadError::AlreadyLoaded);
    }

    let loaded = try_load(path.as_ref())?;
    let _ = LIBRARY.set(loaded);
    Ok(())
}

/// Return the name or path of the Botan shared library which was loaded
///
/// Returns `None` if no library has been loaded yet
pub fn loaded_library_name() -> Option<&'static str> {
    LIBRARY.get().map(|l| l.name.as_str())
}

/// Return a description of why the Botan library could not be loaded
///
/// Returns `None` if the library was loaded successfully or if loading has
/// not yet been attempted.
pub fn last_load_error() -> Option<&'static str> {
    if LIBRARY.get().is_some() {
        return None;
    }
    match *lock_state() {
        State::AutoFailed(msg) => Some(msg),
        State::Unattempted => None,
    }
}
