#[cfg(feature = "vendored")]
fn os_uses_gnu_libstdcpp() -> bool {
    /*
     * Possibly other OSes should default to libstdc++ as well.  But
     * given macOS, iOS, Android, FreeBSD, etc should all use libc++
     * probably defaulting to libc++ when in doubt is the correct move.
     */
    if cfg!(any(target_os = "linux")) {
        true
    } else {
        false
    }
}

fn botan_lib_major_version() -> i32 {
    if cfg!(any(feature = "vendored", feature = "botan3")) {
        3
    } else {
        2
    }
}

fn botan_library_name() -> String {
    let major_version = botan_lib_major_version();

    if cfg!(target_os = "windows") && major_version == 2 {
        // For some unknown reason, Botan 2.x does not include
        // the major version in the name of the Windows library
        "botan".to_string()
    } else {
        format!("botan-{major_version}")
    }
}

fn main() {
    #[cfg(feature = "vendored")]
    {
        let (lib_dir, _) = botan_src::build();
        println!("cargo:vendored=1");
        println!("cargo:rustc-link-search=native={}", &lib_dir);
        println!("cargo:rustc-link-lib=static={}", botan_library_name(),);

        if os_uses_gnu_libstdcpp() {
            println!("cargo:rustc-flags=-l dylib=stdc++");
        } else {
            println!("cargo:rustc-flags=-l dylib=c++");
        }
    }
    #[cfg(not(feature = "vendored"))]
    {
        println!("cargo:rustc-link-lib={}", botan_library_name());
    }
}
