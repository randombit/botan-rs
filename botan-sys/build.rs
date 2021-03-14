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

fn main() {
    #[cfg(feature = "vendored")]
    {
        let (lib_dir, _) = botan_src::build();
        println!("cargo:vendored=1");
        println!("cargo:rustc-link-search=native={}", &lib_dir);
        println!("cargo:rustc-link-lib=static=botan-2");

        if os_uses_gnu_libstdcpp() {
            println!("cargo:rustc-flags=-l dylib=stdc++");
        } else {
            println!("cargo:rustc-flags=-l dylib=c++");
        }
    }
    #[cfg(not(feature = "vendored"))]
    {
        println!("cargo:rustc-link-lib=botan-2");
    }
}
