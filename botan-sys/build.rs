#[cfg(feature = "vendored")]
fn emit_dylibs() -> Vec<&'static str> {
    // Windows doesn't need to dynamically link the C++ runtime
    // but we do need to link to DLLs with needed functionality:
    if cfg!(target_os = "windows") {
        return vec!["user32", "crypt32"];
    }

    // On Linux we use libstdc++
    if cfg!(any(target_os = "linux")) {
        return vec!["stdc++"];
    }

    // For all other platforms, link to libc++ from LLVM/Clang
    vec!["c++"]
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
        println!("cargo:rustc-link-lib=static={}", botan_library_name());

        for dylib in emit_dylibs() {
            println!("cargo:rustc-flags=-l dylib={}", dylib);
        }
    }
    #[cfg(not(feature = "vendored"))]
    {
        #[cfg(feature = "static")]
        {
            #[cfg(feature = "pkg-config")]
            {
                pkg_config::Config::new().statik(true).probe(&botan_library_name()).unwrap();
            }
            #[cfg(not(feature = "pkg-config"))]
            {
                println!("cargo:rustc-link-lib=static={}", botan_library_name());
            }
        }
        #[cfg(not(feature = "static"))]
        {
            println!("cargo:rustc-link-lib={}", botan_library_name());
        }
    }
}
