use std::env;
use std::str::FromStr;

fn main() {
    let known_ffi_versions = [
        20250506, 20240408, 20231009, 20230711, 20230403, 20210220, 20191214,
    ];

    for ffi in &known_ffi_versions {
        println!("cargo:rustc-check-cfg=cfg(botan_ffi_{ffi})");
    }

    if let Ok(version) = env::var("DEP_BOTAN_FFI_VERSION") {
        let version = u64::from_str(&version).unwrap();

        for ffi in known_ffi_versions {
            if version >= ffi {
                println!("cargo:rustc-cfg=botan_ffi_{ffi}");
            }
        }
    } else {
        panic!("Expected DEP_BOTAN_FFI_VERSION to be set");
    }
}
