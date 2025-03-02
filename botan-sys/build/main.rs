use std::collections::HashMap;
use std::path::PathBuf;

const KNOWN_FFI_VERSIONS: [(u32, u32); 7] = [
    (3, 20250506), // 3.8
    (3, 20240408), // 3.4
    (3, 20231009), // 3.2
    (3, 20230711), // 3.1
    (3, 20230403), // 3.0
    (2, 20210220), // 2.18
    (2, 20191214), // 2.13
];

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

fn sanity_check_ffi(major_version: u32, minor_version: u32, ffi_version: u32) -> u32 {
    if ffi_version == 0 {
        panic!("The libbotan found does not support the FFI feature");
    }

    if ffi_version < 20191214 {
        panic!("This version of Botan is too old; at least 2.13.0 is required");
    }

    if major_version < 2 {
        panic!("Major version 1 or lower not supported");
    }

    if major_version > 4 {
        panic!("Major version unexpectedly high");
    }

    if major_version >= 3 && ffi_version > 20250506 {
        // Some future version; assume FFI is additive
        return 20250506;
    }

    for (mv, fv) in &KNOWN_FFI_VERSIONS {
        if ffi_version == *fv && major_version >= *mv {
            return *fv;
        }
    }

    panic!(
        "Unexpected version settings major={} minor={} ffi={}",
        major_version, minor_version, ffi_version
    );
}

#[allow(dead_code)]
fn env_var(key: &str) -> Option<String> {
    println!("cargo:rerun-if-env-changed={}", key);
    std::env::var(key).ok()
}

#[derive(Debug, Copy, Clone)]
struct DetectedVersionInfo {
    major_version: u32,
    #[allow(dead_code)]
    minor_version: u32,
    ffi_version: u32,
}

impl DetectedVersionInfo {
    fn library_link_name(&self) -> String {
        if cfg!(target_os = "windows") && self.major_version == 2 {
            // For some unknown reason, Botan 2.x does not include
            // the major version in the name of the Windows library
            "botan".to_string()
        } else {
            format!("botan-{}", self.major_version)
        }
    }

    fn from_map(map: HashMap<String, u32>) -> Self {
        let major_version = *map.get("MAJOR_VERSION").expect("Missing MAJOR_VERSION");
        let minor_version = *map.get("MINOR_VERSION").expect("Missing MINOR_VERSION");
        let ffi_version = *map.get("FFI_VERSION").expect("Missing FFI_VERSION");
        let ffi_version = sanity_check_ffi(major_version, minor_version, ffi_version);
        Self {
            major_version,
            minor_version,
            ffi_version,
        }
    }

    fn from_header(include_dir: &PathBuf) -> Self {
        println!("cargo:rerun-if-changed=build/version.c");
        let mut cc = cc::Build::new();
        cc.include(include_dir);

        match cc.file("build/version.c").try_expand() {
            Ok(o) => {
                let expanded = String::from_utf8(o).expect("Output is not valid UTF8");
                let mut map = HashMap::new();

                for line in expanded.split('\n') {
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let line = line.replace('\r', "");

                    let parts = line.split(' ').collect::<Vec<_>>();

                    if parts.len() != 2 {
                        continue;
                    }

                    if parts[0] == "MAJOR_VERSION"
                        || parts[0] == "MINOR_VERSION"
                        || parts[0] == "FFI_VERSION"
                    {
                        if let Ok(code) = parts[1].parse::<u32>() {
                            map.insert(parts[0].to_owned(), code);
                        } else {
                            panic!("Unexpected line '{}'", line);
                        }
                    }
                }

                DetectedVersionInfo::from_map(map)
            }
            Err(e) => {
                panic!("Failed to expand header {:?}", e);
            }
        }
    }
}

#[cfg(not(feature = "vendored"))]
fn find_botan_include_dir() -> std::path::PathBuf {
    #[cfg(feature = "pkg-config")]
    {
        for major in [3, 2] {
            let lib_name = format!("botan-{}", major);

            let statik = if cfg!(feature = "static") {
                true
            } else {
                false
            };

            if let Ok(config) = pkg_config::Config::new().statik(statik).probe(&lib_name) {
                return config.include_paths[0].clone();
            }
        }
    }

    #[cfg(not(feature = "pkg-config"))]
    {
        if let Some(dir) = env_var("BOTAN_INCLUDE_DIR") {
            return dir.into();
        }

        fn possible_header_locations() -> Vec<std::path::PathBuf> {
            let dirs = [
                "/opt/homebrew/include",
                "/usr/local/include",
                "/usr/include",
                "/opt/include",
            ];
            let mut paths = vec![];

            for dirname in dirs {
                let path = PathBuf::from(dirname);
                if path.exists() {
                    paths.push(path);
                }
            }

            paths
        }

        for major_version in [3, 2] {
            let dir = PathBuf::from(format!("botan-{}", major_version));
            for basedir in possible_header_locations() {
                let inc_dir = basedir.join(dir.clone());
                if inc_dir.exists() {
                    return inc_dir;
                }
            }
        }

        panic!("Unable to find the headers cooresponding with any supported version of Botan");
    }
}

fn main() {
    for (_, v) in &KNOWN_FFI_VERSIONS {
        println!("cargo:rustc-check-cfg=cfg(botan_ffi_{})", v);
    }

    // TODO refactor this to avoid duplication between the two branches

    #[cfg(feature = "vendored")]
    {
        let (lib_dir, inc_dir) = botan_src::build();

        let version = DetectedVersionInfo::from_header(&inc_dir);
        println!("cargo:vendored=1");
        println!("cargo:rustc-link-search=native={}", &lib_dir);
        println!(
            "cargo:rustc-link-lib=static={}",
            version.library_link_name()
        );

        for dylib in emit_dylibs() {
            println!("cargo:rustc-flags=-l dylib={}", dylib);
        }
        println!("cargo:ffi_version={}", version.ffi_version);
        for (_, ffi) in &KNOWN_FFI_VERSIONS {
            if *ffi <= version.ffi_version {
                println!("cargo:rustc-cfg=botan_ffi_{}", ffi);
            }
        }
    }
    #[cfg(not(feature = "vendored"))]
    {
        let version = DetectedVersionInfo::from_header(&find_botan_include_dir());

        if cfg!(feature = "static") {
            println!(
                "cargo:rustc-link-lib=static={}",
                version.library_link_name()
            );
        } else {
            println!("cargo:rustc-link-lib={}", version.library_link_name());
        }
        // TODO(MSRV) cargo::metadata after 1.77
        println!("cargo:ffi_version={}", version.ffi_version);
        for (_, ffi) in &KNOWN_FFI_VERSIONS {
            if *ffi <= version.ffi_version {
                println!("cargo:rustc-cfg=botan_ffi_{}", ffi);
            }
        }
    }
}
