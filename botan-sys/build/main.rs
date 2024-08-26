use std::path::PathBuf;
use std::collections::HashMap;

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

// Note this reflects the latest FFI version exposed by the library,
// which does not usually coorespond with the named version. For
// example 3.5.0 did not introduce any new FFI interfaces so it
// implements the same FFI verison as 3.4 (20240408)
#[derive(Debug, Copy, Clone)]
enum FfiVersion {
    Ffi20191214, // 2.13
    Ffi20210220, // 2.18
    Ffi20230403, // 3.0
    Ffi20230711, // 3.1
    Ffi20231009, // 3.2
    Ffi20240408, // 3.4
}

impl FfiVersion {
    fn from_code(code: u32) -> Self {
        match code {
            20191214 => Self::Ffi20191214,
            20210220 => Self::Ffi20210220,
            20230403 => Self::Ffi20230403,
            20230711 => Self::Ffi20230711,
            20231009 => Self::Ffi20231009,
            20240408 => Self::Ffi20240408,
            _something_else => {
                if code == 0 {
                    panic!("The libbotan found does not support the FFI feature");
                } else if code < 20191214 {
                    panic!("This version of Botan is too old; at least 2.13.0 is required");
                } else if code > 20240408 {
                    // Some future version; assume FFI is additive
                    Self::Ffi20240408
                } else {
                    // This is unexpected: an FFI version in the known range but
                    // *not* one of the known values. This should never happen.
                    panic!("Unexpected FFI version code {}", code);
                }
            }
        }
    }
}

fn env_var(key: &str) -> Option<String> {
    println!("cargo:rerun-if-env-changed={}", key);
    std::env::var(key).ok()
}

#[derive(Debug, Copy, Clone)]
struct DetectedVersionInfo {
    major_version: u32,
    ffi_version: u32
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
        Self {
            major_version: *map.get("MAJOR_VERSION").expect("Missing MAJOR_VERSION"),
            ffi_version: *map.get("FFI_VERSION").expect("Missing FFI_VERSION"),
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

                    let parts = line.split(' ').collect::<Vec<_>>();

                    assert!(parts.len() == 2, "Unexpected cpp output '{}'", line);

                    if let Ok(code) = parts[1].parse::<u32>() {
                        map.insert(parts[0].to_owned(), code);
                    } else {
                        panic!("Unexpected line '{}'", line);
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

fn possible_header_locations() -> Vec<std::path::PathBuf> {
    let mut paths = vec![];

    paths.push(std::path::PathBuf::from("/opt/homebrew"));
    paths.push(std::path::PathBuf::from("/usr/local"));
    paths.push(std::path::PathBuf::from("/usr"));

    paths
}

fn main() {
    #[cfg(feature = "vendored")]
    {
        let (lib_dir, inc_dir) = botan_src::build();

        let version = DetectedVersionInfo::from_header(&inc_dir);
        println!("cargo:vendored=1");
        println!("cargo:rustc-link-search=native={}", &lib_dir);
        println!("cargo:rustc-link-lib=static={}", version.library_link_name());

        for dylib in emit_dylibs() {
            println!("cargo:rustc-flags=-l dylib={}", dylib);
        }
    }
    #[cfg(not(feature = "vendored"))]
    {
        let version = DetectedVersionInfo::from_header(&PathBuf::from("/usr/include/botan-3"));
        println!("cargo:rustc-link-lib={}", version.library_link_name());
    }
}
