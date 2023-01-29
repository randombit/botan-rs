use std::env;
use std::path::PathBuf;
use std::process::Command;

const BUILD_ERROR_MSG: &str = "Unable to build botan.";
const SRC_DIR_ERROR_MSG: &str = "Unable to find the source directory.";
const SRC_DIR: &str = "botan";
const INCLUDE_DIR: &str = "build/include/botan";

macro_rules! pathbuf_to_string {
    ($s: ident) => {
        $s.to_str().expect(BUILD_ERROR_MSG).to_string()
    };
}

fn env_name_for(opt: &'static str) -> String {
    assert!(opt[0..2] == *"--");
    let to_var = opt[2..].to_uppercase().replace('-', "_");
    format!("BOTAN_CONFIGURE_{to_var}")
}

fn configure(build_dir: &str) {
    let mut configure = Command::new("python3");
    configure.arg("configure.py");
    configure.arg(format!("--with-build-dir={build_dir}"));
    configure.arg("--build-targets=static");
    configure.arg("--without-documentation");
    configure.arg("--no-install-python-module");
    configure.arg("--distribution-info=https://crates.io/crates/botan-src");
    #[cfg(debug_assertions)]
    configure.arg("--with-debug-info");

    let args = [
        "--os",
        "--cpu",
        "--compiler-cache",
        "--cc",
        "--cc-min-version",
        "--cc-bin",
        "--cc-abi-flags",
        "--cxxflags",
        "--extra-cxxflags",
        "--ldflags",
        "--ar-command",
        "--ar-options",
        "--msvc-runtime",
        "--with-endian",
        "--with-os-features",
        "--without-os-features",
        "--system-cert-bundle",
        "--with-local-config",
        "--boost-library-name",
        "--module-policy",
        "--enable-modules",
        "--disable-modules",
        "--library-suffix",
        "--prefix",
        "--libdir",
        "--mandir",
        "--includedir",
    ];

    let flags = [
        "--optimize-for-size",
        "--no-optimizations",
        "--amalgamation",
        "--minimized-build",
        "--with-openssl",
        "--with-commoncrypto",
        "--with-sqlite3",
    ];

    for arg_name in &args {
        let env_name = env_name_for(arg_name);
        if let Ok(arg_val) = env::var(env_name) {
            let arg = format!("{arg_name}={arg_val}");
            configure.arg(arg);
        }
    }

    for flag_name in &flags {
        let env_name = env_name_for(flag_name);
        if env::var(env_name).is_ok() {
            configure.arg(flag_name);
        }
    }

    let status = configure
        .spawn()
        .expect(BUILD_ERROR_MSG)
        .wait()
        .expect(BUILD_ERROR_MSG);
    if !status.success() {
        panic!("configure terminated unsuccessfully");
    }
}

fn make(build_dir: &str) {
    let mut cmd = Command::new("make");
    // Set MAKEFLAGS to the content of CARGO_MAKEFLAGS
    // to give jobserver (parallel builds) support to the
    // spawned sub-make.
    if let Ok(val) = env::var("CARGO_MAKEFLAGS") {
        cmd.env("MAKEFLAGS", val);
    } else {
        eprintln!("Can't set MAKEFLAGS as CARGO_MAKEFLAGS couldn't be read");
    }
    let status = cmd
        .arg("-f")
        .arg(format!("{build_dir}/Makefile"))
        .arg("libs")
        .spawn()
        .expect(BUILD_ERROR_MSG)
        .wait()
        .expect(BUILD_ERROR_MSG);
    if !status.success() {
        panic!("make terminated unsuccessfully");
    }
}

pub fn build() -> (String, String) {
    let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(SRC_DIR);
    let build_dir = env::var_os("OUT_DIR").map_or(src_dir.to_owned(), PathBuf::from);
    let build_dir = build_dir.join("botan");
    let include_dir = build_dir.join(INCLUDE_DIR);
    let build_dir = pathbuf_to_string!(build_dir);
    env::set_current_dir(&src_dir).expect(SRC_DIR_ERROR_MSG);
    configure(&build_dir);
    make(&build_dir);
    (build_dir, pathbuf_to_string!(include_dir))
}
