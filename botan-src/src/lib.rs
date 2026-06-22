use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

const BUILD_ERROR_MSG: &str = "Unable to build botan.";
const SRC_DIR_ERROR_MSG: &str = "Unable to find the source directory.";
const INCLUDE_DIR: &str = "build/include/public";

// Pinned upstream release. Single source of truth lives in release.toml;
// build.rs parses that file and re-exports it via `cargo:rustc-env`.
pub const BOTAN_VERSION: &str = env!("BOTAN_VERSION");
pub const BOTAN_TARBALL_SHA256: &str = env!("BOTAN_TARBALL_SHA256");
pub const BOTAN_TARBALL_URL: &str = env!("BOTAN_TARBALL_URL");

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

    configure.arg(format!(
        "--cpu={}",
        env::var("CARGO_CFG_TARGET_ARCH").unwrap()
    ));
    configure.arg(format!("--os={}", env::var("CARGO_CFG_TARGET_OS").unwrap()));

    #[cfg(debug_assertions)]
    configure.arg("--with-debug-info");

    // On Windows we require the amalgamation, to work around the fact that
    // otherwise the linker command lines become too long for Windows
    #[cfg(target_os = "windows")]
    configure.arg("--amalgamation");

    let args = [
        "--compiler-cache",
        "--cc",
        "--cc-bin",
        "--cc-abi-flags",
        "--cxxflags",
        "--extra-cxxflags",
        "--ldflags",
        "--ar-command",
        "--ar-options",
        "--msvc-runtime",
        "--system-cert-bundle",
        "--module-policy",
        "--enable-modules",
        "--disable-modules",
    ];

    let flags = [
        "--optimize-for-size",
        "--amalgamation",
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

fn bundled_tarball_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("vendor")
        .join(format!("Botan-{BOTAN_VERSION}.tar.xz"))
}

fn verify_sha256(path: &Path) {
    use sha2::{Digest, Sha256};
    let bytes = fs::read(path).expect("read tarball");
    let actual = format!("{:x}", Sha256::digest(&bytes));
    if actual != BOTAN_TARBALL_SHA256 {
        panic!(
            "Botan tarball at {} has unexpected sha256 (expected {}, got {})",
            path.display(),
            BOTAN_TARBALL_SHA256,
            actual,
        );
    }
}

fn extract_tarball(tarball: &Path, dest: &Path) {
    let file = fs::File::open(tarball).expect("open tarball");
    let mut reader = io::BufReader::new(file);
    let mut decompressed = Vec::new();
    lzma_rs::xz_decompress(&mut reader, &mut decompressed).expect("xz decompress");
    let mut archive = tar::Archive::new(io::Cursor::new(decompressed));

    // Windows without Developer Mode (or admin rights) cannot create symlinks.
    // The Botan tarball contains a handful of symlinks (e.g. .github/codecov.yml)
    // that are not needed to build the library. Skip them on Windows only.
    #[cfg(target_os = "windows")]
    {
        for entry in archive.entries().expect("read archive entries") {
            let mut entry = entry.expect("read archive entry");
            let entry_type = entry.header().entry_type();
            if entry_type.is_symlink() || entry_type.is_hard_link() {
                continue;
            }
            entry.unpack_in(dest).expect("unpack entry");
        }
    }

    #[cfg(not(target_os = "windows"))]
    archive.unpack(dest).expect("untar");
}

// After unpacking, find the single top-level directory the tarball
// produced. Bundled Botan releases use `Botan-X.Y.Z`, but a developer's
// custom tarball (BOTAN_SRC_TARBALL) might use anything.
fn find_extracted_root(extract_root: &Path) -> PathBuf {
    let mut dirs = fs::read_dir(extract_root)
        .expect("read extract root")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir());
    let first = dirs
        .next()
        .expect("tarball produced no top-level directory");
    if dirs.next().is_some() {
        panic!("tarball must contain exactly one top-level directory");
    }
    first
}

/// Returns the directory containing Botan sources to build against.
///
/// Resolution order, highest priority first:
/// - `BOTAN_SRC_DIR` — use this directory as the source tree directly
///   (no extraction, no checksum). Useful for testing a local git
///   checkout or fork.
/// - `BOTAN_SRC_TARBALL` — extract this `.tar.xz` instead of the bundled
///   one. No checksum: the caller is responsible for what they hand us.
/// - otherwise: extract the bundled `vendor/Botan-X.Y.Z.tar.xz`,
///   verifying it matches the pinned SHA-256.
fn ensure_source(out_dir: &Path) -> PathBuf {
    println!("cargo:rerun-if-env-changed=BOTAN_SRC_DIR");
    println!("cargo:rerun-if-env-changed=BOTAN_SRC_TARBALL");

    if let Some(custom_dir) = env::var_os("BOTAN_SRC_DIR") {
        let path = PathBuf::from(custom_dir);
        if !path.join("configure.py").is_file() {
            panic!(
                "BOTAN_SRC_DIR={} does not contain configure.py",
                path.display()
            );
        }
        return path;
    }

    let custom_tarball = env::var_os("BOTAN_SRC_TARBALL").map(PathBuf::from);
    let tarball = custom_tarball.clone().unwrap_or_else(bundled_tarball_path);
    let stamp_marker = match &custom_tarball {
        Some(p) => format!("custom:{}", p.display()),
        None => format!("bundled:{BOTAN_TARBALL_SHA256}"),
    };

    let extract_root = out_dir.join("botan-src");
    let stamp = extract_root.join(".extracted");
    let already_extracted = fs::read_to_string(&stamp)
        .map(|s| s.trim() == stamp_marker)
        .unwrap_or(false);
    if !already_extracted {
        if !tarball.exists() {
            panic!("Botan source tarball missing at {}", tarball.display());
        }
        if custom_tarball.is_none() {
            verify_sha256(&tarball);
        }
        let _ = fs::remove_dir_all(&extract_root);
        fs::create_dir_all(&extract_root).expect("mkdir extract root");
        extract_tarball(&tarball, &extract_root);
        fs::write(&stamp, &stamp_marker).expect("write stamp");
    }
    find_extracted_root(&extract_root)
}

pub fn build() -> (String, std::path::PathBuf) {
    let out_dir = env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .expect("OUT_DIR is set when invoked from a build script");
    let src_dir = ensure_source(&out_dir);
    let build_dir = out_dir.join("botan-build");
    let include_dir = build_dir.join(INCLUDE_DIR);
    let build_dir = pathbuf_to_string!(build_dir);
    let orig_dir = env::current_dir().expect(SRC_DIR_ERROR_MSG);
    env::set_current_dir(&src_dir).expect(SRC_DIR_ERROR_MSG);
    configure(&build_dir);
    make(&build_dir);
    env::set_current_dir(&orig_dir).expect("Unable to restore cwd");
    (build_dir, include_dir)
}
