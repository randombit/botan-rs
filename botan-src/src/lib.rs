use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

const BUILD_ERROR_MSG: &str = "Unable to build botan.";
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

/// `configure.py` options taking a value, settable through [`Config`] and
/// read from `BOTAN_CONFIGURE_*` by [`Config::from_env`].
const VALUE_OPTIONS: [&str; 12] = [
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
];

/// Boolean `configure.py` options, settable through [`Config`] and enabled
/// by the presence of `BOTAN_CONFIGURE_*` in [`Config::from_env`].
const FLAG_OPTIONS: [&str; 4] = [
    "--optimize-for-size",
    "--amalgamation",
    "--with-commoncrypto",
    "--with-sqlite3",
];

fn env_name_for(opt: &str) -> String {
    assert!(opt[0..2] == *"--");
    let to_var = opt[2..].to_uppercase().replace('-', "_");
    format!("BOTAN_CONFIGURE_{to_var}")
}

fn split_modules(list: &str) -> Vec<String> {
    list.split(',')
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .map(String::from)
        .collect()
}

/// Describes how Botan should be configured and built by [`build_with`].
///
/// A `Config` is a plain value, so a build script can set the compiler,
/// module list and so on without mutating the process environment. The
/// only environment variables [`build_with`] itself consults are the
/// Cargo-provided `OUT_DIR`, `CARGO_CFG_TARGET_ARCH` and
/// `CARGO_CFG_TARGET_OS`, and only for settings the caller did not provide.
///
/// [`Config::from_env`] builds one from the `BOTAN_SRC_*` and
/// `BOTAN_CONFIGURE_*` environment variables, which is what [`build`] does.
/// Start from [`Config::from_env`] to let end users override settings, or
/// from [`Config::new`] for full control, then use the builder methods.
///
/// ```no_run
/// let config = botan_src::Config::from_env()
///     .enable_modules(["ml_kem", "ml_dsa"])
///     .amalgamation(true);
/// let (lib_dir, include_dir) = botan_src::build_with(&config);
/// ```
#[derive(Debug, Clone)]
pub struct Config {
    out_dir: Option<PathBuf>,
    src_dir: Option<PathBuf>,
    src_tarball: Option<PathBuf>,
    target_arch: Option<String>,
    target_os: Option<String>,
    with_debug_info: bool,
    enable_modules: Vec<String>,
    disable_modules: Vec<String>,
    values: BTreeMap<&'static str, String>,
    flags: BTreeSet<&'static str>,
    extra_configure_args: Vec<String>,
}

impl Default for Config {
    /// The default configuration: build the bundled tarball for the Cargo
    /// target, with debug info if this crate was compiled with debug
    /// assertions, and using the amalgamation on Windows (where the linker
    /// command lines otherwise become too long).
    fn default() -> Self {
        let mut flags = BTreeSet::new();
        if cfg!(target_os = "windows") {
            flags.insert("--amalgamation");
        }
        Self {
            out_dir: None,
            src_dir: None,
            src_tarball: None,
            target_arch: None,
            target_os: None,
            with_debug_info: cfg!(debug_assertions),
            enable_modules: Vec::new(),
            disable_modules: Vec::new(),
            values: BTreeMap::new(),
            flags,
            extra_configure_args: Vec::new(),
        }
    }
}

macro_rules! value_setters {
    ($($(#[$m:meta])* $name:ident => $opt:literal,)*) => {
        impl Config {
            $(
                $(#[$m])*
                #[doc = concat!("\n\nPasses `", $opt, "=<value>` to `configure.py`.")]
                pub fn $name(self, value: impl Into<String>) -> Self {
                    self.value($opt, value)
                }
            )*
        }
    };
}

macro_rules! flag_setters {
    ($($(#[$m:meta])* $name:ident => $opt:literal,)*) => {
        impl Config {
            $(
                $(#[$m])*
                #[doc = concat!("\n\nControls whether `", $opt, "` is passed to `configure.py`.")]
                pub fn $name(self, enable: bool) -> Self {
                    self.flag($opt, enable)
                }
            )*
        }
    };
}

value_setters! {
    /// Compiler cache (eg `ccache`) to prefix compiler invocations with.
    compiler_cache => "--compiler-cache",
    /// Compiler family to configure for (eg `gcc`, `clang`, `msvc`).
    cc => "--cc",
    /// Compiler binary to invoke.
    cc_bin => "--cc-bin",
    /// ABI flags passed to both the compiler and the linker.
    cc_abi_flags => "--cc-abi-flags",
    /// Replace the default compiler flags entirely.
    cxxflags => "--cxxflags",
    /// Add to the default compiler flags.
    extra_cxxflags => "--extra-cxxflags",
    /// Linker flags.
    ldflags => "--ldflags",
    /// Archiver command.
    ar_command => "--ar-command",
    /// Archiver options.
    ar_options => "--ar-options",
    /// MSVC runtime to link against (eg `MT`, `MD`).
    msvc_runtime => "--msvc-runtime",
    /// Path to the system certificate bundle.
    system_cert_bundle => "--system-cert-bundle",
    /// Module policy (eg `modern`, `bsi`, `nist`).
    module_policy => "--module-policy",
}

flag_setters! {
    /// Optimize for size rather than speed.
    optimize_for_size => "--optimize-for-size",
    /// Build from a single amalgamated source file. Defaults to enabled on
    /// Windows.
    amalgamation => "--amalgamation",
    /// Enable use of Apple's CommonCrypto.
    with_commoncrypto => "--with-commoncrypto",
    /// Enable use of SQLite3.
    with_sqlite3 => "--with-sqlite3",
}

impl Config {
    /// Equivalent to [`Config::default`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a configuration from the process environment.
    ///
    /// Starting from [`Config::default`], this applies:
    ///
    /// - `BOTAN_SRC_DIR` — see [`Config::src_dir`]
    /// - `BOTAN_SRC_TARBALL` — see [`Config::src_tarball`]
    /// - `BOTAN_CONFIGURE_ENABLE_MODULES` / `BOTAN_CONFIGURE_DISABLE_MODULES`
    ///   — comma separated lists, see [`Config::enable_modules`] and
    ///   [`Config::disable_modules`]
    /// - `BOTAN_CONFIGURE_<OPTION>` for each of the other `configure.py`
    ///   options that have a builder method here, eg `BOTAN_CONFIGURE_CC`
    ///   for [`Config::cc`] or `BOTAN_CONFIGURE_AMALGAMATION` (any value)
    ///   for [`Config::amalgamation`]
    ///
    /// Each variable is registered with Cargo via `rerun-if-env-changed`, so
    /// this must be called from a build script.
    pub fn from_env() -> Self {
        let mut config = Self::default();

        println!("cargo:rerun-if-env-changed=BOTAN_SRC_DIR");
        if let Some(dir) = env::var_os("BOTAN_SRC_DIR") {
            config = config.src_dir(dir);
        }
        println!("cargo:rerun-if-env-changed=BOTAN_SRC_TARBALL");
        if let Some(tarball) = env::var_os("BOTAN_SRC_TARBALL") {
            config = config.src_tarball(tarball);
        }

        for (opt, modules) in [
            ("--enable-modules", &mut config.enable_modules),
            ("--disable-modules", &mut config.disable_modules),
        ] {
            let env_name = env_name_for(opt);
            println!("cargo:rerun-if-env-changed={env_name}");
            if let Ok(list) = env::var(env_name) {
                modules.extend(split_modules(&list));
            }
        }

        for opt in VALUE_OPTIONS {
            let env_name = env_name_for(opt);
            println!("cargo:rerun-if-env-changed={env_name}");
            if let Ok(val) = env::var(env_name) {
                config = config.value(opt, val);
            }
        }

        for opt in FLAG_OPTIONS {
            let env_name = env_name_for(opt);
            println!("cargo:rerun-if-env-changed={env_name}");
            if env::var_os(env_name).is_some() {
                config = config.flag(opt, true);
            }
        }

        config
    }

    /// Directory to extract and build in. Defaults to Cargo's `OUT_DIR`.
    pub fn out_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.out_dir = Some(dir.into());
        self
    }

    /// Build from an existing Botan source tree (eg a git checkout) rather
    /// than extracting a tarball. No checksum is verified. Takes precedence
    /// over [`Config::src_tarball`].
    pub fn src_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.src_dir = Some(dir.into());
        self
    }

    /// Extract this `.tar.xz` instead of the bundled release. No checksum is
    /// verified.
    pub fn src_tarball(mut self, tarball: impl Into<PathBuf>) -> Self {
        self.src_tarball = Some(tarball.into());
        self
    }

    /// Value passed to `configure.py --cpu`. Defaults to Cargo's
    /// `CARGO_CFG_TARGET_ARCH`.
    pub fn target_arch(mut self, arch: impl Into<String>) -> Self {
        self.target_arch = Some(arch.into());
        self
    }

    /// Value passed to `configure.py --os`. Defaults to Cargo's
    /// `CARGO_CFG_TARGET_OS`.
    pub fn target_os(mut self, os: impl Into<String>) -> Self {
        self.target_os = Some(os.into());
        self
    }

    /// Controls whether `--with-debug-info` is passed to `configure.py`.
    /// Defaults to enabled if this crate was compiled with debug assertions.
    pub fn with_debug_info(mut self, enable: bool) -> Self {
        self.with_debug_info = enable;
        self
    }

    /// Adds modules to `--enable-modules`. Accumulates across calls.
    pub fn enable_modules<I, S>(mut self, modules: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.enable_modules
            .extend(modules.into_iter().map(Into::into));
        self
    }

    /// Adds modules to `--disable-modules`. Accumulates across calls.
    pub fn disable_modules<I, S>(mut self, modules: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.disable_modules
            .extend(modules.into_iter().map(Into::into));
        self
    }

    /// Passes an arbitrary additional argument to `configure.py`, for
    /// options without a dedicated builder method. Use with care: the
    /// argument is not checked against those generated from the rest of
    /// the configuration.
    pub fn configure_arg(mut self, arg: impl Into<String>) -> Self {
        self.extra_configure_args.push(arg.into());
        self
    }

    fn value(mut self, opt: &'static str, value: impl Into<String>) -> Self {
        self.values.insert(opt, value.into());
        self
    }

    fn flag(mut self, opt: &'static str, enable: bool) -> Self {
        if enable {
            self.flags.insert(opt);
        } else {
            self.flags.remove(opt);
        }
        self
    }

    fn cargo_env(&self, name: &str) -> String {
        env::var(name).unwrap_or_else(|_| {
            panic!("{name} is set when invoked from a build script; otherwise supply it via Config")
        })
    }

    fn resolved_out_dir(&self) -> PathBuf {
        self.out_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(self.cargo_env("OUT_DIR")))
    }

    fn configure_args(&self, build_dir: &str) -> Vec<String> {
        let mut args = vec![
            format!("--with-build-dir={build_dir}"),
            "--build-targets=static".to_string(),
            "--without-documentation".to_string(),
            "--no-install-python-module".to_string(),
            "--distribution-info=https://crates.io/crates/botan-src".to_string(),
        ];

        let cpu = self
            .target_arch
            .clone()
            .unwrap_or_else(|| self.cargo_env("CARGO_CFG_TARGET_ARCH"));
        args.push(format!("--cpu={cpu}"));
        let os = self
            .target_os
            .clone()
            .unwrap_or_else(|| self.cargo_env("CARGO_CFG_TARGET_OS"));
        args.push(format!("--os={os}"));

        if self.with_debug_info {
            args.push("--with-debug-info".to_string());
        }

        for (opt, modules) in [
            ("--enable-modules", &self.enable_modules),
            ("--disable-modules", &self.disable_modules),
        ] {
            if !modules.is_empty() {
                args.push(format!("{opt}={}", modules.join(",")));
            }
        }

        for (opt, val) in &self.values {
            args.push(format!("{opt}={val}"));
        }

        for flag in &self.flags {
            args.push(flag.to_string());
        }

        args.extend(self.extra_configure_args.iter().cloned());
        args
    }
}

fn configure(config: &Config, src_dir: &Path, build_dir: &str) {
    let mut configure = Command::new("python3");
    configure.current_dir(src_dir);
    configure.arg("configure.py");
    configure.args(config.configure_args(build_dir));

    let status = configure
        .spawn()
        .expect(BUILD_ERROR_MSG)
        .wait()
        .expect(BUILD_ERROR_MSG);
    if !status.success() {
        panic!("configure terminated unsuccessfully");
    }
}

fn make(src_dir: &Path, build_dir: &str) {
    // On Windows the Botan Makefile is generated for the MSVC toolchain, whose
    // standard build tool is `nmake` (ships with Visual Studio and is on PATH
    // inside a VS developer environment). GNU make is frequently absent from
    // Windows build images, so use nmake there. nmake does not support GNU
    // Make's jobserver or parallel target execution, so CARGO_MAKEFLAGS is not
    // forwarded on Windows.
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut cmd = Command::new("nmake");
        cmd.arg("/NOLOGO")
            .arg("/F")
            .arg(format!("{build_dir}/Makefile"))
            .arg("libs");
        cmd
    };

    #[cfg(not(target_os = "windows"))]
    let mut cmd = {
        let mut cmd = Command::new("make");
        // Set MAKEFLAGS to the content of CARGO_MAKEFLAGS to give jobserver
        // (parallel builds) support to the spawned sub-make.
        if let Ok(val) = env::var("CARGO_MAKEFLAGS") {
            cmd.env("MAKEFLAGS", val);
        } else {
            eprintln!("Can't set MAKEFLAGS as CARGO_MAKEFLAGS couldn't be read");
        }
        cmd.arg("-f")
            .arg(format!("{build_dir}/Makefile"))
            .arg("libs");
        cmd
    };

    let status = cmd
        .current_dir(src_dir)
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
/// - [`Config::src_dir`] — use this directory as the source tree directly
///   (no extraction, no checksum). Useful for testing a local git
///   checkout or fork.
/// - [`Config::src_tarball`] — extract this `.tar.xz` instead of the
///   bundled one. No checksum: the caller is responsible for what they
///   hand us.
/// - otherwise: extract the bundled `vendor/Botan-X.Y.Z.tar.xz`,
///   verifying it matches the pinned SHA-256.
fn ensure_source(config: &Config, out_dir: &Path) -> PathBuf {
    if let Some(path) = &config.src_dir {
        if !path.join("configure.py").is_file() {
            panic!(
                "Botan source dir {} does not contain configure.py",
                path.display()
            );
        }
        return path.clone();
    }

    let custom_tarball = config.src_tarball.as_ref();
    let tarball = custom_tarball.cloned().unwrap_or_else(bundled_tarball_path);
    let stamp_marker = match custom_tarball {
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

/// Builds Botan as configured by the `BOTAN_SRC_*` and `BOTAN_CONFIGURE_*`
/// environment variables.
///
/// Equivalent to `build_with(&Config::from_env())`; see [`Config::from_env`]
/// for the variables consulted.
pub fn build() -> (String, PathBuf) {
    build_with(&Config::from_env())
}

/// Builds Botan as a static library according to `config`.
///
/// Returns the directory containing the built library, and the directory
/// containing its public headers. Panics if the build fails.
///
/// Unless overridden in `config`, the output directory and target are taken
/// from the Cargo build script environment, so this is expected to be called
/// from a build script.
pub fn build_with(config: &Config) -> (String, PathBuf) {
    let out_dir = config.resolved_out_dir();
    let src_dir = ensure_source(config, &out_dir);
    let build_dir = out_dir.join("botan-build");
    let include_dir = build_dir.join(INCLUDE_DIR);
    let build_dir = pathbuf_to_string!(build_dir);
    configure(config, &src_dir, &build_dir);
    make(&src_dir, &build_dir);
    (build_dir, include_dir)
}
