// Builds Botan into the directory given as the first argument (or `OUT_DIR`
// if not given), using the same environment variables a build script would
// consult, plus any extra `configure.py` arguments passed after it.
fn main() {
    let mut args = std::env::args().skip(1);
    let mut config = botan_src::Config::from_env();
    if let Some(out_dir) = args.next() {
        config = config.out_dir(out_dir);
    }
    for arg in args {
        config = config.configure_arg(arg);
    }
    let (lib_dir, include_dir) = botan_src::build_with(&config);
    println!("Library directory: {lib_dir}");
    println!("Include directory: {}", include_dir.display());
}
