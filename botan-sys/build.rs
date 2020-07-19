fn main() {
    #[cfg(feature = "vendored")]
    {
        let (lib_dir, _) = botan_src::build();
        println!("cargo:vendored=1");
        println!("cargo:rustc-link-search=native={}", &lib_dir);
        println!("cargo:rustc-link-lib=static=botan-2");
        println!("cargo:rustc-flags=-l dylib=stdc++");
    }
    #[cfg(not(feature = "vendored"))]
    {
        println!("cargo:rustc-link-lib=botan-2");
    }
}
