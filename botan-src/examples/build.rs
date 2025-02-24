fn main() {
    let (lib_dir, include_dir) = botan_src::build();
    println!("Library directory: {lib_dir}");
    println!("Include directory: {}", include_dir.display());
}
