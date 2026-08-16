#![cfg(feature = "dynamic-loading")]

// This test file runs in its own process, so it can observe the state of the
// library loader before anything else has triggered loading

#[test]
fn test_dynamic_loading() -> Result<(), botan::Error> {
    assert!(botan::loaded_library_name().is_none());

    // Loading something that does not exist fails without affecting later loads
    let err = botan::load_library("/nonexistent/path/libbotan-3.so").unwrap_err();
    assert_eq!(err.error_type(), botan::ErrorType::LibraryNotLoaded);
    assert!(botan::loaded_library_name().is_none());

    // The first use triggers the default search
    let version = botan::Version::current()?;
    println!(
        "Loaded {:?} from {:?}",
        version,
        botan::loaded_library_name()
    );
    let name = botan::loaded_library_name().expect("library was loaded");
    assert!(name.contains("botan"));

    // Once loaded the library cannot be replaced
    let err = botan::load_library(name).unwrap_err();
    assert_eq!(err.error_type(), botan::ErrorType::InvalidObjectState);

    // And it works
    let mut hash = botan::HashFunction::new("SHA-256")?;
    hash.update(b"abc")?;
    let digest = hash.finish()?;
    assert_eq!(digest[0], 0xBA);
    assert_eq!(digest[31], 0xAD);

    Ok(())
}
