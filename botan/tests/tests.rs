extern crate botan;

#[test]
fn test_version() {
    let version = botan::Version::new();

    assert_eq!(version.major, 2);
    assert!(version.release_date == 0 || version.release_date >= 20170000);
    assert!(version.ffi_api >= 20150000);

    println!("{:?}", version);
}

#[test]
fn test_hash() {
    let hash = botan::HashFunction::new("SHA-384").unwrap();

    assert_eq!(hash.output_length(), 48);

    assert!(hash.update(&[97,98]).is_ok());

    let hash_dup = hash.duplicate().unwrap();

    assert!(hash.update(&[99]).is_ok());
    assert!(hash_dup.update(&[100]).is_ok());

    let digest = hash.finish().unwrap();

    assert_eq!(digest[0], 0xCB);
    assert_eq!(digest[1], 0x00);
    assert_eq!(digest[47], 0xA7);

    let digest_dup = hash_dup.finish().unwrap();

    assert_eq!(digest_dup[0], 0x5D);
    assert_eq!(digest_dup[1], 0x15);
    assert_eq!(digest_dup[47], 0xF7);

    let bad_hash = botan::HashFunction::new("BunnyHash9000");

    assert_eq!(bad_hash.is_err(), true);
    assert_eq!(*bad_hash.as_ref().unwrap_err(), botan::Error::NotImplemented);
}


#[test]
fn test_mac() {
    let mac = botan::MsgAuthCode::new("HMAC(SHA-384)").unwrap();

    mac.set_key(&vec![0xAA; 20]).unwrap();

    mac.update(&vec![0xDD; 1]).unwrap();
    mac.update(&vec![0xDD; 29]).unwrap();
    mac.update(&vec![0xDD; 20]).unwrap();

    let r = mac.finish().unwrap();

    println!("{:?}", r);

    assert_eq!(r[0], 0x88);
    assert_eq!(r[1], 0x06);
    assert_eq!(r[47], 0x27);

}
