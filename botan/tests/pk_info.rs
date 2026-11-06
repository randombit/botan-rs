use botan::{Error, ErrorType, MPI, Privkey, Pubkey, RandomNumberGenerator, SignatureParams};

// Only skip the first use of an independent algorithm or API. Once available,
// subsequent errors must fail the test.
macro_rules! skip_if_not_implemented {
    ($call:expr) => {
        match $call {
            Ok(value) => value,
            Err(e) if e.error_type() == ErrorType::NotImplemented => return Ok(()),
            Err(e) => return Err(e),
        }
    };
}

#[test]
fn rsa_metadata() -> Result<(), Error> {
    let mut rng = RandomNumberGenerator::new_system()?;
    let key = skip_if_not_implemented!(Privkey::create("RSA", "1024", &mut rng));
    let public = key.pubkey()?;
    let private_oid = skip_if_not_implemented!(key.oid());
    let public_oid = public.oid()?;
    assert!(!key.is_stateful()?);
    assert_eq!(key.remaining_operations()?, None);

    // The returned OIDs own their handles independently of the keys.
    drop(key);
    drop(public);
    assert_eq!(private_oid.as_string()?, "1.2.840.113549.1.1.1");
    assert_eq!(public_oid.as_string()?, "1.2.840.113549.1.1.1");
    assert!(private_oid.equals(&public_oid)?);
    Ok(())
}

#[test]
fn ec_algorithm_oid() -> Result<(), Error> {
    let scalar = MPI::new_from_u32(1)?;
    let key = skip_if_not_implemented!(Privkey::load_ecdsa(&scalar, "secp256r1"));
    let private_oid = skip_if_not_implemented!(key.oid());
    let public_oid = key.pubkey()?.oid()?;
    // This is id-ecPublicKey, not secp256r1's curve OID.
    assert_eq!(private_oid.as_string()?, "1.2.840.10045.2.1");
    assert!(private_oid.equals(&public_oid)?);
    Ok(())
}

#[test]
fn ec_parameter_encoding() -> Result<(), Error> {
    let scalar = MPI::new_from_u32(1)?;
    let named = skip_if_not_implemented!(Privkey::load_ecdsa(&scalar, "secp256r1"));
    let named = Pubkey::load_der(&named.pubkey()?.der_encode()?)?;
    assert!(!skip_if_not_implemented!(
        named.ecc_key_used_explicit_encoding()
    ));

    // Botan's src/tests/data/pubkey/ecc_explicit_curve.vec, secp256r1 fixture.
    // This tests the encoding indicator, not the cryptographic algorithm.
    let explicit_der = hex::decode(concat!(
        "308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101",
        "022100FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFF",
        "FFFF30440420FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFF",
        "FFFFFFFFFC04205AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE",
        "3C3E27D2604B0441046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0",
        "F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECB",
        "B6406837BF51F5022100FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84",
        "F3B9CAC2FC63255102010103420004CE00D94744EB2E486E86BB1A97B775BB002BBD",
        "93FF47879299A0774D5737905B11F120A5A959F5DF3E6DFA5E9EDD7D827A3D6D369",
        "548245F1AB9D37F8BC5C73E",
    ))
    .unwrap();
    let explicit = Pubkey::load_der(&explicit_der)?;
    assert!(explicit.ecc_key_used_explicit_encoding()?);

    let mut rng = RandomNumberGenerator::new_system()?;
    let rsa = skip_if_not_implemented!(Privkey::create("RSA", "1024", &mut rng));
    assert_eq!(
        rsa.pubkey()?
            .ecc_key_used_explicit_encoding()
            .unwrap_err()
            .error_type(),
        ErrorType::BadParameter
    );
    Ok(())
}

#[test]
fn stateful_remaining_operations() -> Result<(), Error> {
    let mut rng = RandomNumberGenerator::new_system()?;
    let key = skip_if_not_implemented!(Privkey::create("HSS-LMS", "SHA-256,HW(5,8)", &mut rng));
    let remaining = skip_if_not_implemented!(key.remaining_operations());
    assert!(key.is_stateful()?);
    assert_eq!(remaining, Some(32));
    assert_eq!(key.remaining_operations()?, remaining);
    key.sign(b"consume one operation", None::<SignatureParams>, &mut rng)?;
    assert_eq!(key.remaining_operations()?, Some(31));

    // A standalone Signer consumes operations in the same way
    let mut signer = botan::Signer::new(&key, None::<SignatureParams>)?;
    signer.update(b"consume another")?;
    assert_eq!(key.remaining_operations()?, Some(31));
    signer.finish(&mut rng)?;
    assert_eq!(key.remaining_operations()?, Some(30));
    Ok(())
}

#[test]
fn rsa_pkcs1_export() -> Result<(), Error> {
    let mut rng = RandomNumberGenerator::new_system()?;
    let key = skip_if_not_implemented!(Privkey::create("RSA", "1024", &mut rng));
    let pkcs8 = key.der_encode()?;
    let pkcs1 = key.der_encode_rsa_pkcs1()?;
    assert_ne!(pkcs1, pkcs8);
    let loaded = Privkey::load_rsa_pkcs1(&pkcs1)?;
    assert_eq!(loaded.der_encode()?, pkcs8);
    assert_eq!(loaded.der_encode_rsa_pkcs1()?, pkcs1);

    let pem = key.pem_encode_rsa_pkcs1()?;
    let body = pem
        .strip_prefix("-----BEGIN RSA PRIVATE KEY-----\n")
        .unwrap()
        .strip_suffix("-----END RSA PRIVATE KEY-----\n")
        .unwrap();
    assert!(!pem.contains('\0'));
    let decoded = botan::base64_decode(body)?;
    assert_eq!(decoded, pkcs1);
    assert_eq!(Privkey::load_rsa_pkcs1(&decoded)?.der_encode()?, pkcs8);

    let scalar = MPI::new_from_u32(1)?;
    let non_rsa = skip_if_not_implemented!(Privkey::load_ecdsa(&scalar, "secp256r1"));
    assert_eq!(
        non_rsa.der_encode_rsa_pkcs1().unwrap_err().error_type(),
        ErrorType::BadParameter
    );
    assert_eq!(
        non_rsa.pem_encode_rsa_pkcs1().unwrap_err().error_type(),
        ErrorType::BadParameter
    );
    Ok(())
}
