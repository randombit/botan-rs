use wycheproof::{EllipticCurve, HashFunction, TestResult};

fn hash_id_to_str(hash: HashFunction) -> Option<&'static str> {
    match hash {
        HashFunction::Sha1 => Some("SHA-1"),
        HashFunction::Sha2_224 => Some("SHA-224"),
        HashFunction::Sha2_256 => Some("SHA-256"),
        HashFunction::Sha2_384 => Some("SHA-384"),
        HashFunction::Sha2_512 => Some("SHA-512"),
        HashFunction::Sha2_512_224 => None,
        HashFunction::Sha2_512_256 => Some("SHA-512-256"),
        HashFunction::Sha3_224 => Some("SHA-3(224)"),
        HashFunction::Sha3_256 => Some("SHA-3(256)"),
        HashFunction::Sha3_384 => Some("SHA-3(384)"),
        HashFunction::Sha3_512 => Some("SHA-3(512)"),
    }
}

#[test]
fn test_wycheproof_rsa_pkcs1_verify() -> Result<(), botan::Error> {
    use wycheproof::rsa_pkcs1_verify::*;

    for test_name in TestName::all() {
        let test_set = TestSet::load(test_name).expect("OK");

        for test_group in &test_set.test_groups {
            let hash = match hash_id_to_str(test_group.hash) {
                Some(hash) => hash,
                None => continue,
            };

            let key = botan::Pubkey::load_der(&test_group.der)?;

            let mut verifier = botan::Verifier::new(&key, &format!("EMSA_PKCS1({})", hash))?;

            for test in &test_group.tests {
                verifier.update(&test.msg)?;
                let accept = verifier.finish(&test.sig)?;

                match (accept, test.result) {
                    (true, TestResult::Valid) => {}
                    (true, TestResult::Acceptable) => {}
                    (true, TestResult::Invalid) => {
                        panic!("Accepted an invalid signature");
                    }
                    (false, TestResult::Valid) => {
                        panic!("Rejected a valid signature");
                    }
                    (false, TestResult::Acceptable) => {}
                    (false, TestResult::Invalid) => {}
                }
            }
        }
    }

    Ok(())
}

#[test]
fn test_wycheproof_rsa_pss_verify() -> Result<(), botan::Error> {
    use wycheproof::rsa_pss_verify::*;

    let is_botan2 = botan::Version::current()?.major == 2;

    fn form_pssr_format(group: &TestGroup) -> Option<String> {
        // MGF hash != hash -> not supported
        if group.hash != group.mgf_hash {
            return None;
        }
        // Something other than MGF1 -> not supported
        if group.mgf != wycheproof::Mgf::Mgf1 {
            return None;
        }

        let hash = match hash_id_to_str(group.hash) {
            Some(hash) => hash,
            None => return None,
        };

        Some(format!("EMSA4({},MGF1,{})", hash, group.salt_length))
    }

    for test_name in TestName::all() {
        let test_set = TestSet::load(test_name).expect("OK");

        for test_group in &test_set.test_groups {
            let key = botan::Pubkey::load_der(&test_group.der)?;

            let pssr_config = match form_pssr_format(test_group) {
                Some(config) => config,
                None => continue,
            };

            let mut verifier = botan::Verifier::new(&key, &pssr_config)?;

            for test in &test_group.tests {
                if is_botan2 && test.comment == "prepending 0's to signature" {
                    continue;
                }

                verifier.update(&test.msg)?;
                let accept = verifier.finish(&test.sig)?;

                match (accept, test.result) {
                    (true, TestResult::Valid) => {}
                    (true, TestResult::Acceptable) => {}
                    (true, TestResult::Invalid) => {
                        panic!("Accepted an invalid signature ({})", test.comment);
                    }
                    (false, TestResult::Valid) => {
                        panic!("Rejected a valid signature ({})", test.comment);
                    }
                    (false, TestResult::Acceptable) => {}
                    (false, TestResult::Invalid) => {}
                }
            }
        }
    }

    Ok(())
}

#[test]
fn test_wycheproof_dsa() -> Result<(), botan::Error> {
    use wycheproof::dsa::*;

    for test_name in TestName::all() {
        let is_ieee = format!("{:?}", test_name).contains("P1363");
        let test_set = TestSet::load(test_name).expect("OK");

        for test_group in &test_set.test_groups {
            let hash = match hash_id_to_str(test_group.hash) {
                Some(hash) => hash,
                None => continue,
            };

            let key = botan::Pubkey::load_der(&test_group.der)?;

            for test in &test_group.tests {
                // Has to be inside the loop to work around the bug addressed in
                // https://github.com/randombit/botan/pull/3333
                let mut verifier = if is_ieee {
                    botan::Verifier::new(&key, &format!("EMSA1({})", hash))?
                } else {
                    botan::Verifier::new_with_der_formatted_signatures(
                        &key,
                        &format!("EMSA1({})", hash),
                    )?
                };

                verifier.update(&test.msg)?;
                let accept = verifier.finish(&test.sig)?;

                match (accept, test.result) {
                    (true, TestResult::Valid) => {}
                    (true, TestResult::Acceptable) => {
                        panic!("Accepted an 'acceptable' signature");
                    }
                    (true, TestResult::Invalid) => {
                        panic!("Accepted an invalid signature");
                    }
                    (false, TestResult::Valid) => {
                        panic!("Rejected a valid signature");
                    }
                    (false, TestResult::Acceptable) => {}
                    (false, TestResult::Invalid) => {}
                }
            }
        }
    }

    Ok(())
}

fn curve_id_to_str(curve: EllipticCurve) -> Option<&'static str> {
    match curve {
        EllipticCurve::Secp224r1 => Some("secp224r1"),
        EllipticCurve::Secp256r1 => Some("secp256r1"),
        EllipticCurve::Secp384r1 => Some("secp384r1"),
        EllipticCurve::Secp521r1 => Some("secp521r1"),
        EllipticCurve::Secp224k1 => Some("secp224k1"),
        EllipticCurve::Secp256k1 => Some("secp256k1"),
        EllipticCurve::Brainpool224r1 => Some("brainpool224r1"),
        EllipticCurve::Brainpool256r1 => Some("brainpool256r1"),
        EllipticCurve::Brainpool320r1 => Some("brainpool320r1"),
        EllipticCurve::Brainpool384r1 => Some("brainpool384r1"),
        EllipticCurve::Brainpool512r1 => Some("brainpool512r1"),
        EllipticCurve::Brainpool224t1 => None,
        EllipticCurve::Brainpool256t1 => None,
        EllipticCurve::Brainpool320t1 => None,
        EllipticCurve::Brainpool384t1 => None,
        EllipticCurve::Brainpool512t1 => None,
    }
}

#[test]
fn test_wycheproof_ecdsa() -> Result<(), botan::Error> {
    use wycheproof::ecdsa::*;

    let is_botan2 = botan::Version::current()?.major == 2;

    for test_name in TestName::all() {
        let is_ieee =
            test_name == TestName::EcdsaWebcrypto || format!("{:?}", test_name).contains("P1363");

        let test_set = TestSet::load(test_name).expect("OK");

        for test_group in &test_set.test_groups {
            if curve_id_to_str(test_group.key.curve) == None {
                continue;
            }

            let hash = match hash_id_to_str(test_group.hash) {
                Some(hash) => hash,
                None => continue,
            };

            if is_botan2 && test_group.key.curve == EllipticCurve::Secp224k1 && hash == "SHA-256" {
                continue;
            }

            let key = botan::Pubkey::load_der(&test_group.der)?;

            for test in &test_group.tests {
                // Has to be inside the loop to work around the bug addressed in
                // https://github.com/randombit/botan/pull/3333
                let mut verifier = if is_ieee {
                    botan::Verifier::new(&key, &format!("EMSA1({})", hash))?
                } else {
                    botan::Verifier::new_with_der_formatted_signatures(
                        &key,
                        &format!("EMSA1({})", hash),
                    )?
                };

                verifier.update(&test.msg)?;
                let accept = verifier.finish(&test.sig)?;

                match (accept, test.result) {
                    (true, TestResult::Valid) => {}
                    (true, TestResult::Acceptable) => {
                        if test.flags != vec![TestFlag::WeakHash] {
                            panic!("Accepted an acceptable signature");
                        }
                    }
                    (true, TestResult::Invalid) => {
                        panic!("Accepted an invalid signature");
                    }
                    (false, TestResult::Valid) => {
                        panic!("Rejected a valid signature");
                    }
                    (false, TestResult::Acceptable) => {}
                    (false, TestResult::Invalid) => {}
                }
            }
        }
    }

    Ok(())
}

#[test]
fn test_wycheproof_ecdh() -> Result<(), botan::Error> {
    use wycheproof::ecdh::*;

    for test_name in TestName::all() {
        let test_set = TestSet::load(test_name).expect("OK");

        for test_group in &test_set.test_groups {
            let curve_id = match curve_id_to_str(test_group.curve) {
                Some(curve_id) => curve_id,
                None => continue,
            };

            if test_group.encoding != EcdhEncoding::EcPoint {
                continue;
            }

            for test in &test_group.tests {
                let s = botan::MPI::new_from_bytes(&test.private_key)?;
                let priv_key = botan::Privkey::load_ecdh(&s, &curve_id)?;

                let mut ka = botan::KeyAgreement::new(&priv_key, "Raw")?;

                let shared_secret = ka.agree(0, &test.public_key, &[]);

                if test.result == TestResult::Valid || test.result == TestResult::Acceptable {
                    match shared_secret {
                        Ok(shared_secret) => assert_eq!(shared_secret, test.shared_secret),
                        Err(e) => panic!("Unable to compute shared secret ({:?})", e),
                    }
                } else {
                    assert!(shared_secret.is_err());
                }
            }
        }
    }

    Ok(())
}
