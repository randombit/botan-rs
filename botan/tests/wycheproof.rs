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

        HashFunction::Shake128 => Some("SHAKE-128(256)"),
        HashFunction::Shake256 => Some("SHAKE-256(512)"),
    }
}

#[test]
fn wycheproof_hkdf_tests() -> Result<(), botan::Error> {
    use wycheproof::hkdf::*;

    for test_set_name in TestName::all() {
        let test_set = TestSet::load(test_set_name).expect("Loading tests failed");

        for test_group in test_set.test_groups {
            let hkdf_name = match test_set.algorithm {
                Algorithm::HkdfSha1 => "HKDF(SHA-1)",
                Algorithm::HkdfSha256 => "HKDF(SHA-256)",
                Algorithm::HkdfSha384 => "HKDF(SHA-384)",
                Algorithm::HkdfSha512 => "HKDF(SHA-512)",
            };

            for test in &test_group.tests {
                if test.flags.contains(&TestFlag::SizeTooLarge) {
                    continue;
                }

                let output = botan::kdf(hkdf_name, test.size, &test.ikm, &test.salt, &test.info)?;

                assert_eq!(output, test.okm.as_ref());
            }
        }
    }

    Ok(())
}

#[test]
fn wycheproof_keywrap_tests() -> Result<(), botan::Error> {
    use wycheproof::keywrap::*;

    let is_botan2 = botan::Version::current()?.major == 2;

    for test_set_name in TestName::all() {
        let test_set = TestSet::load(test_set_name).unwrap();

        if test_set.algorithm != Algorithm::AesKeyWrap {
            continue;
        }

        for test_group in &test_set.test_groups {
            for test in &test_group.tests {
                if is_botan2 && test.pt.len() == 8 {
                    continue;
                }

                if !test.result.must_fail() {
                    let wrapped = botan::rfc3394_key_wrap(&test.key, &test.pt)?;
                    assert_eq!(wrapped, test.ct.as_ref());

                    let unwrapped = botan::rfc3394_key_unwrap(&test.key, &test.ct)?;
                    assert_eq!(unwrapped, test.pt.as_ref());
                }
            }
        }
    }

    Ok(())
}

#[cfg(feature = "botan3")]
#[test]
fn wycheproof_nist_kw_tests() -> Result<(), botan::Error> {
    use wycheproof::keywrap::*;

    for test_set_name in TestName::all() {
        let test_set = TestSet::load(test_set_name).unwrap();

        for test_group in &test_set.test_groups {
            let (cipher, padding) = match (test_set.algorithm, test_group.key_size) {
                (Algorithm::AesKeyWrap, 128) => ("AES-128", false),
                (Algorithm::AesKeyWrap, 192) => ("AES-192", false),
                (Algorithm::AesKeyWrap, 256) => ("AES-256", false),
                (Algorithm::AesKeyWrapWithPadding, 128) => ("AES-128", true),
                (Algorithm::AesKeyWrapWithPadding, 192) => ("AES-192", true),
                (Algorithm::AesKeyWrapWithPadding, 256) => ("AES-256", true),

                (Algorithm::AriaKeyWrap, 128) => ("ARIA-128", false),
                (Algorithm::AriaKeyWrap, 192) => ("ARIA-192", false),
                (Algorithm::AriaKeyWrap, 256) => ("ARIA-256", false),
                (Algorithm::AriaKeyWrapWithPadding, 128) => ("ARIA-128", true),
                (Algorithm::AriaKeyWrapWithPadding, 192) => ("ARIA-192", true),
                (Algorithm::AriaKeyWrapWithPadding, 256) => ("ARIA-256", true),

                (Algorithm::CamelliaKeyWrap, 128) => ("Camellia-128", false),
                (Algorithm::CamelliaKeyWrap, 192) => ("Camellia-192", false),
                (Algorithm::CamelliaKeyWrap, 256) => ("Camellia-256", false),

                (Algorithm::SeedKeyWrap, 128) => ("SEED", false),

                (bc, kl) => panic!("Unhandled block cipher {:?}/{}", bc, kl),
            };

            for test in &test_group.tests {
                if test.result.must_fail() {
                    assert!(botan::nist_kw_dec(cipher, padding, &test.key, &test.ct).is_err());
                } else {
                    let wrapped = botan::nist_kw_enc(cipher, padding, &test.key, &test.pt)?;
                    assert_eq!(wrapped, test.ct.as_ref());

                    let unwrapped = botan::nist_kw_dec(cipher, padding, &test.key, &test.ct)?;
                    assert_eq!(unwrapped, test.pt.as_ref());
                }
            }
        }
    }

    Ok(())
}

#[test]
fn wycheproof_cipher_tests() -> Result<(), botan::Error> {
    use wycheproof::cipher::*;

    let is_botan2 = botan::Version::current()?.major == 2;

    for test_set_name in TestName::all() {
        let test_set = TestSet::load(test_set_name).expect("Loading tests failed");

        let is_xts = test_set.algorithm == Algorithm::AesXts;

        for test_group in test_set.test_groups {
            if is_botan2 && is_xts && test_group.nonce_size != 128 {
                // Botan2 does not support short nonces with XTS
                continue;
            }

            let cipher_name = match (test_set.algorithm, test_group.key_size) {
                (Algorithm::AesCbcPkcs5, 128) => "AES-128/CBC",
                (Algorithm::AesCbcPkcs5, 192) => "AES-192/CBC",
                (Algorithm::AesCbcPkcs5, 256) => "AES-256/CBC",
                (Algorithm::AesXts, 256) => "AES-128/XTS",
                (Algorithm::AesXts, 384) => "AES-192/XTS",
                (Algorithm::AesXts, 512) => "AES-256/XTS",
                (Algorithm::AriaCbcPkcs5, 128) => "ARIA-128/CBC",
                (Algorithm::AriaCbcPkcs5, 192) => "ARIA-192/CBC",
                (Algorithm::AriaCbcPkcs5, 256) => "ARIA-256/CBC",
                (Algorithm::CamelliaCbcPkcs5, 128) => "Camellia-128/CBC",
                (Algorithm::CamelliaCbcPkcs5, 192) => "Camellia-192/CBC",
                (Algorithm::CamelliaCbcPkcs5, 256) => "Camellia-256/CBC",
                (_, _) => panic!("Unhandled cipher"),
            };

            let mut enc = botan::Cipher::new(cipher_name, botan::CipherDirection::Encrypt)?;
            let mut dec = botan::Cipher::new(cipher_name, botan::CipherDirection::Decrypt)?;

            for test in &test_group.tests {
                if !test.result.must_fail() {
                    enc.set_key(&test.key)?;
                    let ct = enc.process(&test.nonce, &test.pt)?;
                    assert_eq!(ct, test.ct.as_ref());
                }

                dec.set_key(&test.key)?;
                match dec.process(&test.nonce, &test.ct) {
                    Ok(pt) => {
                        assert_eq!(pt, test.pt.as_ref());
                        assert!(!test.result.must_fail());
                    }
                    Err(_) => assert!(test.result.must_fail()),
                }
            }
        }
    }

    Ok(())
}

#[test]
fn wycheproof_aead_gcm_tests() -> Result<(), botan::Error> {
    fn aes_gcm_name(ks: usize, ts: usize, _ns: usize) -> Option<String> {
        assert!(ks == 128 || ks == 192 || ks == 256);
        assert!(ts == 128);
        Some(format!("AES-{ks}/GCM"))
    }

    fn aria_gcm_name(ks: usize, ts: usize, _ns: usize) -> Option<String> {
        assert!(ks == 128 || ks == 192 || ks == 256);
        assert!(ts == 128);
        Some(format!("ARIA-{ks}/GCM"))
    }

    fn seed_gcm_name(ks: usize, ts: usize, _ns: usize) -> Option<String> {
        assert!(ks == 128 && ts == 128);
        Some(format!("SEED/GCM"))
    }

    fn sm4_gcm_name(ks: usize, ts: usize, _ns: usize) -> Option<String> {
        assert!(ks == 128 && ts == 128);
        Some(format!("SM4/GCM"))
    }

    wycheproof_aead_test(wycheproof::aead::TestName::AesGcm, aes_gcm_name)?;
    wycheproof_aead_test(wycheproof::aead::TestName::AriaGcm, aria_gcm_name)?;
    wycheproof_aead_test(wycheproof::aead::TestName::SeedGcm, seed_gcm_name)?;
    wycheproof_aead_test(wycheproof::aead::TestName::Sm4Gcm, sm4_gcm_name)?;

    Ok(())
}

#[test]
fn wycheproof_aead_ccm_tests() -> Result<(), botan::Error> {
    fn aes_ccm_name(ks: usize, ts: usize, ns: usize) -> Option<String> {
        assert!(ks == 128 || ks == 192 || ks == 256);
        assert!(ts % 8 == 0);
        let tag_bytes = ts / 8;
        if tag_bytes < 4 || tag_bytes % 2 == 1 {
            return None;
        }
        if ns >= 128 {
            return None;
        }
        let ccm_l = 15 - (ns / 8);
        if ccm_l < 2 || ccm_l > 8 {
            return None;
        }
        Some(format!("AES-{ks}/CCM({tag_bytes},{ccm_l})"))
    }

    wycheproof_aead_test(wycheproof::aead::TestName::AesCcm, aes_ccm_name)?;

    Ok(())
}

#[test]
fn wycheproof_aead_eax_tests() -> Result<(), botan::Error> {
    fn aes_eax_name(ks: usize, ts: usize, _ns: usize) -> Option<String> {
        assert!(ks == 128 || ks == 192 || ks == 256);
        assert!(ts == 128);
        Some(format!("AES-{ks}/EAX"))
    }

    wycheproof_aead_test(wycheproof::aead::TestName::AesEax, aes_eax_name)?;

    Ok(())
}

#[test]
fn wycheproof_aead_siv_tests() -> Result<(), botan::Error> {
    fn aes_siv_name(ks: usize, ts: usize, _ns: usize) -> Option<String> {
        assert!(ks == 2 * 128 || ks == 2 * 192 || ks == 2 * 256);
        assert!(ts == 128);
        Some(format!("AES-{}/SIV", ks / 2))
    }

    wycheproof_aead_test(wycheproof::aead::TestName::AesSivCmac, aes_siv_name)?;

    Ok(())
}

#[test]
fn wycheproof_aead_chacha20poly1305_tests() -> Result<(), botan::Error> {
    fn chacha_name(ks: usize, ts: usize, _ns: usize) -> Option<String> {
        assert_eq!(ks, 256);
        assert_eq!(ts, 128);
        Some("ChaCha20Poly1305".to_string())
    }

    wycheproof_aead_test(wycheproof::aead::TestName::ChaCha20Poly1305, chacha_name)?;

    wycheproof_aead_test(wycheproof::aead::TestName::XChaCha20Poly1305, chacha_name)?;

    Ok(())
}

fn wycheproof_aead_test(
    test_set_name: wycheproof::aead::TestName,
    botan_cipher_name: impl Fn(usize, usize, usize) -> Option<String>,
) -> Result<(), botan::Error> {
    let test_set = wycheproof::aead::TestSet::load(test_set_name).expect("Loading tests failed");

    let is_botan2 = botan::Version::current()?.major == 2;

    for test_group in test_set.test_groups {
        let cipher_name = botan_cipher_name(
            test_group.key_size,
            test_group.tag_size,
            test_group.nonce_size,
        );

        let cipher_name = match cipher_name {
            Some(name) => name,
            None => continue,
        };

        let tag_first = cipher_name.contains("/SIV");

        let mut enc = botan::Cipher::new(&cipher_name, botan::CipherDirection::Encrypt)?;
        let mut dec = botan::Cipher::new(&cipher_name, botan::CipherDirection::Decrypt)?;

        for test in &test_group.tests {
            if is_botan2 && cipher_name.contains("/EAX") {
                // Cipher object must be cleared each time to avoid a bug in EAX encryption in Botan 2
                enc.clear()?;
                dec.clear()?;
            }

            enc.set_key(&test.key)?;
            enc.set_associated_data(&test.aad)?;

            if test.result == wycheproof::TestResult::Invalid
                && test
                    .flags
                    .contains(&wycheproof::aead::TestFlag::ZeroLengthIv)
            {
                assert!(enc.process(&test.nonce, &test.pt).is_err());
                continue;
            }

            if !enc.valid_nonce_length(test.nonce.len())? {
                assert!(test.result.must_fail());
                continue;
            }

            let ctext = enc.process(&test.nonce, &test.pt)?;

            let expected_ctext = if tag_first {
                format!(
                    "{}{}",
                    hex::encode(test.tag.as_ref()),
                    hex::encode(test.ct.as_ref())
                )
            } else {
                format!(
                    "{}{}",
                    hex::encode(test.ct.as_ref()),
                    hex::encode(test.tag.as_ref())
                )
            };

            if test.result.must_fail() {
                assert_ne!(hex::encode(ctext), expected_ctext);
            } else {
                assert_eq!(hex::encode(ctext), expected_ctext);
            }

            dec.set_key(&test.key)?;
            dec.set_associated_data(&test.aad)?;

            if test.result == wycheproof::TestResult::Invalid
                && test
                    .flags
                    .contains(&wycheproof::aead::TestFlag::ZeroLengthIv)
            {
                assert!(dec.process(&test.nonce, &test.pt).is_err());
                continue;
            }

            let ct_and_tag = if tag_first {
                let mut tag_and_ct = test.tag.to_vec();
                tag_and_ct.extend_from_slice(&test.ct);
                tag_and_ct
            } else {
                let mut ct_and_tag = test.ct.to_vec();
                ct_and_tag.extend_from_slice(&test.tag);
                ct_and_tag
            };

            match dec.process(&test.nonce, &ct_and_tag) {
                Ok(ptext) => {
                    assert!(!test.result.must_fail());
                    assert_eq!(hex::encode(ptext), hex::encode(&test.pt));
                }
                Err(_) => {
                    assert!(test.result.must_fail());
                }
            }
        }
    }

    Ok(())
}

#[test]
fn wycheproof_mac_tests() -> Result<(), botan::Error> {
    use wycheproof::mac::*;

    fn mac_test_simple(
        test_set_name: TestName,
        mac_name: &'static str,
    ) -> Result<(), botan::Error> {
        wycheproof_mac_test(test_set_name, |_ks: usize| Some(mac_name.to_string()))
    }

    mac_test_simple(TestName::HmacSha1, "HMAC(SHA-1)")?;
    mac_test_simple(TestName::HmacSha224, "HMAC(SHA-224)")?;
    mac_test_simple(TestName::HmacSha256, "HMAC(SHA-256)")?;
    mac_test_simple(TestName::HmacSha384, "HMAC(SHA-384)")?;
    mac_test_simple(TestName::HmacSha512, "HMAC(SHA-512)")?;
    mac_test_simple(TestName::HmacSha512_256, "HMAC(SHA-512-256)")?;
    mac_test_simple(TestName::HmacSha3_224, "HMAC(SHA-3(224))")?;
    mac_test_simple(TestName::HmacSha3_256, "HMAC(SHA-3(256))")?;
    mac_test_simple(TestName::HmacSha3_384, "HMAC(SHA-3(384))")?;
    mac_test_simple(TestName::HmacSha3_512, "HMAC(SHA-3(512))")?;
    mac_test_simple(TestName::HmacSm3, "HMAC(SM3)")?;
    mac_test_simple(TestName::SipHash_1_3, "SipHash(1,3)")?;
    mac_test_simple(TestName::SipHash_2_4, "SipHash(2,4)")?;
    mac_test_simple(TestName::SipHash_4_8, "SipHash(4,8)")?;

    wycheproof_mac_test(TestName::AesCmac, |ks: usize| {
        if ks == 128 || ks == 192 || ks == 256 {
            Some(format!("CMAC(AES-{})", ks))
        } else {
            None
        }
    })?;

    wycheproof_mac_test(TestName::AriaCmac, |ks: usize| {
        if ks == 128 || ks == 192 || ks == 256 {
            Some(format!("CMAC(ARIA-{})", ks))
        } else {
            None
        }
    })?;

    wycheproof_mac_test(TestName::CamelliaCmac, |ks: usize| {
        if ks == 128 || ks == 192 || ks == 256 {
            Some(format!("CMAC(Camellia-{})", ks))
        } else {
            None
        }
    })?;

    Ok(())
}

fn wycheproof_mac_test(
    test_set_name: wycheproof::mac::TestName,
    mac_name_fn: impl Fn(usize) -> Option<String>,
) -> Result<(), botan::Error> {
    use wycheproof::mac::*;

    let test_set = TestSet::load(test_set_name).expect("Loading tests failed");

    for test_group in &test_set.test_groups {
        let mac_name = match mac_name_fn(test_group.key_size) {
            Some(n) => n,
            None => continue,
        };

        let mut mac = botan::MsgAuthCode::new(&mac_name)?;

        for test in &test_group.tests {
            mac.set_key(&test.key)?;
            mac.update(&test.msg)?;
            let mut computed_tag = mac.finish()?;

            computed_tag.truncate(test_group.tag_size / 8);

            if !test.result.must_fail() {
                assert_eq!(computed_tag, test.tag.as_ref());
            } else {
                assert_ne!(computed_tag, test.tag.as_ref());
            }
        }
    }

    Ok(())
}

#[cfg(feature = "botan3")]
#[test]
fn wycheproof_mac_with_nonce_tests() -> Result<(), botan::Error> {
    use wycheproof::mac_with_nonce::*;

    let test_set = TestSet::load(TestName::Gmac).expect("Loading tests failed");

    for test_group in &test_set.test_groups {
        let mac_name = format!("GMAC(AES-{})", test_group.key_size);

        let mut mac = botan::MsgAuthCode::new(&mac_name)?;

        for test in &test_group.tests {
            mac.set_key(&test.key)?;
            mac.set_nonce(&test.nonce)?;
            mac.update(&test.msg)?;
            let mut computed_tag = mac.finish()?;

            computed_tag.truncate(test_group.tag_size / 8);

            if !test.result.must_fail() {
                assert_eq!(computed_tag, test.tag.as_ref());
            } else {
                assert_ne!(computed_tag, test.tag.as_ref());
            }
        }
    }

    Ok(())
}
#[test]
fn wycheproof_primality_tests() -> Result<(), botan::Error> {
    use wycheproof::{primality::*, TestResult};

    let mut rng = botan::RandomNumberGenerator::new_system()?;

    for test_name in TestName::all() {
        let test_set = TestSet::load(test_name).expect("Loading tests failed");

        for test_group in &test_set.test_groups {
            for test in &test_group.tests {
                if test.flags.contains(&TestFlag::NegativeOfPrime) {
                    continue;
                }

                // The primality test data encodes negative numbers using
                // twos complement encoding
                let mpi = if test.value.len() > 0 && (test.value[0] & 0x80 == 0x80) {
                    let mut flipped: Vec<u8> = test.value.to_vec();
                    for i in 0..flipped.len() {
                        flipped[i] = !flipped[i];
                    }
                    let one = botan::MPI::new_from_u32(1)?;
                    botan::MPI::new_from_bytes(&flipped)? + &one
                } else {
                    botan::MPI::new_from_bytes(&test.value)?
                };
                let is_prime = mpi.is_prime(&mut rng, 128)?;

                assert_eq!(is_prime, test.result == TestResult::Valid);
            }
        }
    }

    Ok(())
}

#[test]
fn wycheproof_rsa_pkcs1_decrypt_tests() -> Result<(), botan::Error> {
    use wycheproof::rsa_pkcs1_decrypt::*;

    let is_botan2 = botan::Version::current()?.major == 2;

    for test_name in TestName::all() {
        let test_set = TestSet::load(test_name).expect("Loading tests failed");

        for test_group in &test_set.test_groups {
            let key = botan::Privkey::load_der(&test_group.pkcs8)?;

            let mut decryptor = botan::Decryptor::new(&key, "PKCS1v15")?;

            for test in &test_group.tests {
                if is_botan2 && test.comment == "Prepended bytes to ciphertext" {
                    continue;
                }

                match decryptor.decrypt(&test.ct) {
                    Ok(pt) => {
                        assert_eq!(pt, test.pt.as_ref());
                        assert!(!test.result.must_fail());
                    }
                    Err(_) => {
                        assert!(test.result.must_fail());
                    }
                }
            }
        }
    }

    Ok(())
}

#[test]
fn wycheproof_rsa_oaep_decrypt_tests() -> Result<(), botan::Error> {
    use wycheproof::rsa_oaep::*;

    fn gen_oaep_string(group: &TestGroup) -> Option<String> {
        if group.mgf != wycheproof::Mgf::Mgf1 {
            return None;
        }

        let label_hash = match hash_id_to_str(group.hash) {
            Some(h) => h,
            None => return None,
        };

        let mgf_hash = match hash_id_to_str(group.mgf_hash) {
            Some(h) => h,
            None => return None,
        };

        Some(format!("OAEP({},MGF1({}))", label_hash, mgf_hash))
    }

    let is_botan2 = botan::Version::current()?.major == 2;

    for test_name in TestName::all() {
        let test_set = TestSet::load(test_name).expect("Loading tests failed");

        for test_group in &test_set.test_groups {
            let oaep_string = match gen_oaep_string(&test_group) {
                Some(s) => s,
                None => continue,
            };

            let key = botan::Privkey::load_der(&test_group.pkcs8)?;

            let mut decryptor = botan::Decryptor::new(&key, &oaep_string)?;

            for test in &test_group.tests {
                if !test.label.is_empty() {
                    continue;
                }

                if is_botan2 && test.comment == "prepended bytes to ciphertext" {
                    continue;
                }

                match decryptor.decrypt(&test.ct) {
                    Ok(pt) => {
                        assert_eq!(pt, test.pt.as_ref());
                        assert!(!test.result.must_fail());
                    }
                    Err(_) => {
                        assert!(test.result.must_fail());
                    }
                }
            }
        }
    }

    Ok(())
}

#[test]
fn wycheproof_rsa_pkcs1_verify_tests() -> Result<(), botan::Error> {
    use wycheproof::rsa_pkcs1_verify::*;

    for test_name in TestName::all() {
        let test_set = TestSet::load(test_name).expect("Loading tests failed");

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
fn wycheproof_rsa_pss_verify_tests() -> Result<(), botan::Error> {
    use wycheproof::rsa_pss_verify::*;

    let is_botan2 = botan::Version::current()?.major == 2;

    fn form_pssr_format(group: &TestGroup) -> Option<String> {
        // MGF hash != hash -> not supported
        // Something other than MGF1 -> not supported
        match (group.hash, group.mgf, group.mgf_hash) {
            (h1, wycheproof::Mgf::Mgf1, Some(h2)) if h1 == h2 => {}
            (_, _, _) => return None,
        }

        let hash = match hash_id_to_str(group.hash) {
            Some(hash) => hash,
            None => return None,
        };

        Some(format!("EMSA4({},MGF1,{})", hash, group.salt_size))
    }

    for test_name in TestName::all() {
        let test_set = TestSet::load(test_name).expect("Loading tests failed");

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
fn wycheproof_dsa_verify_tests() -> Result<(), botan::Error> {
    use wycheproof::dsa::*;

    for test_name in TestName::all() {
        let is_ieee = format!("{:?}", test_name).contains("P1363");
        let test_set = TestSet::load(test_name).expect("Loading tests failed");

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
        EllipticCurve::Secp160r1 => Some("secp160r1"),
        EllipticCurve::Secp160r2 => Some("secp160r2"),
        EllipticCurve::Secp160k1 => Some("secp160k1"),
        EllipticCurve::Secp192r1 => Some("secp192r1"),
        EllipticCurve::Secp192k1 => Some("secp192k1"),
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
fn wycheproof_ecdsa_verify_tests() -> Result<(), botan::Error> {
    use wycheproof::ecdsa::*;

    let is_botan2 = botan::Version::current()?.major == 2;

    for test_name in TestName::all() {
        if test_name == TestName::EcdsaSecp256k1Sha256Bitcoin {
            continue;
        }

        let is_ieee = format!("{:?}", test_name).contains("P1363")
            || format!("{:?}", test_name).contains("Webcrypto");

        let test_set = TestSet::load(test_name).expect("Loading tests failed");

        for test_group in &test_set.test_groups {
            if curve_id_to_str(test_group.key.curve) == None {
                continue;
            }

            let hash = match hash_id_to_str(test_group.hash) {
                Some(hash) => hash,
                None => continue,
            };

            if is_botan2 {
                // https://github.com/randombit/botan/issues/2841
                match (test_group.key.curve, hash) {
                    (EllipticCurve::Secp160k1, "SHA-256") => continue,
                    (EllipticCurve::Secp160r1, "SHA-256") => continue,
                    (EllipticCurve::Secp160r2, "SHA-256") => continue,
                    (EllipticCurve::Secp224k1, "SHA-256") => continue,
                    (_, _) => {}
                }
            }

            let key = botan::Pubkey::load_der(&test_group.der)?;

            let mut verifier_ieee = botan::Verifier::new(&key, &format!("EMSA1({})", hash))?;

            for test in &test_group.tests {
                let accept = if is_ieee {
                    verifier_ieee.update(&test.msg)?;
                    verifier_ieee.finish(&test.sig)?
                } else {
                    // Has to be inside the loop to work around the bug addressed in
                    // https://github.com/randombit/botan/pull/3333
                    let mut verifier_der = botan::Verifier::new_with_der_formatted_signatures(
                        &key,
                        &format!("EMSA1({})", hash),
                    )?;

                    verifier_der.update(&test.msg)?;
                    verifier_der.finish(&test.sig)?
                };

                match (accept, test.result) {
                    (true, TestResult::Valid) => {}
                    (true, TestResult::Acceptable) => {
                        panic!("Accepted an acceptable signature");
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
fn wycheproof_eddsa_verify_tests() -> Result<(), botan::Error> {
    use wycheproof::eddsa::*;

    let is_botan2 = botan::Version::current()?.major == 2;

    for test_name in TestName::all() {
        if test_name == TestName::Ed448 {
            continue;
        }

        let test_set = TestSet::load(test_name).expect("Loading tests failed");

        for test_group in &test_set.test_groups {
            let key = botan::Pubkey::load_der(&test_group.der)?;

            let mut verifier = botan::Verifier::new(&key, "Pure")?;

            for test in &test_group.tests {
                if is_botan2 {
                    if test.flags.contains(&TestFlag::SignatureMalleability) {
                        continue;
                    }
                    if test.comment == "Signature with S just above the bound. [David Benjamin]" {
                        continue;
                    }
                }

                verifier.update(&test.msg)?;
                let accept = verifier.finish(&test.sig)?;

                match (accept, test.result) {
                    (true, TestResult::Valid) => {}
                    (true, TestResult::Acceptable) => {
                        panic!("Accepted an acceptable signature");
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
fn wycheproof_ecdh_tests() -> Result<(), botan::Error> {
    use wycheproof::ecdh::*;

    for test_name in TestName::all() {
        let test_set = TestSet::load(test_name).expect("Loading tests failed");

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
                        Ok(shared_secret) => assert_eq!(shared_secret, test.shared_secret.as_ref()),
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

#[test]
fn wycheproof_xdh_tests() -> Result<(), botan::Error> {
    use wycheproof::xdh::*;

    for test_name in TestName::all() {
        if test_name == TestName::X448 {
            continue;
        }

        let test_set = TestSet::load(test_name).expect("Loading tests failed");

        for test_group in &test_set.test_groups {
            for test in &test_group.tests {
                let priv_key = botan::Privkey::load_x25519(&test.private_key)?;

                let mut ka = botan::KeyAgreement::new(&priv_key, "Raw")?;

                let shared_secret = ka.agree(0, &test.public_key, &[]);

                if test.result == TestResult::Valid || test.result == TestResult::Acceptable {
                    match shared_secret {
                        Ok(shared_secret) => assert_eq!(shared_secret, test.shared_secret.as_ref()),
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
