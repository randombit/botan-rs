#[test]
fn wycheproof_aead_gcm_tests() -> Result<(), botan::Error> {
    wycheproof_aead_test(wycheproof::aead::TestName::AesGcm, |ks: usize| {
        format!("AES-{}/GCM", ks)
    })
}

#[test]
fn wycheproof_aead_eax_tests() -> Result<(), botan::Error> {
    wycheproof_aead_test(wycheproof::aead::TestName::AesEax, |ks: usize| {
        format!("AES-{}/EAX", ks)
    })
}

#[test]
fn wycheproof_aead_siv_tests() -> Result<(), botan::Error> {
    wycheproof_aead_test(wycheproof::aead::TestName::AesSivCmac, |ks: usize| {
        format!("AES-{}/SIV", ks / 2)
    })
}

#[test]
fn wycheproof_aead_chacha20poly1305_tests() -> Result<(), botan::Error> {
    wycheproof_aead_test(
        wycheproof::aead::TestName::ChaCha20Poly1305,
        |_ks: usize| "ChaCha20Poly1305".to_string(),
    )
}

#[test]
fn wycheproof_aead_xchacha20poly1305_tests() -> Result<(), botan::Error> {
    wycheproof_aead_test(
        wycheproof::aead::TestName::XChaCha20Poly1305,
        |_ks: usize| "ChaCha20Poly1305".to_string(),
    )
}

fn wycheproof_aead_test(
    test_set_name: wycheproof::aead::TestName,
    botan_cipher_name: impl Fn(usize) -> String,
) -> Result<(), botan::Error> {
    let test_set = wycheproof::aead::TestSet::load(test_set_name).unwrap();

    for test_group in test_set.test_groups {
        let cipher_name = botan_cipher_name(test_group.key_size);

        let tag_first = cipher_name.contains("/SIV");

        for test in &test_group.tests {
            // Cipher object must be created each time to avoid a bug in EAX encryption
            let mut cipher = botan::Cipher::new(&cipher_name, botan::CipherDirection::Encrypt)?;

            cipher.set_key(&test.key).unwrap();
            cipher.set_associated_data(&test.aad).unwrap();

            if test.result == wycheproof::TestResult::Invalid
                && test
                    .flags
                    .contains(&wycheproof::aead::TestFlag::ZeroLengthIv)
            {
                assert!(cipher.process(&test.nonce, &test.pt).is_err());
                continue;
            }

            if !cipher.valid_nonce_length(test.nonce.len())? {
                assert!(test.result.must_fail());
                continue;
            }

            let ctext = cipher.process(&test.nonce, &test.pt).unwrap();

            let expected_ctext = if tag_first {
                format!("{}{}", hex::encode(&test.tag), hex::encode(&test.ct))
            } else {
                format!("{}{}", hex::encode(&test.ct), hex::encode(&test.tag))
            };

            if test.result.must_fail() {
                assert_ne!(hex::encode(ctext), expected_ctext);
            } else {
                assert_eq!(hex::encode(ctext), expected_ctext);
            }
        }

        for test in &test_group.tests {
            let mut cipher =
                botan::Cipher::new(&cipher_name, botan::CipherDirection::Decrypt).unwrap();

            cipher.set_key(&test.key).unwrap();
            cipher.set_associated_data(&test.aad).unwrap();

            if test.result == wycheproof::TestResult::Invalid
                && test
                    .flags
                    .contains(&wycheproof::aead::TestFlag::ZeroLengthIv)
            {
                assert!(cipher.process(&test.nonce, &test.pt).is_err());
                continue;
            }

            let ct_and_tag = if tag_first {
                let mut tag_and_ct = test.tag.clone();
                tag_and_ct.extend_from_slice(&test.ct);
                tag_and_ct
            } else {
                let mut ct_and_tag = test.ct.clone();
                ct_and_tag.extend_from_slice(&test.tag);
                ct_and_tag
            };

            match cipher.process(&test.nonce, &ct_and_tag) {
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
