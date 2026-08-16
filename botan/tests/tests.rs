extern crate botan;

use std::str::FromStr;

/// If the first Botan call in a test fails with NotImplemented, the
/// functionality was not compiled into the library we are running against,
/// and the test is skipped. This must only be applied to a test's initial
/// call (or to the first use of an independent algorithm); once an algorithm
/// has been created successfully, a NotImplemented error from any later call
/// is a real failure.
macro_rules! skip_if_not_implemented {
    ($call:expr) => {
        match $call {
            Ok(val) => val,
            Err(e) if e.error_type() == botan::ErrorType::NotImplemented => {
                return Ok(());
            }
            Err(e) => return Err(e),
        }
    };
}

#[test]
fn test_version() -> Result<(), botan::Error> {
    let version = botan::Version::current()?;

    assert!(version.release_date == 0 || version.release_date >= 20181001);

    assert!(version.ffi_api >= 20180713);

    assert!(botan::Version::supports_version(version.ffi_api));
    assert!(botan::Version::supports_version(20180713));
    assert!(!botan::Version::supports_version(20180712));

    assert!(version.at_least(2, 13));
    assert!(version.at_least(2, 4));
    assert!(version.at_least(1, 100));

    println!("{version:?}");

    if cfg!(botan_ffi_20250506) {
        assert!(version.at_least(3, 8));
    }

    if cfg!(botan_ffi_20240408) {
        assert!(version.at_least(3, 4));
    }

    if cfg!(botan_ffi_20231009) {
        assert!(version.at_least(3, 2));
    }

    if cfg!(botan_ffi_20230711) {
        assert!(version.at_least(3, 1));
    }

    if cfg!(botan_ffi_20230403) {
        assert!(version.at_least(3, 0));
    }

    if cfg!(botan_ffi_20191214) {
        assert!(version.at_least(2, 13));
    }

    Ok(())
}

#[test]
fn test_hash() -> Result<(), botan::Error> {
    let mut hash = skip_if_not_implemented!(botan::HashFunction::new("SHA-384"));

    assert_eq!(hash.output_length()?, 48);
    assert_eq!(hash.block_size()?, 128);
    assert_eq!(hash.algo_name()?, "SHA-384");

    assert!(hash.update(&[97, 98]).is_ok());

    let mut hash_dup = hash.duplicate()?;

    assert!(hash.update(&[99]).is_ok());
    assert!(hash_dup.update(&[100]).is_ok());

    hash.clear()?;

    hash.update(&[97, 98, 99])?;

    let digest = hash.finish()?;

    assert_eq!(
        botan::hex_encode(&digest)?,
        "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7"
    );

    let digest_dup = hash_dup.finish()?;

    assert_eq!(
        botan::hex_encode(&digest_dup)?,
        "5D15BCEBB965FA77926C23471C96E3A326B363F5F105C3EF17CFD033B9734FA46556F81A26BB3044D2DDA50481325EF7"
    );

    let bad_hash = botan::HashFunction::new("BunnyHash9000");

    assert!(bad_hash.is_err());
    assert_eq!(
        bad_hash.as_ref().unwrap_err().error_type(),
        botan::ErrorType::NotImplemented
    );
    Ok(())
}

#[test]
fn test_algorithm_identifiers() -> Result<(), botan::Error> {
    let blake2b = botan::HashAlgorithm::Blake2b(256);
    assert_eq!(blake2b.botan_name(), "BLAKE2b(256)");

    let hmac = botan::MacAlgorithm::Hmac(botan::HashAlgorithm::Sha256);
    assert_eq!(hmac.botan_name(), "HMAC(SHA-256)");

    let kmac = botan::MacAlgorithm::Kmac128(256);
    assert_eq!(kmac.botan_name(), "KMAC-128(256)");

    let gcm = botan::CipherAlgorithm::Gcm(botan::BlockCipherAlgorithm::Aes128, Some(16));
    assert_eq!(gcm.botan_name(), "AES-128/GCM(16)");

    let ctr = botan::StreamCipherAlgorithm::CtrBe(botan::BlockCipherAlgorithm::Aes128, None);
    assert_eq!(ctr.botan_name(), "CTR-BE(AES-128)");

    let ctr32 = botan::StreamCipherAlgorithm::CtrBe(botan::BlockCipherAlgorithm::Aes128, Some(4));
    assert_eq!(ctr32.botan_name(), "CTR-BE(AES-128,4)");

    let rc4 = botan::StreamCipherAlgorithm::Rc4(Some(256));
    assert_eq!(rc4.botan_name(), "RC4(256)");
    assert_eq!(botan::StreamCipherAlgorithm::Rc4(None).botan_name(), "RC4");

    assert_eq!(
        botan::StreamCipherAlgorithm::ChaCha8.botan_name(),
        "ChaCha(8)"
    );
    assert_eq!(
        botan::StreamCipherAlgorithm::ChaCha12.botan_name(),
        "ChaCha(12)"
    );

    assert_eq!(botan::RngType::Hwrng.botan_name(), "hwrng");

    let cbc = botan::CipherAlgorithm::Cbc(botan::BlockCipherAlgorithm::Aes128, None);
    assert_eq!(cbc.botan_name(), "AES-128/CBC");

    let cbc_cts = botan::CipherAlgorithm::Cbc(
        botan::BlockCipherAlgorithm::Aes128,
        Some(botan::CipherPadding::Cts),
    );
    assert_eq!(cbc_cts.botan_name(), "AES-128/CBC/CTS");

    let ccm = botan::CipherAlgorithm::Ccm(botan::BlockCipherAlgorithm::Aes128, None, None);
    assert_eq!(ccm.botan_name(), "AES-128/CCM");

    let ccm_tag = botan::CipherAlgorithm::Ccm(botan::BlockCipherAlgorithm::Aes128, Some(8), None);
    assert_eq!(ccm_tag.botan_name(), "AES-128/CCM(8)");

    let ccm_l = botan::CipherAlgorithm::Ccm(botan::BlockCipherAlgorithm::Aes128, None, Some(2));
    assert_eq!(ccm_l.botan_name(), "AES-128/CCM(16,2)");

    let ccm_tag_l =
        botan::CipherAlgorithm::Ccm(botan::BlockCipherAlgorithm::Aes128, Some(8), Some(2));
    assert_eq!(ccm_tag_l.botan_name(), "AES-128/CCM(8,2)");

    let gcm_siv = botan::CipherAlgorithm::GcmSiv(botan::BlockCipherAlgorithm::Aes256);
    assert_eq!(gcm_siv.botan_name(), "AES-256/GCM-SIV");

    let ascon = botan::CipherAlgorithm::AsconAead128;
    assert_eq!(ascon.botan_name(), "Ascon-AEAD128");

    let lion = botan::BlockCipherAlgorithm::Arbitrary("Lion(SHA-1,RC4,64)".to_string());
    assert_eq!(lion.botan_name(), "Lion(SHA-1,RC4,64)");

    let pbkdf2_cmac = botan::PasswordHashAlgorithm::Pbkdf2Mac(botan::MacAlgorithm::Cmac(
        botan::BlockCipherAlgorithm::Blowfish,
    ));
    assert_eq!(pbkdf2_cmac.botan_name(), "PBKDF2(CMAC(Blowfish))");

    let pkcs12 = botan::PasswordHashAlgorithm::Pkcs12Kdf(botan::HashAlgorithm::Sha256, 1);
    assert_eq!(pkcs12.botan_name(), "PKCS12-KDF(SHA-256,1)");

    let hmac_sha256 = botan::MacAlgorithm::Hmac(botan::HashAlgorithm::Sha256);

    assert_eq!(
        botan::KdfAlgorithm::HkdfMac(botan::MacAlgorithm::Cmac(
            botan::BlockCipherAlgorithm::Aes128
        ))
        .botan_name(),
        "HKDF(CMAC(AES-128))"
    );
    assert_eq!(
        botan::KdfAlgorithm::Tls12Prf(botan::HashAlgorithm::Sha256).botan_name(),
        "TLS-12-PRF(SHA-256)"
    );
    assert_eq!(
        botan::KdfAlgorithm::Tls12PrfMac(hmac_sha256.clone()).botan_name(),
        "TLS-12-PRF(HMAC(SHA-256))"
    );
    assert_eq!(
        botan::KdfAlgorithm::Sp80056cHash(botan::HashAlgorithm::Sha256).botan_name(),
        "SP800-56C(SHA-256)"
    );
    assert_eq!(
        botan::KdfAlgorithm::Sp800108Counter(hmac_sha256.clone(), None, None).botan_name(),
        "SP800-108-Counter(HMAC(SHA-256))"
    );
    assert_eq!(
        botan::KdfAlgorithm::Sp800108Counter(hmac_sha256.clone(), Some(8), None).botan_name(),
        "SP800-108-Counter(HMAC(SHA-256),8)"
    );
    assert_eq!(
        botan::KdfAlgorithm::Sp800108Counter(hmac_sha256.clone(), None, Some(64)).botan_name(),
        "SP800-108-Counter(HMAC(SHA-256),32,64)"
    );
    assert_eq!(
        botan::KdfAlgorithm::Sp800108Counter(hmac_sha256, Some(8), Some(64)).botan_name(),
        "SP800-108-Counter(HMAC(SHA-256),8,64)"
    );

    assert_eq!(
        botan::Pkcs8Kdf::Pbkdf2(botan::HashAlgorithm::Sha512).botan_name(),
        "SHA-512"
    );
    assert_eq!(botan::Pkcs8Kdf::Scrypt.botan_name(), "Scrypt");

    Ok(())
}

#[test]
fn test_hash_algo_runtime() -> Result<(), botan::Error> {
    let hash = skip_if_not_implemented!(botan::HashFunction::new(botan::HashAlgorithm::Sha384));
    assert_eq!(hash.algo_name()?, "SHA-384");
    Ok(())
}

#[test]
fn test_mac_algo_runtime() -> Result<(), botan::Error> {
    let mac = skip_if_not_implemented!(botan::MsgAuthCode::new(botan::MacAlgorithm::Hmac(
        botan::HashAlgorithm::Sha384
    )));
    assert_eq!(mac.algo_name()?, "HMAC(SHA-384)");
    Ok(())
}

#[test]
fn test_block_cipher_algo_runtime() -> Result<(), botan::Error> {
    let block =
        skip_if_not_implemented!(botan::BlockCipher::new(botan::BlockCipherAlgorithm::Aes128));
    assert_eq!(block.algo_name()?, "AES-128");
    Ok(())
}

#[test]
fn test_gcm_algo_runtime() -> Result<(), botan::Error> {
    let cipher = skip_if_not_implemented!(botan::Cipher::new(
        botan::CipherAlgorithm::Gcm(botan::BlockCipherAlgorithm::Aes128, None),
        botan::CipherDirection::Encrypt,
    ));
    assert_eq!(cipher.algo_name()?, "AES-128/GCM(16)");
    Ok(())
}

#[test]
fn test_cbc_algo_runtime() -> Result<(), botan::Error> {
    let cipher = skip_if_not_implemented!(botan::Cipher::new(
        botan::CipherAlgorithm::Cbc(botan::BlockCipherAlgorithm::Aes128, None),
        botan::CipherDirection::Encrypt,
    ));
    assert_eq!(cipher.algo_name()?, "AES-128/CBC/PKCS7");
    Ok(())
}

#[test]
fn test_ccm_algo_runtime() -> Result<(), botan::Error> {
    let cipher = skip_if_not_implemented!(botan::Cipher::new(
        botan::CipherAlgorithm::Ccm(botan::BlockCipherAlgorithm::Aes128, Some(8), Some(2)),
        botan::CipherDirection::Encrypt,
    ));
    assert_eq!(cipher.algo_name()?, "AES-128/CCM(8,2)");
    Ok(())
}

#[test]
fn test_ctr_algo_runtime() -> Result<(), botan::Error> {
    let cipher = skip_if_not_implemented!(botan::Cipher::new(
        botan::CipherAlgorithm::CtrBe(botan::BlockCipherAlgorithm::Aes128, Some(4)),
        botan::CipherDirection::Encrypt,
    ));
    assert_eq!(cipher.algo_name()?, "CTR-BE(AES-128,4)");
    Ok(())
}

#[test]
fn test_chacha_algo_runtime() -> Result<(), botan::Error> {
    let cipher = skip_if_not_implemented!(botan::Cipher::new(
        botan::CipherAlgorithm::Stream(botan::StreamCipherAlgorithm::ChaCha12),
        botan::CipherDirection::Encrypt,
    ));
    assert_eq!(cipher.algo_name()?, "ChaCha(12)");
    Ok(())
}

#[test]
fn test_ascon_algo_runtime() -> Result<(), botan::Error> {
    let cipher = skip_if_not_implemented!(botan::Cipher::new(
        botan::CipherAlgorithm::AsconAead128,
        botan::CipherDirection::Encrypt,
    ));
    assert_eq!(cipher.algo_name()?, "Ascon-AEAD128");
    Ok(())
}

#[test]
fn test_gcm_siv_algo_runtime() -> Result<(), botan::Error> {
    let cipher = skip_if_not_implemented!(botan::Cipher::new(
        botan::CipherAlgorithm::GcmSiv(botan::BlockCipherAlgorithm::Aes256),
        botan::CipherDirection::Encrypt,
    ));
    assert_eq!(cipher.algo_name()?, "AES-256/GCM-SIV");
    Ok(())
}

#[test]
fn test_kdf_algo_runtime() -> Result<(), botan::Error> {
    let salt = botan::hex_decode("000102030405060708090A0B0C")?;
    let label = botan::hex_decode("F0F1F2F3F4F5F6F7F8F9")?;
    let secret = botan::hex_decode("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")?;
    let derived = skip_if_not_implemented!(botan::kdf(
        botan::KdfAlgorithm::Hkdf(botan::HashAlgorithm::Sha256),
        42,
        &secret,
        &salt,
        &label,
    ));
    assert_eq!(derived.len(), 42);

    // The one-width form of SP800-108
    let derived = skip_if_not_implemented!(botan::kdf(
        botan::KdfAlgorithm::Sp800108Counter(
            botan::MacAlgorithm::Hmac(botan::HashAlgorithm::Sha256),
            Some(8),
            None
        ),
        32,
        &secret,
        &salt,
        &label,
    ));
    assert_eq!(derived.len(), 32);

    Ok(())
}

#[test]
fn test_pbkdf_algo_runtime() -> Result<(), botan::Error> {
    let salt = botan::hex_decode("000102030405060708090A0B0C")?;
    let pbkdf = skip_if_not_implemented!(botan::pbkdf(
        botan::PasswordHashAlgorithm::Pbkdf2(botan::HashAlgorithm::Sha256),
        16,
        "passphrase",
        &salt,
        10000,
    ));
    assert_eq!(pbkdf.len(), 16);

    let pbkdf = skip_if_not_implemented!(botan::pbkdf(
        botan::PasswordHashAlgorithm::Pbkdf2Mac(botan::MacAlgorithm::Hmac(
            botan::HashAlgorithm::Sha512,
        )),
        16,
        "passphrase",
        &salt,
        10000,
    ));
    assert_eq!(pbkdf.len(), 16);

    Ok(())
}

#[test]
fn test_pkcs12_kdf_algo_runtime() -> Result<(), botan::Error> {
    let salt = botan::hex_decode("000102030405060708090A0B0C")?;
    let pkcs12 = botan::PasswordHashAlgorithm::Pkcs12Kdf(botan::HashAlgorithm::Sha256, 1);
    let key = skip_if_not_implemented!(botan::derive_key_from_password(
        pkcs12,
        16,
        "passphrase",
        &salt,
        1000,
        0,
        0
    ));
    assert_eq!(key.len(), 16);
    Ok(())
}

#[test]
fn test_pkcs8_kdf_runtime() -> Result<(), botan::Error> {
    let mut rng = botan::RandomNumberGenerator::new_userspace()?;
    let key = skip_if_not_implemented!(botan::Privkey::create(
        botan::PublicKeyAlgorithm::Ecdsa,
        botan::EcGroupId::Secp256r1,
        &mut rng
    ));

    let pem = skip_if_not_implemented!(key.pem_encode_encrypted_with_options(
        "passphrase",
        botan::CipherAlgorithm::Cbc(botan::BlockCipherAlgorithm::Aes256, None),
        botan::Pkcs8Kdf::Pbkdf2(botan::HashAlgorithm::Sha512),
        10000,
        &mut rng
    ));
    let loaded = botan::Privkey::load_encrypted_pem(&pem, "passphrase")?;
    assert_eq!(loaded.algo_name()?, "ECDSA");

    let pem = skip_if_not_implemented!(key.pem_encode_encrypted_with_options(
        "passphrase",
        botan::CipherAlgorithm::Cbc(botan::BlockCipherAlgorithm::Aes256, None),
        botan::Pkcs8Kdf::Scrypt,
        8192,
        &mut rng
    ));
    let loaded = botan::Privkey::load_encrypted_pem(&pem, "passphrase")?;
    assert_eq!(loaded.algo_name()?, "ECDSA");

    Ok(())
}

#[test]
fn test_signature_params() -> Result<(), botan::Error> {
    use botan::SignatureParamsIdentifier;
    use botan::{HashAlgorithm, PublicKeyAlgorithm, SignatureParams};

    // Botan 2 requires the EMSA1 spelling for hash parameterized schemes
    let expected_hash_padding = if botan::Version::current()?.major == 2 {
        "EMSA1(SHA-256)"
    } else {
        "SHA-256"
    };
    assert_eq!(
        SignatureParams::Hash(HashAlgorithm::Sha256).botan_name(),
        expected_hash_padding
    );
    assert_eq!(
        SignatureParams::RsaPss {
            hash: HashAlgorithm::Sha256,
            salt_len: None
        }
        .botan_name(),
        "PSS(SHA-256)"
    );
    assert_eq!(
        SignatureParams::RsaPss {
            hash: HashAlgorithm::Sha256,
            salt_len: Some(32)
        }
        .botan_name(),
        "PSS(SHA-256,MGF1,32)"
    );
    assert_eq!(
        SignatureParams::RsaPssRaw {
            hash: HashAlgorithm::Sha512,
            salt_len: Some(64)
        }
        .botan_name(),
        "PSS_Raw(SHA-512,MGF1,64)"
    );
    assert_eq!(
        SignatureParams::RsaPkcs1v15(HashAlgorithm::Sha384).botan_name(),
        "PKCS1v15(SHA-384)"
    );
    assert_eq!(
        SignatureParams::RsaPkcs1v15Raw(None).botan_name(),
        "PKCS1v15(Raw)"
    );
    assert_eq!(
        SignatureParams::RsaPkcs1v15Raw(Some(HashAlgorithm::Sha256)).botan_name(),
        "PKCS1v15(Raw,SHA-256)"
    );
    assert_eq!(
        SignatureParams::RsaX931(HashAlgorithm::Sha256).botan_name(),
        "X9.31(SHA-256)"
    );
    assert_eq!(SignatureParams::Raw(None).botan_name(), "Raw");
    assert_eq!(
        SignatureParams::Raw(Some(HashAlgorithm::Sha256)).botan_name(),
        "Raw(SHA-256)"
    );
    assert_eq!(
        SignatureParams::Sm2 {
            user_id: "user@example.com".to_string(),
            hash: None
        }
        .botan_name(),
        "user@example.com"
    );
    assert_eq!(
        SignatureParams::Sm2 {
            user_id: "user@example.com".to_string(),
            hash: Some(HashAlgorithm::Sm3)
        }
        .botan_name(),
        "user@example.com,SM3"
    );
    assert_eq!(SignatureParams::Deterministic.botan_name(), "Deterministic");
    assert_eq!(SignatureParams::Randomized.botan_name(), "Randomized");
    assert_eq!(SignatureParams::Ed25519ph.botan_name(), "Ed25519ph");
    assert_eq!(SignatureParams::Ed448ph.botan_name(), "Ed448ph");
    assert_eq!(None::<SignatureParams>.botan_name(), "");

    assert_eq!(PublicKeyAlgorithm::MlKem.botan_name(), "ML-KEM");
    assert_eq!(PublicKeyAlgorithm::MlDsa.botan_name(), "ML-DSA");
    assert_eq!(PublicKeyAlgorithm::SlhDsa.botan_name(), "SLH-DSA");
    assert_eq!(PublicKeyAlgorithm::FrodoKem.botan_name(), "FrodoKEM");
    assert_eq!(
        PublicKeyAlgorithm::ClassicMcEliece.botan_name(),
        "ClassicMcEliece"
    );
    assert_eq!(PublicKeyAlgorithm::HssLms.botan_name(), "HSS-LMS");
    assert_eq!(PublicKeyAlgorithm::Xmss.botan_name(), "XMSS");

    Ok(())
}

#[test]
fn test_signature_params_ecdsa() -> Result<(), botan::Error> {
    let msg = [1u8, 23, 84, 224];
    let mut rng = botan::RandomNumberGenerator::new_userspace()?;

    let ecdsa_key = skip_if_not_implemented!(botan::Privkey::create(
        botan::PublicKeyAlgorithm::Ecdsa,
        botan::EcGroupId::Secp256r1,
        &mut rng,
    ));
    // Passing a HashAlgorithm directly as the signature parameters
    let sig = ecdsa_key.sign(&msg, botan::HashAlgorithm::Sha256, &mut rng)?;

    assert!(ecdsa_key.pubkey()?.verify(
        &msg,
        &sig,
        botan::SignatureParams::Hash(botan::HashAlgorithm::Sha256)
    )?);

    Ok(())
}

#[test]
fn test_signature_params_rsa_pss() -> Result<(), botan::Error> {
    let msg = [1u8, 23, 84, 224];
    let mut rng = botan::RandomNumberGenerator::new_userspace()?;

    let rsa_key = skip_if_not_implemented!(botan::Privkey::create(
        botan::PublicKeyAlgorithm::Rsa,
        2048u32,
        &mut rng
    ));
    let pss = botan::SignatureParams::RsaPss {
        hash: botan::HashAlgorithm::Sha256,
        salt_len: Some(32),
    };
    // The PSS padding is independent of RSA itself
    let sig = skip_if_not_implemented!(rsa_key.sign(&msg, &pss, &mut rng));
    assert!(rsa_key.pubkey()?.verify(&msg, &sig, &pss)?);
    Ok(())
}

#[test]
fn test_signature_params_ed25519() -> Result<(), botan::Error> {
    let msg = [1u8, 23, 84, 224];
    let mut rng = botan::RandomNumberGenerator::new_userspace()?;

    // Pure signing takes no parameters
    let ed_key = skip_if_not_implemented!(botan::Privkey::create(
        botan::PublicKeyAlgorithm::Ed25519,
        "",
        &mut rng
    ));
    let sig = ed_key.sign(&msg, None, &mut rng)?;
    assert!(ed_key.pubkey()?.verify(&msg, &sig, None)?);

    let sig = ed_key.sign(&msg, botan::SignatureParams::Ed25519ph, &mut rng)?;
    assert!(
        ed_key
            .pubkey()?
            .verify(&msg, &sig, botan::SignatureParams::Ed25519ph)?
    );
    Ok(())
}

#[test]
fn test_signature_params_ml_dsa() -> Result<(), botan::Error> {
    let msg = [1u8, 23, 84, 224];
    let mut rng = botan::RandomNumberGenerator::new_userspace()?;

    let key = skip_if_not_implemented!(botan::Privkey::create(
        botan::PublicKeyAlgorithm::MlDsa,
        botan::MlDsaParams::MlDsa6x5,
        &mut rng,
    ));
    let sig = key.sign(&msg, botan::SignatureParams::Deterministic, &mut rng)?;
    assert!(key.pubkey()?.verify(&msg, &sig, None)?);
    Ok(())
}

#[test]
fn test_encryption_params() -> Result<(), botan::Error> {
    use botan::EncryptionParamsIdentifier;
    use botan::{EncryptionParams, HashAlgorithm};

    assert_eq!(
        EncryptionParams::RsaOaep {
            hash: HashAlgorithm::Sha256,
            mgf1_hash: None,
            label: None
        }
        .botan_name(),
        "OAEP(SHA-256,MGF1)"
    );
    assert_eq!(
        EncryptionParams::RsaOaep {
            hash: HashAlgorithm::Sha256,
            mgf1_hash: Some(HashAlgorithm::Sha512),
            label: None
        }
        .botan_name(),
        "OAEP(SHA-256,MGF1(SHA-512))"
    );
    assert_eq!(
        EncryptionParams::RsaOaep {
            hash: HashAlgorithm::Sha256,
            mgf1_hash: None,
            label: Some("label".to_string())
        }
        .botan_name(),
        "OAEP(SHA-256,MGF1,label)"
    );
    assert_eq!(
        EncryptionParams::RsaOaep {
            hash: HashAlgorithm::Sha256,
            mgf1_hash: Some(HashAlgorithm::Sha512),
            label: Some("label".to_string())
        }
        .botan_name(),
        "OAEP(SHA-256,MGF1(SHA-512),label)"
    );
    assert_eq!(EncryptionParams::RsaPkcs1v15.botan_name(), "PKCS1v15");
    assert_eq!(EncryptionParams::Raw.botan_name(), "Raw");
    assert_eq!(
        EncryptionParams::Sm2(HashAlgorithm::Sm3).botan_name(),
        "SM3"
    );
    assert_eq!(None::<EncryptionParams>.botan_name(), "");

    Ok(())
}

#[test]
fn test_encryption_params_rsa_oaep() -> Result<(), botan::Error> {
    let msg = [1u8, 23, 84, 224];
    let mut rng = botan::RandomNumberGenerator::new_userspace()?;

    // OAEP with a label; decryption must use the same label
    let rsa_key = skip_if_not_implemented!(botan::Privkey::create(
        botan::PublicKeyAlgorithm::Rsa,
        2048u32,
        &mut rng
    ));
    let oaep = botan::EncryptionParams::RsaOaep {
        hash: botan::HashAlgorithm::Sha256,
        mgf1_hash: None,
        label: Some("label".to_string()),
    };
    // The OAEP padding is independent of RSA itself
    let ctext = skip_if_not_implemented!(rsa_key.pubkey()?.encrypt(&msg, &oaep, &mut rng));
    assert_eq!(rsa_key.decrypt(&ctext, &oaep)?, msg);

    let wrong_label = botan::EncryptionParams::RsaOaep {
        hash: botan::HashAlgorithm::Sha256,
        mgf1_hash: None,
        label: Some("wrong".to_string()),
    };
    assert!(rsa_key.decrypt(&ctext, &wrong_label).is_err());
    Ok(())
}

#[test]
fn test_encryption_params_sm2() -> Result<(), botan::Error> {
    let msg = [1u8, 23, 84, 224];
    let mut rng = botan::RandomNumberGenerator::new_userspace()?;

    // SM2 encryption, with an explicit hash and with the SM3 default
    let sm2_key = skip_if_not_implemented!(botan::Privkey::create(
        botan::PublicKeyAlgorithm::Sm2,
        botan::EcGroupId::Sm2p256v1,
        &mut rng,
    ));
    let ctext = sm2_key.pubkey()?.encrypt(
        &msg,
        botan::EncryptionParams::Sm2(botan::HashAlgorithm::Sha256),
        &mut rng,
    )?;
    assert_eq!(
        sm2_key.decrypt(
            &ctext,
            botan::EncryptionParams::Sm2(botan::HashAlgorithm::Sha256)
        )?,
        msg
    );

    let ctext = sm2_key.pubkey()?.encrypt(&msg, None, &mut rng)?;
    assert_eq!(sm2_key.decrypt(&ctext, None)?, msg);

    Ok(())
}

#[test]
fn test_keygen_params() -> Result<(), botan::Error> {
    use botan::KeyGenParamsIdentifier;

    assert_eq!(botan::EcGroupId::Secp521r1.botan_name(), "secp521r1");
    assert_eq!(
        botan::EcGroupId::Brainpool256r1.botan_name(),
        "brainpool256r1"
    );
    assert_eq!(botan::DlGroup::ModpIetf2048.botan_name(), "modp/ietf/2048");
    assert_eq!(
        botan::DlGroup::FfdheIetf4096.botan_name(),
        "ffdhe/ietf/4096"
    );
    assert_eq!(botan::MlKemParams::MlKem1024.botan_name(), "ML-KEM-1024");
    assert_eq!(botan::MlDsaParams::MlDsa8x7.botan_name(), "ML-DSA-8x7");
    assert_eq!(
        botan::SlhDsaParams::Sha2_128s.botan_name(),
        "SLH-DSA-SHA2-128s"
    );
    assert_eq!(
        botan::SlhDsaParams::Shake256f.botan_name(),
        "SLH-DSA-SHAKE-256f"
    );
    assert_eq!(
        botan::FrodoKemParams::EFrodo640Shake.botan_name(),
        "eFrodoKEM-640-SHAKE"
    );
    assert_eq!(
        botan::ClassicMcElieceParams::P6960119pcf.botan_name(),
        "ClassicMcEliece_6960119pcf"
    );
    assert_eq!(
        botan::XmssParams::Shake256_10_192.botan_name(),
        "XMSS-SHAKE256_10_192"
    );
    assert_eq!(2048u32.botan_name(), "2048");

    Ok(())
}

#[test]
fn test_keygen_params_dh() -> Result<(), botan::Error> {
    let mut rng = botan::RandomNumberGenerator::new_userspace()?;
    let dh_key = skip_if_not_implemented!(botan::Privkey::create(
        botan::PublicKeyAlgorithm::Dh,
        botan::DlGroup::ModpIetf2048,
        &mut rng,
    ));
    assert_eq!(dh_key.algo_name()?, "DH");
    Ok(())
}

#[test]
fn test_keygen_params_ml_kem() -> Result<(), botan::Error> {
    let mut rng = botan::RandomNumberGenerator::new_userspace()?;
    let key = skip_if_not_implemented!(botan::Privkey::create(
        botan::PublicKeyAlgorithm::MlKem,
        botan::MlKemParams::MlKem768,
        &mut rng,
    ));
    assert_eq!(key.algo_name()?, "ML-KEM");
    Ok(())
}

#[test]
fn test_keygen_params_slh_dsa() -> Result<(), botan::Error> {
    let mut rng = botan::RandomNumberGenerator::new_userspace()?;
    let key = skip_if_not_implemented!(botan::Privkey::create(
        botan::PublicKeyAlgorithm::SlhDsa,
        botan::SlhDsaParams::Shake128f,
        &mut rng,
    ));
    let sig = key.sign(&[1, 2, 3], None, &mut rng)?;
    assert!(key.pubkey()?.verify(&[1, 2, 3], &sig, None)?);
    Ok(())
}

#[test]
fn test_mac() -> Result<(), botan::Error> {
    let mut mac = skip_if_not_implemented!(botan::MsgAuthCode::new("HMAC(SHA-384)"));

    let key_spec = mac.key_spec()?;
    assert_eq!(mac.output_length()?, 48);
    assert_eq!(mac.algo_name()?, "HMAC(SHA-384)");

    assert!(key_spec.is_valid_keylength(20));

    mac.set_key(&[0xAA; 20])?;

    mac.update(&[0xDD; 1])?;
    mac.update(&[0xDD; 29])?;
    mac.update(&[0xDD; 20])?;

    let r = mac.finish()?;

    assert_eq!(
        botan::hex_encode(&r)?,
        "88062608D3E6AD8A0AA2ACE014C8A86F0AA635D947AC9FEBE83EF4E55966144B2A5AB39DC13814B94E3AB6E101A34F27"
    );
    Ok(())
}

#[test]
fn test_block_cipher() -> Result<(), botan::Error> {
    let mut bc = skip_if_not_implemented!(botan::BlockCipher::new("AES-128"));

    assert_eq!(bc.algo_name()?, "AES-128");
    assert_eq!(bc.block_size()?, 16);

    let key_spec = bc.key_spec()?;

    assert!(!key_spec.is_valid_keylength(20));
    assert!(key_spec.is_valid_keylength(16));

    assert_eq!(
        bc.set_key(&[0; 32]).unwrap_err().error_type(),
        botan::ErrorType::InvalidKeyLength
    );

    bc.set_key(&[0; 16])?;

    let input = vec![0; 16];

    let exp_ctext = "66E94BD4EF8A2C3B884CFA59CA342B2E";

    let ctext = bc.encrypt_blocks(&input)?;
    assert_eq!(botan::hex_encode(&ctext)?, exp_ctext);

    let ptext = bc.decrypt_blocks(&ctext)?;

    assert_eq!(ptext, input);

    let mut buf = input.clone();
    bc.encrypt_in_place(&mut buf)?;
    assert_eq!(botan::hex_encode(&buf)?, exp_ctext);

    bc.decrypt_in_place(&mut buf)?;
    assert_eq!(buf, input);
    Ok(())
}

#[test]
fn test_cipher() -> Result<(), botan::Error> {
    let mut cipher = skip_if_not_implemented!(botan::Cipher::new(
        "AES-128/GCM",
        botan::CipherDirection::Encrypt
    ));

    assert_eq!(cipher.tag_length(), 16);

    let zero16 = vec![0; 16];
    let zero12 = vec![0; 12];

    assert!(cipher.set_associated_data(&[1, 2, 3]).is_err()); // trying to set AD before key is set
    assert_eq!(
        cipher.set_key(&[0; 42]).unwrap_err().error_type(),
        botan::ErrorType::InvalidKeyLength
    );

    cipher.set_key(&zero16)?;

    assert!(cipher.update_granularity() > 0);

    if let Some(i) = cipher.ideal_update_granularity() {
        assert!(i >= cipher.update_granularity());
    }

    cipher.set_associated_data(&[1, 2, 3])?;
    cipher.set_associated_data(&[])?;

    let ctext = cipher.process(&zero12, &zero16)?;

    assert_eq!(
        botan::hex_encode(&ctext)?,
        "0388DACE60B6A392F328C2B971B2FE78AB6E47D42CEC13BDF53A67B21257BDDF"
    );

    let mut cipher = botan::Cipher::new("AES-128/GCM", botan::CipherDirection::Decrypt)?;
    cipher.set_key(&zero16)?;

    let ptext = cipher.process(&zero12, &ctext)?;

    assert_eq!(ptext, zero16);
    Ok(())
}

#[test]
fn test_incremental_cipher() -> Result<(), botan::Error> {
    // This test requires Botan 2.9 or higher to work correctly
    if !botan::Version::current()?.at_least(2, 9) {
        return Ok(());
    }

    // Key    = 00000000000000000000000000000000
    // Nonce  = 0AAC82F3E53C2756034F7BD5827C9EDD
    // In     = 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    // Out    = 38C21B6430D9A3E4BC6749405765653AE91051E96CE0D076141DD7B515EC150FDB8A65EE988D206C9F64874664CDBF61257FFAE521B9A5EB5B35E3745F4232025B269A6CD7DCFE19153ECF7341CE2C6A6A87F95F2109841350DA3D24EEED4E4E32D2BED880737670FFE8ED76DB890FD72A0076300E50914984A777C9F2BC843977396C602B24E7A045F04D15CD2EAC01AD8808064CFE5A2DC1AE9FFFA4BF0A6F0C07668097DEEB9C5CA5EC1F9A52F96A403B73FEA2DBBF44473D355553EE7FB1B4D6630777DAF67804BE213089B9F78652CE970C582FD813F87FF0ECBACCE1CA46247E20D09F3E0B4EF6BFCD13244C6877F25E6646252CAD6EB7DBBA3476AAAC83BC3285FF70B50D6CDEDC8E5921944A

    let key = botan::hex_decode("00000000000000000000000000000000")?;
    let nonce = botan::hex_decode("0AAC82F3E53C2756034F7BD5827C9EDD")?;
    let input = botan::hex_decode(
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    )?;
    let output = botan::hex_decode(
        "38C21B6430D9A3E4BC6749405765653AE91051E96CE0D076141DD7B515EC150FDB8A65EE988D206C9F64874664CDBF61257FFAE521B9A5EB5B35E3745F4232025B269A6CD7DCFE19153ECF7341CE2C6A6A87F95F2109841350DA3D24EEED4E4E32D2BED880737670FFE8ED76DB890FD72A0076300E50914984A777C9F2BC843977396C602B24E7A045F04D15CD2EAC01AD8808064CFE5A2DC1AE9FFFA4BF0A6F0C07668097DEEB9C5CA5EC1F9A52F96A403B73FEA2DBBF44473D355553EE7FB1B4D6630777DAF67804BE213089B9F78652CE970C582FD813F87FF0ECBACCE1CA46247E20D09F3E0B4EF6BFCD13244C6877F25E6646252CAD6EB7DBBA3476AAAC83BC3285FF70B50D6CDEDC8E5921944A",
    )?;

    // encode
    let mut cipher = skip_if_not_implemented!(botan::Cipher::new(
        "AES-128/GCM",
        botan::CipherDirection::Encrypt
    ));
    cipher.set_key(&key)?;
    cipher.start(&nonce)?;

    let enc_iter = input.chunks(cipher.update_granularity()).enumerate();
    let chunks = if input.len() % cipher.update_granularity() == 0 {
        input.len() / cipher.update_granularity()
    } else {
        input.len() / cipher.update_granularity() + 1
    };
    let mut enc_out = vec![0; 0];
    for (cnt, v) in enc_iter {
        let mut res = if (cnt + 1) < chunks {
            cipher.update(v)?
        } else {
            cipher.finish(v)?
        };
        enc_out.append(&mut res);
    }

    assert_eq!(
        botan::hex_encode(&enc_out)?,
        "38C21B6430D9A3E4BC6749405765653AE91051E96CE0D076141DD7B515EC150FDB8A65EE988D206C9F64874664CDBF61257FFAE521B9A5EB5B35E3745F4232025B269A6CD7DCFE19153ECF7341CE2C6A6A87F95F2109841350DA3D24EEED4E4E32D2BED880737670FFE8ED76DB890FD72A0076300E50914984A777C9F2BC843977396C602B24E7A045F04D15CD2EAC01AD8808064CFE5A2DC1AE9FFFA4BF0A6F0C07668097DEEB9C5CA5EC1F9A52F96A403B73FEA2DBBF44473D355553EE7FB1B4D6630777DAF67804BE213089B9F78652CE970C582FD813F87FF0ECBACCE1CA46247E20D09F3E0B4EF6BFCD13244C6877F25E6646252CAD6EB7DBBA3476AAAC83BC3285FF70B50D6CDEDC8E5921944A"
    );

    // Try the same with the allocation-free interface.
    cipher.set_key(&key)?;
    cipher.start(&nonce)?;
    let mut enc_out_prealloc = vec![0; input.len() + cipher.tag_length()];
    let mut written = 0;
    for (cnt, v) in input.chunks(cipher.update_granularity()).enumerate() {
        if (cnt + 1) < chunks {
            written += cipher.update_into(v, &mut enc_out_prealloc[written..])?
        } else {
            written += cipher.finish_into(v, &mut enc_out_prealloc[written..])?
        }
    }
    assert_eq!(enc_out, enc_out_prealloc);

    // decode
    let mut cipher = botan::Cipher::new("AES-128/GCM", botan::CipherDirection::Decrypt)?;
    cipher.set_key(&key)?;
    cipher.start(&nonce)?;
    let chunk_size = cipher.update_granularity();
    let mut dec_iter = output.chunks(chunk_size).enumerate();
    let chunks = if output.len() % chunk_size == 0 {
        output.len() / chunk_size
    } else {
        output.len() / chunk_size + 1
    };
    let mut dec_out = vec![0; 0];
    for (cnt, v) in dec_iter.by_ref() {
        let mut res = cipher.update(v)?;
        dec_out.append(&mut res);
        if (cnt + 3) == chunks {
            break;
        }
    }
    let mut remain = vec![0; 0];
    let (_, v) = dec_iter.next().unwrap(); //  the one before last one
    remain.append(v.to_vec().as_mut());
    let (_, v) = dec_iter.next().unwrap(); //  last one
    remain.append(v.to_vec().as_mut());
    let mut res = cipher.finish(&remain)?;
    dec_out.append(&mut res);
    assert_eq!(
        botan::hex_encode(&dec_out)?,
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );

    // Try the same with the allocation-free interface.
    cipher.set_key(&key)?;
    cipher.start(&nonce)?;
    let mut dec_out_prealloc = vec![0; output.len() - cipher.tag_length()];
    let mut written = 0;
    for (cnt, v) in output.chunks(chunk_size).enumerate() {
        if (cnt + 1) < chunks {
            written += cipher.update_into(v, &mut dec_out_prealloc[written..])?
        } else {
            written += cipher.finish_into(v, &mut dec_out_prealloc[written..])?
        }
    }
    assert_eq!(dec_out, dec_out_prealloc);

    Ok(())
}

#[test]
fn test_cipher_padding() -> Result<(), botan::Error> {
    let mut cipher = skip_if_not_implemented!(botan::Cipher::new(
        "AES-128/CBC/PKCS7",
        botan::CipherDirection::Encrypt
    ));
    let key = [0; 16];
    let nonce = [0; 16];
    let msg = [0; 8];

    cipher.set_key(&key)?;
    cipher.start(&nonce)?;
    let ct = cipher.finish(&msg)?;

    let mut cipher = botan::Cipher::new("AES-128/CBC/PKCS7", botan::CipherDirection::Decrypt)?;
    cipher.set_key(&key)?;
    cipher.start(&nonce)?;
    assert_eq!(cipher.finish(&ct)?, msg);

    Ok(())
}

#[test]
fn test_chacha() -> Result<(), botan::Error> {
    let mut cipher = skip_if_not_implemented!(botan::Cipher::new(
        "ChaCha20",
        botan::CipherDirection::Encrypt
    ));

    assert_eq!(cipher.tag_length(), 0);

    let key_spec = cipher.key_spec()?;

    assert!(!key_spec.is_valid_keylength(0));
    assert!(key_spec.is_valid_keylength(16));
    assert!(key_spec.is_valid_keylength(32));
    assert!(!key_spec.is_valid_keylength(48));

    let key = vec![0; 32];

    let expected = botan::hex_decode(
        "76B8E0ADA0F13D90405D6AE55386BD28BDD219B8A08DED1AA836EFCC8B770DC7DA41597C5157488D7724E03FB8D84A376A43B8F41518A11CC387B669",
    )?;

    cipher.set_key(&key)?;

    assert!(cipher.set_associated_data(&[1, 2, 3]).is_err()); // not an AEAD
    assert!(cipher.set_associated_data(&[]).is_err());

    let iv = vec![];
    let input = vec![0; expected.len()];

    let ctext = cipher.process(&iv, &input)?;

    assert_eq!(ctext, expected);
    Ok(())
}

#[test]
fn test_kdf() -> Result<(), botan::Error> {
    let salt = botan::hex_decode("000102030405060708090A0B0C")?;
    let label = botan::hex_decode("F0F1F2F3F4F5F6F7F8F9")?;
    let secret = botan::hex_decode("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")?;
    let expected_output = botan::hex_decode(
        "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865",
    )?;

    let output = skip_if_not_implemented!(botan::kdf(
        "HKDF(SHA-256)",
        expected_output.len(),
        &secret,
        &salt,
        &label,
    ));

    assert_eq!(output, expected_output);
    Ok(())
}

#[test]
fn test_pbkdf() -> Result<(), botan::Error> {
    let salt = botan::hex_decode("0001020304050607")?;
    let iterations = 10000;
    let passphrase = "xyz";
    let expected_output =
        botan::hex_decode("DEFD2987FA26A4672F4D16D98398432AD95E896BF619F6A6B8D4ED")?;

    let output = skip_if_not_implemented!(botan::pbkdf(
        "PBKDF2(SHA-256)",
        expected_output.len(),
        passphrase,
        &salt,
        iterations,
    ));

    assert_eq!(output, expected_output);
    Ok(())
}

#[test]
fn test_scrypt() -> Result<(), botan::Error> {
    let salt = botan::hex_decode("4E61436C")?;
    let n = 1024;
    let r = 8;
    let p = 16;
    let passphrase = "password";
    let expected_output =
        botan::hex_decode("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622e")?;

    let output = skip_if_not_implemented!(botan::scrypt(
        expected_output.len(),
        passphrase,
        &salt,
        n,
        r,
        p
    ));

    assert_eq!(output, expected_output);
    Ok(())
}

#[test]
fn test_pwdhash() -> Result<(), botan::Error> {
    let mut rng = botan::RandomNumberGenerator::new()?;
    let salt = rng.read(10)?;
    let msec = 30;
    let (key, r, p, n) = skip_if_not_implemented!(botan::derive_key_from_password_timed(
        "Scrypt",
        32,
        "passphrase",
        &salt,
        msec
    ));
    assert_eq!(key.len(), 32);
    let key2 = botan::derive_key_from_password("Scrypt", 32, "passphrase", &salt, n, r, p)?;
    assert_eq!(key, key2);
    Ok(())
}

#[test]
fn test_hex() -> Result<(), botan::Error> {
    let raw = vec![1, 2, 3, 255, 42, 23];
    assert_eq!(botan::hex_encode(&raw)?, "010203FF2A17");
    assert_eq!(botan::hex_decode("010203FF2A17")?, raw);
    Ok(())
}

#[test]
fn test_rng() -> Result<(), botan::Error> {
    let mut rng = botan::RandomNumberGenerator::new_system()?;

    let read1 = rng.read(10)?;
    let read2 = rng.read(10)?;

    assert!(read1 != read2);

    #[cfg(feature = "rand")]
    {
        use rand_core::TryRng;

        let read1 = rng.try_next_u32()?;
        let read2 = rng.try_next_u32()?;
        assert!(read1 != read2);

        let read1 = rng.try_next_u64()?;
        let read2 = rng.try_next_u64()?;
        assert!(read1 != read2);

        let mut bytes = vec![0; 64];
        rng.try_fill_bytes(&mut bytes)?;
    }

    Ok(())
}

#[test]
fn test_crl() -> Result<(), botan::Error> {
    let crl_pem = r"-----BEGIN X509 CRL-----
MIIBszCBnAIBATANBgkqhkiG9w0BAQsFADAjMRQwEgYDVQQDDAtUZXN0IFN1YiBD
QTELMAkGA1UEBhMCREUXDTE3MDcyNjEzMjQ0N1oXDTE3MTAyNTEzMjQ0N1owFDAS
AgEBFw0xNzA3MjYwNzI0NDdaoC8wLTAKBgNVHRQEAwIBAjAfBgNVHSMEGDAWgBTg
jBmqaSWaGiUA9rMouhv3DfnPwDANBgkqhkiG9w0BAQsFAAOCAQEASVKeNF4ozBHs
jKss2P4Wor9/yvCi6PH+f3fr774nbpW4hK7BqMDfLt1lyPMMRil/Z0FGsTF4wy9f
CSnI/NNIqDLdPfL/Wq40swJvuR3p7CjGwEZjfYJ3Zbz+JZJBws7Eg6JtBLHAc9JQ
uw9odU3oBt9w9DP0Oh3idfXAQp1Ho/nK+ssXOEo1ADETFjaVooXSpeJ7Khi/6Asq
L8A/gDTbuT6K3bEusSXhMo1juAN3oDj7Ruev+CWx0EkxtM9AUBzw707kL7ELxm3g
8FsPC0ejfaQIPluaEBgTuaHtGCUCKnUeUYc2MHPJZZWSaNpqv9OLoAn/25tvsyvI
pIKYuraHXw==
-----END X509 CRL-----";

    let cert_pem = r"-----BEGIN CERTIFICATE-----
MIIDbzCCAlegAwIBAgIBATANBgkqhkiG9w0BAQsFADAjMRQwEgYDVQQDDAtUZXN0
IFN1YiBDQTELMAkGA1UEBhMCREUwHhcNMTcwNzI3MDUyNDQ2WhcNMTgwNzI3MTMy
NDQ2WjAfMRAwDgYDVQQDDAdUZXN0IEVFMQswCQYDVQQGEwJERTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAJWomlxlqcdd/t7IQjIGy2M0nEP8Bah1ooLr
Iq73gzeVFM4qIjKL2OyQYbJDLkMXWUmzmX5P5cGG3pjAJ+Van0ch+OL6Utj8RijJ
Ufc10Oo/TIVzIXbMxIa1oLZ8gQ73nhFkNxQZxzgsKop8wPPTdo41p3DSw/+a9cD0
bmqgjSMDYydfuo/42bLeSmlLYhF18T5C1gUn+JXMvQJSI6kLPczsi+mQ0N0GtV0C
1whWBo1atAUK3OeYGRDzIXnE591vXICYg1JBjjEYe6VNK/B3vCEu/QFRLtF3IYHc
loU4uurI8HfgeEbJ/H3/uDrUwgahuoIqRXtxNIQv1qGXwbAnPBcCAwEAAaOBsTCB
rjA1BgNVHR8ELjAsMCqgKKAmhiRodHRwOi8vbG9jYWxob3N0L3N1YmNhL2NybGRw
L2NybC5jcmwwHwYDVR0jBBgwFoAU4IwZqmklmholAPazKLob9w35z8AwHQYDVR0O
BBYEFITwNLOf7HFKC/d5A2X3c8Qdd3sQMA4GA1UdDwEB/wQEAwIHgDAPBgNVHRMB
Af8EBTADAQEAMBQGA1UdEQQNMAuCCWR1bW15aG9zdDANBgkqhkiG9w0BAQsFAAOC
AQEABaLToWh/aCEOlWbi810W1FeAvkwJYSqyYK6hyFYiQ6dn0x4OnqytfVxYKaj6
wp1OOy/aAG9sSak2/Yp18J7U9Nnl/fz66TNBwjsipAo2auHsqfvrxQl4xEyovdzp
OhJY4gLUPrmbecsmI4UTU6Xl9IGMDh9LPAn1ErYUvvolJp9Y6XlSb/jHT/7BDMmq
JwToSRDikiaCKtrjQvtgw5vFUfcBqKlQmy70ZxIHW92E4cq1twugzc1RpO/c0mxj
zjd8FaHJYT9q6z5fRhloqN6w46mS9nbt8xa4As9ULoMcpeVglDXXLh+A8HLLudWD
ZB6LDkS9rU3WAqYfPzNZ5AR06A==
-----END CERTIFICATE-----";

    let crl = skip_if_not_implemented!(botan::CRL::load(crl_pem.as_bytes()));

    let cert = botan::Certificate::load(cert_pem.as_bytes())?;

    assert!(crl.is_revoked(&cert)?);

    Ok(())
}

#[cfg(botan_ffi_20260303)]
#[test]
fn test_crl_creation() -> Result<(), botan::Error> {
    let ca_key_pem = r"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgoVEKnWZw2Bfrf3MM
WLrfvRcAqq/sOf58jny37NLGQHShRANCAARageRLkKQEh1M86zvqeeesx2u9duLP
iWtHjIcunpiq6+IiB8IVu7Ncu6uPKoFS/mWzTvjgdNusmgNle9p3OAbE
-----END PRIVATE KEY-----";

    let ca_pem = r"-----BEGIN CERTIFICATE-----
MIIBxTCCAWugAwIBAgIRANaPVuZZ0F1TP1Cyepqi9UcwCgYIKoZIzj0EAwIwKzEp
MCcGA1UEAxMgVGVzdCBDQS9VUy9Cb3RhbiBQcm9qZWN0L1Rlc3RpbmcwIBcNMjUx
MTIxMTUzOTQ2WhgPMjEyNTEwMjgxNTM5NDZaMCsxKTAnBgNVBAMTIFRlc3QgQ0Ev
VVMvQm90YW4gUHJvamVjdC9UZXN0aW5nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEWoHkS5CkBIdTPOs76nnnrMdrvXbiz4lrR4yHLp6YquviIgfCFbuzXLurjyqB
Uv5ls0744HTbrJoDZXvadzgGxKNuMGwwIQYDVR0OBBoEGM6/Sxg0CYRYRGfOWslf
ejh8frTqyJmK9jAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBATAj
BgNVHSMEHDAagBjOv0sYNAmEWERnzlrJX3o4fH606siZivYwCgYIKoZIzj0EAwID
SAAwRQIgB1pUBb+jznOrFBTDz9r60f6Q548KdqQX5IEALLD+Gl0CIQCCh6ZvmIGk
Poyp/IDllrZcbKGbMPvMHE81r33DwgShBg==
-----END CERTIFICATE-----";

    let sub1_pem = r"-----BEGIN CERTIFICATE-----
MIIBtjCCAVygAwIBAgIRANYzqdzaS1B3OIKXqOo2NK0wCgYIKoZIzj0EAwIwKzEp
MCcGA1UEAxMgVGVzdCBDQS9VUy9Cb3RhbiBQcm9qZWN0L1Rlc3RpbmcwIBcNMjUx
MTIxMTU0MjE0WhgPMjEyNTEwMjgxNTQyMTRaMDIxMDAuBgNVBAMTJ1Rlc3QgQ2Vy
dCBTdWIxL1VTL0JvdGFuIFByb2plY3QvVGVzdGluZzBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABPuKRaa3tieYoeaIq0EwKgEaWQQqArGEJI4voYKoyz4Yr4PoAowX
Aw6iay0vSDcu2L3q6RsNlS0kR1COb+qfh22jWDBWMCEGA1UdDgQaBBg8yOoSIn4A
jnsn42OMNUCjcQ/skT6rbQ4wDAYDVR0TAQH/BAIwADAjBgNVHSMEHDAagBjOv0sY
NAmEWERnzlrJX3o4fH606siZivYwCgYIKoZIzj0EAwIDSAAwRQIhAJ3K4x2Jlgvu
n6p9N+7O4X+auqbkeTBrvDWymJBOcoCuAiA6KO5WedzThA4c+seatfc3Lr8WLM9f
CxcfHT040ib+lQ==
-----END CERTIFICATE-----
";

    let sub2_pem = r"
-----BEGIN CERTIFICATE-----
MIIBtjCCAVygAwIBAgIRAMtzPuWhJ9gzszvF+b/Knp4wCgYIKoZIzj0EAwIwKzEp
MCcGA1UEAxMgVGVzdCBDQS9VUy9Cb3RhbiBQcm9qZWN0L1Rlc3RpbmcwIBcNMjUx
MTIxMTU0MjE4WhgPMjEyNTEwMjgxNTQyMThaMDIxMDAuBgNVBAMTJ1Rlc3QgQ2Vy
dCBTdWIyL1VTL0JvdGFuIFByb2plY3QvVGVzdGluZzBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABJOWUmHvX7EEIcpOeYOd4olY5/FhK8R81zrEAj7ZFZzdUPkSWQo7
Tw4wEKhEh5yWnpf5/GYPeLeJVILNl6V3CC2jWDBWMCEGA1UdDgQaBBjVnj0PMoah
Z75YsOESDdjAOKRH2X00f1wwDAYDVR0TAQH/BAIwADAjBgNVHSMEHDAagBjOv0sY
NAmEWERnzlrJX3o4fH606siZivYwCgYIKoZIzj0EAwIDSAAwRQIgbsswTSNN5oiY
RjfYKoLqBqiSXUwMobCm/a/AmYWCm1gCIQCT5AS0BZYHqcJaMFnvqvQoiP5pG4UA
rWSdD+Aor4KcEQ==
-----END CERTIFICATE-----
";

    let mut rng = botan::RandomNumberGenerator::new()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let ca_cert = skip_if_not_implemented!(botan::Certificate::load(ca_pem.as_bytes()));
    let ca_key = botan::Privkey::load_pem(ca_key_pem)?;
    let ca_pubkey = ca_cert.public_key()?;

    let sub1_cert = botan::Certificate::load(sub1_pem.as_bytes())?;
    let sub2_cert = botan::Certificate::load(sub2_pem.as_bytes())?;

    let crl = botan::CRL::new(&mut rng, &ca_cert, &ca_key, now, 600, None, None)?;
    assert!(crl.verify(&ca_pubkey)?);
    assert!(
        sub1_cert
            .verify_with_crl(&[], &[&ca_cert], None, None, None, &[&crl])?
            .success()
    );
    assert!(
        sub2_cert
            .verify_with_crl(&[], &[&ca_cert], None, None, None, &[&crl])?
            .success()
    );

    let to_revoke = botan::CRLEntry::new(&sub2_cert, botan::CRLReason::KeyCompromise)?;

    let crl = crl.revoke(
        &mut rng,
        &ca_cert,
        &ca_key,
        now,
        86400,
        &[&to_revoke],
        None,
        None,
    )?;
    assert!(crl.verify(&ca_pubkey)?);
    assert!(
        sub1_cert
            .verify_with_crl(&[], &[&ca_cert], None, None, None, &[&crl])?
            .success()
    );
    assert!(
        !sub2_cert
            .verify_with_crl(&[], &[&ca_cert], None, None, None, &[&crl])?
            .success()
    );

    let revoked = crl.revoked()?;
    assert_eq!(revoked.len(), 1);
    let revoked_entry = &revoked[0];
    assert_eq!(revoked_entry.reason()?, botan::CRLReason::KeyCompromise);
    assert_eq!(
        revoked_entry.serial_number(),
        botan::MPI::from_str("270431672985589325219914342203841486494")
    );
    assert!(
        now - 20 <= revoked_entry.revocation_date()?
            && revoked_entry.revocation_date()? <= now + 20
    );

    Ok(())
}

#[test]
fn test_certs() -> Result<(), botan::Error> {
    let cert_bits = botan::hex_decode(
        "3082035A30820305A003020102020101300C06082A8648CE3D04030105003050310B3009060355040613024445310D300B060355040A0C0462756E64310C300A060355040B0C03627369310D300B06035504051304343536373115301306035504030C0C637363612D6765726D616E79301E170D3037303731393135323731385A170D3238303131393135313830305A3050310B3009060355040613024445310D300B060355040A0C0462756E64310C300A060355040B0C03627369310D300B06035504051304343536373115301306035504030C0C637363612D6765726D616E79308201133081D406072A8648CE3D02013081C8020101302806072A8648CE3D0101021D00D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF303C041C68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43041C2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B0439040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD021D00D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F020101033A000401364A4B0F0102E9502AB9DC6855D90B065A6F5E5E48395F8309D57C11ABAFF21756607EF6757EC9886CA222D83CA04B1A99FA43C5A9BCE1A38201103082010C30360603551D11042F302D8118637363612D6765726D616E79406273692E62756E642E646586116661783A2B343932323839353832373232300E0603551D0F0101FF040403020106301D0603551D0E041604140096452DE588F966C4CCDF161DD1F3F5341B71E7301F0603551D230418301680140096452DE588F966C4CCDF161DD1F3F5341B71E730410603551D20043A30383036060904007F0007030101013029302706082B06010505070201161B687474703A2F2F7777772E6273692E62756E642E64652F6373636130120603551D130101FF040830060101FF020100302B0603551D1004243022800F32303037303731393135323731385A810F32303237313131393135313830305A300C06082A8648CE3D0403010500034100303E021D00C6B41E830217FD4C93B59E9E2B13734E09C182FA63FAEE4115A8EDD5021D00D27938DA01B8951A9064A1B696AEDF181B74968829C138F0EB2F623B",
    )?;

    let cert = skip_if_not_implemented!(botan::Certificate::load(&cert_bits));

    let key_id = botan::hex_decode("0096452DE588F966C4CCDF161DD1F3F5341B71E7")?;
    assert_eq!(cert.serial_number()?, vec![1]);
    assert_eq!(cert.authority_key_id()?, key_id);
    assert_eq!(cert.subject_key_id()?, key_id);

    assert_eq!(cert.not_before_raw()?, 1184858838);
    assert_eq!(cert.not_after_raw()?, 1831907880);

    #[cfg(feature = "std")]
    {
        assert_eq!(
            cert.not_before()?,
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1184858838)
        );
        assert_eq!(
            cert.not_after()?,
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1831907880)
        );
    }

    assert!(cert.allows_usage(botan::CertUsage::CertificateSign)?);
    assert!(cert.allows_usage(botan::CertUsage::CrlSign)?);
    assert!(!(cert.allows_usage(botan::CertUsage::KeyEncipherment)?));

    let pubkey = cert.public_key()?;

    assert_eq!(pubkey.algo_name()?, "ECDSA");

    assert_eq!(
        botan::hex_encode(&pubkey.fingerprint("SHA-256")?)?,
        "110467922A582F7F35E55DF1C787709A6D27B4F581C02586E9076F1A385404B3"
    );
    Ok(())
}

#[test]
fn test_cert_verify() -> Result<(), botan::Error> {
    let ca = b"-----BEGIN CERTIFICATE-----
MIIBkDCCATegAwIBAgIRANQudMcHu/SmX8470nbNlj0wCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEAxMHVGVzdCBDQTAeFw0xODA4MTYyMjMyNDFaFw00NjAxMDEyMjMyNDFa
MBIxEDAOBgNVBAMTB1Rlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASN
+LHr9ZN72sxZqi4zcYDIg4xzN3DOF3epvlpGHLnju5ogp8dJ46YydTi3g/SfBGOp
j9jrYP5Jgkkmpo0lMh7ho24wbDAhBgNVHQ4EGgQYLg/lfneWJ36rZdGMoVyKD6Zl
mHkST7ZNMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEBMCMGA1Ud
IwQcMBqAGC4P5X53lid+q2XRjKFcig+mZZh5Ek+2TTAKBggqhkjOPQQDAgNHADBE
AiB30ZIFV1cZbknu5lt1fWrM9tNSgCbj5BN9CI+Q9aq1LQIgD9o/8oGmFgvWLjsx
b39VOu00+Vy9kpNO1Sgx7wSWoIU=
-----END CERTIFICATE-----";

    let ee = b"-----BEGIN CERTIFICATE-----
MIIBoDCCAUagAwIBAgIRAK27a2NlSYEH63xIsAbBA1wwCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEAxMHVGVzdCBDQTAeFw0xODA4MTYyMjMzNDBaFw00NjAxMDEyMjMzNDBa
MBoxGDAWBgNVBAMTD1Rlc3QgRW5kIEVudGl0eTBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABDykQMvlV7GyIJeANLWEs5bXReqpvTEFu3zYPBjOhyx784VPVl84h8c5
ycru3Hk8N/SIITSWzpbjPMp9jRbyDy+jdTBzMCEGA1UdDgQaBBjkPzL+BXHtQJDR
ciwvzeHQKuQZOstyM2swGwYDVR0RBBQwEoIQdGVzdC5leGFtcGxlLmNvbTAMBgNV
HRMBAf8EAjAAMCMGA1UdIwQcMBqAGC4P5X53lid+q2XRjKFcig+mZZh5Ek+2TTAK
BggqhkjOPQQDAgNIADBFAiEAowK8jGhosOxQpOCjlRg0nFceQ0ETITQC43fk0CZA
AzMCIEJSRDmXjX8TMTbSfoTLmhaYJnCL+AfHLZLdHlSLDIzh
-----END CERTIFICATE-----";

    // ee but with a bit flipped in the signature
    let bad_ee = b"-----BEGIN CERTIFICATE-----
MIIBoDCCAUagAwIBAgIRAK27a2NlSYEH63xIsAbBA1wwCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEAxMHVGVzdCBDQTAeFw0xODA4MTYyMjMzNDBaFw00NjAxMDEyMjMzNDBa
MBoxGDAWBgNVBAMTD1Rlc3QgRW5kIEVudGl0eTBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABDykQMvlV7GyIJeANLWEs5bXReqpvTEFu3zYPBjOhyx784VPVl84h8c5
ycru3Hk8N/SIITSWzpbjPMp9jRbyDy+jdTBzMCEGA1UdDgQaBBjkPzL+BXHtQJDR
ciwvzeHQKuQZOstyM2swGwYDVR0RBBQwEoIQdGVzdC5leGFtcGxlLmNvbTAMBgNV
HRMBAf8EAjAAMCMGA1UdIwQcMBqAGC4P5X53lid+q2XRjKFcig+mZZh5Ek+2TTAK
BggqhkjOPQQDAgNIADBFAiEAowK8jGhosOxQpOCjlRg0nFceQ0ETITQC43fk0CZA
AzMCIEJSRDmXjX8TMTbSfoTLmhaYJnCL+AfHLZLdHlSLDIzz
-----END CERTIFICATE-----";

    let ca = skip_if_not_implemented!(botan::Certificate::load(ca));

    assert!(ca.to_string()?.starts_with("Version: 3"));

    assert_eq!(ca.public_key_bits()?.len(), 89);

    let ee = botan::Certificate::load(ee)?;
    let bad_ee = botan::Certificate::load(bad_ee)?;

    let ca_dup = ca.clone();

    let result = ee.verify(&[], &[&ca], None, None, None)?;
    assert!(result.success());
    assert_eq!(result.to_string(), "Verified");

    let result = ee.verify(&[], &[&ca], None, None, Some(300))?;
    assert!(!result.success());
    assert_eq!(result.to_string(), "Certificate is not yet valid");

    let result = ee.verify(&[], &[&ca], None, Some("no.hostname.com"), None)?;
    assert!(!result.success());
    assert_eq!(
        result.to_string(),
        "Certificate does not match provided name"
    );

    let result = ee.verify(&[], &[], None, None, None)?;
    assert!(!result.success());
    assert_eq!(result.to_string(), "Certificate issuer not found");

    let result = bad_ee.verify(&[], &[&ca_dup], None, None, None)?;
    assert!(!result.success());
    assert_eq!(result.to_string(), "Signature error");
    Ok(())
}

#[cfg(botan_ffi_20260303)]
#[test]
fn test_cert_getters() -> Result<(), botan::Error> {
    // openssl req -x509 -newkey ed25519 \
    // -keyout /dev/null -days 3650 -nodes \
    // -subj "/C=US/ST=Some state/O=Botan Project/OU=Testing/CN=Test certificate" \
    // -addext "subjectAltName=DNS:botan.randombit.net,URI:https://botan.randombit.net,IP:127.0.0.1,email:testing@randombit.net" \
    // -addext "basicConstraints=critical,CA:TRUE,pathlen:3" \
    // -addext "authorityInfoAccess=OCSP;URI:https://ocsp.botan.randombit.net"

    let cert_pem = r"-----BEGIN CERTIFICATE-----
MIICgDCCAjKgAwIBAgIUNjiedT1Hl76k7Fy3LZP9pvn/TPswBQYDK2VwMGcxCzAJ
BgNVBAYTAlVTMRMwEQYDVQQIDApTb21lIHN0YXRlMRYwFAYDVQQKDA1Cb3RhbiBQ
cm9qZWN0MRAwDgYDVQQLDAdUZXN0aW5nMRkwFwYDVQQDDBBUZXN0IGNlcnRpZmlj
YXRlMB4XDTI2MDMyNjEyMzQyNVoXDTM2MDMyMzEyMzQyNVowZzELMAkGA1UEBhMC
VVMxEzARBgNVBAgMClNvbWUgc3RhdGUxFjAUBgNVBAoMDUJvdGFuIFByb2plY3Qx
EDAOBgNVBAsMB1Rlc3RpbmcxGTAXBgNVBAMMEFRlc3QgY2VydGlmaWNhdGUwKjAF
BgMrZXADIQDrO/Y+zn3jLywZjW0mdmtLDLwGjJVCoBM22wbp9WrMLqOB7zCB7DAd
BgNVHQ4EFgQUZCMU7YjjngDNElfFCQifo4YJVjQwHwYDVR0jBBgwFoAUZCMU7Yjj
ngDNElfFCQifo4YJVjQwWAYDVR0RBFEwT4ITYm90YW4ucmFuZG9tYml0Lm5ldIYb
aHR0cHM6Ly9ib3Rhbi5yYW5kb21iaXQubmV0hwR/AAABgRV0ZXN0aW5nQHJhbmRv
bWJpdC5uZXQwEgYDVR0TAQH/BAgwBgEB/wIBAzA8BggrBgEFBQcBAQQwMC4wLAYI
KwYBBQUHMAGGIGh0dHBzOi8vb2NzcC5ib3Rhbi5yYW5kb21iaXQubmV0MAUGAytl
cANBAFhRmPvQ0gPxfUI2NYSj5/hRn59rgYqkOpXHWnV/RTGAMccUSVwOITNUa/Y7
Dy94ca65ondQ2JGAxBuxZX2HZAE=
-----END CERTIFICATE-----";

    let cert = skip_if_not_implemented!(botan::Certificate::load(cert_pem.as_bytes()));

    assert!(cert.is_ca()?);
    assert_eq!(cert.path_limit()?, 3);

    let ocsp = cert.ocsp_responders()?;
    assert_eq!(ocsp.len(), 1);
    assert_eq!(ocsp[0], "https://ocsp.botan.randombit.net");

    let expected_both = [
        ("X520.Country", vec!["US"]),
        ("X520.State", vec!["Some state"]),
        ("X520.Organization", vec!["Botan Project"]),
        ("X520.OrganizationalUnit", vec!["Testing"]),
        ("X520.CommonName", vec!["Test certificate"]),
    ];

    let expected_subject = [
        ("Email", vec!["testing@randombit.net"]),
        ("RFC822", vec!["testing@randombit.net"]),
        ("DNS", vec!["botan.randombit.net"]),
        ("URI", vec!["https://botan.randombit.net"]),
        ("IP", vec!["127.0.0.1"]),
    ];

    for (k, v) in expected_both.iter().chain(&expected_subject) {
        assert_eq!(&cert.subject_dn(k)?, v);
        assert_eq!(cert.subject_dn(k)?.len(), 1);
    }

    for (k, v) in &expected_both {
        assert_eq!(&cert.issuer_dn(k)?, v);
        assert_eq!(cert.issuer_dn(k)?.len(), 1);
    }

    Ok(())
}

#[test]
#[cfg(botan_ffi_20260811)]
fn test_cert_rfc3779_exts() -> Result<(), botan::Error> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let no_ext_pem = b"-----BEGIN CERTIFICATE-----
MIIBkDCCATegAwIBAgIRANQudMcHu/SmX8470nbNlj0wCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEAxMHVGVzdCBDQTAeFw0xODA4MTYyMjMyNDFaFw00NjAxMDEyMjMyNDFa
MBIxEDAOBgNVBAMTB1Rlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASN
+LHr9ZN72sxZqi4zcYDIg4xzN3DOF3epvlpGHLnju5ogp8dJ46YydTi3g/SfBGOp
j9jrYP5Jgkkmpo0lMh7ho24wbDAhBgNVHQ4EGgQYLg/lfneWJ36rZdGMoVyKD6Zl
mHkST7ZNMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEBMCMGA1Ud
IwQcMBqAGC4P5X53lid+q2XRjKFcig+mZZh5Ek+2TTAKBggqhkjOPQQDAgNHADBE
AiB30ZIFV1cZbknu5lt1fWrM9tNSgCbj5BN9CI+Q9aq1LQIgD9o/8oGmFgvWLjsx
b39VOu00+Vy9kpNO1Sgx7wSWoIU=
-----END CERTIFICATE-----";
    let no_ext_cert = skip_if_not_implemented!(botan::Certificate::load(no_ext_pem));

    assert!(
        no_ext_cert
            .ext_as_blocks_asnum()
            .is_err_and(|e| e.error_type() == botan::ErrorType::NoValueAvailable)
    );

    assert!(
        no_ext_cert
            .ext_as_blocks_rdi()
            .is_err_and(|e| e.error_type() == botan::ErrorType::NoValueAvailable)
    );

    let asnum_pem = b"-----BEGIN CERTIFICATE-----
MIIBiTCCATCgAwIBAgIRAIxkvUFe24qH+RH0D814mEswCgYIKoZIzj0EAwIwADAe
Fw0yNDEwMjIxMDQwMTNaFw0yNTEwMjIxMDQwMTNaMAAwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAAS8OgRLt85kZt8M5MGKcwXyOkUXoylpsp3gKVnQukeEVUPzhYUT
t/nAC9s6tlqQx06aLo4NMpC/ZiLjfqRoh7/Co4GKMIGHMC8GCCsGAQUFBwEIAQH/
BCAwHqACBQChGDAWMAgCAgTSAgIWLjAKAgEAAgUA/////zAhBgNVHQ4EGgQYEekx
OowtPJb0QL2dSh4YuqEhfAEZh6g6MAwGA1UdEwEB/wQCMAAwIwYDVR0jBBwwGoAY
EekxOowtPJb0QL2dSh4YuqEhfAEZh6g6MAoGCCqGSM49BAMCA0cAMEQCIG5s6rM9
fpV76Ydij83G5dfNw8xq/PKohCQAsRc5BFP1AiANm2/BiqB6yzNO3t+1PFdjgpFu
8zYpwnxA4Q4yEvKDxg==
-----END CERTIFICATE-----
";
    let asnum_cert = botan::Certificate::load(asnum_pem)?;

    assert_eq!(asnum_cert.ext_as_blocks_asnum(), Ok(None));
    assert_eq!(
        asnum_cert.ext_as_blocks_rdi(),
        Ok(Some(vec![(0, 4294967295)]))
    );

    let ip_addr_blocks_pem = b"-----BEGIN CERTIFICATE-----
MIICqzCCAmKgAwIBAgIRANPort9DlhqMt2QI6bFLA+IwCgYIKoZIzj0EAwIwSTEQ
MA4GA1UEAxMHVGVzdCBDQTELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUJvdGFuIFBy
b2plY3QxEDAOBgNVBAsTB1Rlc3RpbmcwHhcNMjUwNjE0MTkxNjEzWhcNMjYwNjE0
MTkxNjEzWjBJMRAwDgYDVQQDEwdUZXN0IENBMQswCQYDVQQGEwJVUzEWMBQGA1UE
ChMNQm90YW4gUHJvamVjdDEQMA4GA1UECxMHVGVzdGluZzBJMBMGByqGSM49AgEG
CCqGSM49AwEBAzIABN0stcHCSpEww/+tZrO2Uv36ZJmjLel058Rdr5tdShPCNEmy
MeXB+cGQ1kWVMh+sp6OCATkwggE1MHMGCCsGAQUFBwEHBGcwZTAHBAMAAgEFADAZ
BAIAAjATAxEA/////////////////////zAHBAMAAQIFADAVBAMAAQEwDjAMAwMD
wKgDBQHAqAIAMBcEAwABATAQMA4DBQHAqAICAwUAyAAAADAGBAIAAQUAMCEGA1Ud
DgQaBBgub8YveBEYQ3Q3XbeiHtrh38tnkuzOOtQwDgYDVR0PAQH/BAQDAgGGMFIG
A1UdEQRLMEmBFXRlc3RpbmdAcmFuZG9tYml0Lm5ldIITYm90YW4ucmFuZG9tYml0
Lm5ldIYbaHR0cHM6Ly9ib3Rhbi5yYW5kb21iaXQubmV0MBIGA1UdEwEB/wQIMAYB
Af8CAQEwIwYDVR0jBBwwGoAYLm/GL3gRGEN0N123oh7a4d/LZ5LszjrUMAoGCCqG
SM49BAMCAzcAMDQCGF6Idq8d0ibVHxOTBA7xzFrquTz7crUfBAIYMNxljBJPw+CX
VaIdhfLji2fOE9P8vx9O
-----END CERTIFICATE-----
";
    let ip_addr_blocks_cert = botan::Certificate::load(ip_addr_blocks_pem)?;
    let (v4, v6) = ip_addr_blocks_cert.ext_ip_addr_blocks()?;

    assert_eq!(
        v4,
        vec![
            (None, None),
            (
                Some(1),
                Some(vec![(
                    Ipv4Addr::new(192, 168, 0, 0),
                    Ipv4Addr::new(200, 0, 0, 0)
                )])
            ),
            (Some(2), None),
        ]
    );

    assert_eq!(
        v6,
        vec![
            (
                None,
                Some(vec![(Ipv6Addr::from([255; 16]), Ipv6Addr::from([255; 16]))])
            ),
            (Some(1), None)
        ]
    );

    Ok(())
}

#[test]
fn test_bcrypt() -> Result<(), botan::Error> {
    let pass = "password";
    let mut rng = botan::RandomNumberGenerator::new_system()?;

    let bcrypt1 = skip_if_not_implemented!(botan::bcrypt_hash(pass, &mut rng, 10));

    assert_eq!(bcrypt1.len(), 60);

    let bcrypt2 = botan::bcrypt_hash(pass, &mut rng, 10)?;

    assert_eq!(bcrypt2.len(), 60);

    assert!(bcrypt1 != bcrypt2);

    assert!(botan::bcrypt_verify(pass, &bcrypt1)?);
    assert!(botan::bcrypt_verify(pass, &bcrypt2)?);

    assert!(!(botan::bcrypt_verify("passwurd", &bcrypt2)?));
    Ok(())
}

#[test]
fn test_pubkey() -> Result<(), botan::Error> {
    let mut rng = botan::RandomNumberGenerator::new_system()?;

    let ecdsa_key =
        skip_if_not_implemented!(botan::Privkey::create("ECDSA", "secp256r1", &mut rng));

    assert!(ecdsa_key.check_key(&mut rng)?);
    assert_eq!(ecdsa_key.algo_name()?, "ECDSA");

    assert!(ecdsa_key.get_field("n").is_err());
    assert_eq!(
        ecdsa_key.get_field("order"),
        botan::MPI::from_str("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
    );

    let pub_key = ecdsa_key.pubkey()?;

    assert_eq!(pub_key.algo_name()?, "ECDSA");

    let bits = ecdsa_key.der_encode()?;
    let pem = ecdsa_key.pem_encode()?;
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    assert!(pem.ends_with("-----END PRIVATE KEY-----\n"));

    let pub_bits = pub_key.der_encode()?;
    let pub_pem = pub_key.pem_encode()?;
    assert!(pub_pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
    assert!(pub_pem.ends_with("-----END PUBLIC KEY-----\n"));

    let loaded_key = botan::Privkey::load_der(&bits)?;
    assert!(loaded_key.check_key(&mut rng)?);

    let loaded_pem_key = botan::Pubkey::load_pem(&pub_pem)?;
    assert!(loaded_pem_key.check_key(&mut rng)?);

    let loaded_bits = loaded_key.der_encode()?;
    let loaded_pub_key = loaded_key.pubkey()?;
    assert_eq!(loaded_pub_key.algo_name()?, "ECDSA");
    let loaded_pub_bits = loaded_pub_key.der_encode()?;

    assert_eq!(bits, loaded_bits);
    assert_eq!(pub_bits, loaded_pub_bits);
    Ok(())
}

#[test]
fn test_x25519() -> Result<(), botan::Error> {
    // Test from RFC 8037
    let a_pub_bits =
        botan::hex_decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")?;
    let b_priv_bits =
        botan::hex_decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")?;
    let b_pub_bits =
        botan::hex_decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")?;
    let expected_shared =
        botan::hex_decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")?;

    let a_pub = skip_if_not_implemented!(botan::Pubkey::load_x25519(&a_pub_bits));
    assert_eq!(a_pub.get_x25519_key()?, a_pub_bits);

    let b_priv = botan::Privkey::load_x25519(&b_priv_bits)?;
    assert_eq!(b_priv.get_x25519_key()?, b_priv_bits);

    assert_eq!(b_priv.key_agreement_key()?, b_pub_bits);
    assert_eq!(b_priv.pubkey()?.get_x25519_key()?, b_pub_bits);

    let shared = b_priv.agree(&a_pub_bits, 0, &[], "Raw")?;

    assert_eq!(shared, expected_shared);
    Ok(())
}

#[test]
fn test_ed25519() -> Result<(), botan::Error> {
    let mut rng = botan::RandomNumberGenerator::new_system()?;

    let msg = vec![23, 42, 69, 6, 66];
    let padding = "Pure";

    let ed_priv = skip_if_not_implemented!(botan::Privkey::create("Ed25519", "", &mut rng));

    let signature1 = ed_priv.sign(&msg, padding, &mut rng)?;

    let ed_bits = ed_priv.get_ed25519_key()?;

    let ed_loaded = botan::Privkey::load_ed25519(&ed_bits.1)?;
    let signature2 = ed_loaded.sign(&msg, padding, &mut rng)?;

    let ed_pub = ed_priv.pubkey()?;

    assert!(ed_pub.verify(&msg, &signature1, padding)?);
    assert!(ed_pub.verify(&msg, &signature2, padding)?);

    let ed_loaded = botan::Pubkey::load_ed25519(&ed_bits.0)?;
    assert!(ed_loaded.verify(&msg, &signature1, padding)?);
    assert!(ed_loaded.verify(&msg, &signature2, padding)?);

    assert_eq!(ed_loaded.get_ed25519_key()?, ed_pub.get_ed25519_key()?);

    assert_eq!(signature1, signature2);
    Ok(())
}

#[test]
fn test_rsa() -> Result<(), botan::Error> {
    let mut rng = botan::RandomNumberGenerator::new_system()?;

    let padding = "EMSA-PKCS1-v1_5(SHA-256)";
    let msg = rng.read(32)?;

    let privkey = skip_if_not_implemented!(botan::Privkey::create("RSA", "1024", &mut rng));
    let pubkey = privkey.pubkey()?;

    assert_eq!(privkey.get_field("e"), botan::MPI::from_str("65537"));
    assert_eq!(privkey.get_field("n")?.bit_count()?, 1024);

    assert_eq!(pubkey.get_field("n"), privkey.get_field("n"));

    let p = privkey.get_field("p")?;
    let q = privkey.get_field("q")?;

    assert_eq!(&p * &q, privkey.get_field("n")?);

    let signature = privkey.sign(&msg, padding, &mut rng)?;

    assert!(pubkey.verify(&msg, &signature, padding)?);

    let pubkey = botan::Pubkey::load_rsa(&privkey.get_field("n")?, &privkey.get_field("e")?)?;
    assert!(pubkey.verify(&msg, &signature, padding)?);
    Ok(())
}

#[test]
fn test_pubkey_encryption() -> Result<(), botan::Error> {
    let padding = "EMSA-PKCS1-v1_5(SHA-256)";
    let msg = [1, 2, 3];

    let mut rng = botan::RandomNumberGenerator::new_system()?;
    let key = skip_if_not_implemented!(botan::Privkey::create("RSA", "1024", &mut rng));

    let der = key.der_encode_encrypted("passphrase", &mut rng)?;
    let pem = key.pem_encode_encrypted("pemword", &mut rng)?;

    assert!(pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"));
    assert!(pem.ends_with("-----END ENCRYPTED PRIVATE KEY-----\n"));

    let sig1 = key.sign(&msg, padding, &mut rng)?;

    //assert!(botan::Privkey::load_encrypted_der(&der, "i forget").is_err());

    let load = botan::Privkey::load_encrypted_der(&der, "passphrase")?;
    let sig2 = load.sign(&msg, padding, &mut rng)?;

    assert_eq!(sig1, sig2);

    let load = botan::Privkey::load_encrypted_pem(&pem, "pemword")?;
    let sig3 = load.sign(&msg, padding, &mut rng)?;

    assert_eq!(sig1, sig3);
    Ok(())
}

#[test]
fn test_pubkey_sign() -> Result<(), botan::Error> {
    let msg = vec![1, 23, 42];

    let mut rng = botan::RandomNumberGenerator::new_system()?;

    let ecdsa_key =
        skip_if_not_implemented!(botan::Privkey::create("ECDSA", "secp256r1", &mut rng));
    assert!(ecdsa_key.key_agreement_key().is_err());

    let signature = ecdsa_key.sign(&msg, "EMSA1(SHA-256)", &mut rng)?;

    let pub_key = ecdsa_key.pubkey()?;

    let mut verifier = botan::Verifier::new(&pub_key, "EMSA1(SHA-256)")?;

    verifier.update(&[1])?;
    verifier.update(&[23, 42])?;

    assert!(verifier.finish(&signature)?);

    verifier.update(&[1])?;
    assert!(!(verifier.finish(&signature)?));

    verifier.update(&[1])?;
    verifier.update(&[23, 42])?;

    assert!(verifier.finish(&signature)?);
    Ok(())
}

#[test]
fn test_pubkey_sign_der() -> Result<(), botan::Error> {
    let msg = vec![1, 23, 42];

    let mut rng = botan::RandomNumberGenerator::new_system()?;

    let ecdsa_key =
        skip_if_not_implemented!(botan::Privkey::create("ECDSA", "secp256r1", &mut rng));
    assert!(ecdsa_key.key_agreement_key().is_err());

    let hash = "EMSA1(SHA-256)";

    let mut signer = botan::Signer::new(&ecdsa_key, hash)?;
    signer.update(&msg)?;
    let signature = signer.finish(&mut rng)?;
    assert!(signature.len() <= signer.signature_length());

    let mut signer = botan::Signer::new_with_der_formatted_signatures(&ecdsa_key, hash)?;
    signer.update(&msg)?;
    let signature = signer.finish(&mut rng)?;
    assert!(signature.len() <= signer.signature_length());

    let pub_key = ecdsa_key.pubkey()?;

    let mut verifier = botan::Verifier::new_with_der_formatted_signatures(&pub_key, hash)?;

    verifier.update(&[1])?;
    verifier.update(&[23, 42])?;

    assert!(verifier.finish(&signature)?);

    verifier.update(&[1])?;
    assert!(!(verifier.finish(&signature)?));

    verifier.update(&[1])?;
    verifier.update(&[23, 42])?;

    assert!(verifier.finish(&signature)?);

    // DER Signatures start with a SEQUENCE
    assert_eq!(signature[0], 0x30);

    // The SEQUENCE contains the whole signature (for ECDSA w/ secp256r1, the length can always be encoded with a single byte)
    assert_eq!(signature[1], (signature.len() - 2) as u8);

    // The first element is an INTEGER
    assert_eq!(signature[2], 0x02);
    Ok(())
}

#[test]
fn test_pubkey_encrypt() -> Result<(), botan::Error> {
    let msg = vec![1, 23, 42];

    let mut rng = botan::RandomNumberGenerator::new_system()?;

    let priv_key = skip_if_not_implemented!(botan::Privkey::create("RSA", "2048", &mut rng));
    assert!(priv_key.key_agreement_key().is_err());
    let pub_key = priv_key.pubkey()?;

    let mut encryptor = botan::Encryptor::new(&pub_key, "OAEP(SHA-256)")?;

    let ctext = encryptor.encrypt(&msg, &mut rng)?;
    assert_eq!(ctext.len(), 2048 / 8);

    let mut decryptor = botan::Decryptor::new(&priv_key, "OAEP(SHA-256)")?;

    let ptext = decryptor.decrypt(&ctext)?;

    assert_eq!(ptext, msg);
    Ok(())
}

#[test]
fn test_pubkey_key_agreement() -> Result<(), botan::Error> {
    let mut rng = botan::RandomNumberGenerator::new_system()?;

    let a_priv = skip_if_not_implemented!(botan::Privkey::create("ECDH", "secp384r1", &mut rng));
    let b_priv = botan::Privkey::create("ECDH", "secp384r1", &mut rng)?;

    let a_pub = a_priv.key_agreement_key()?;
    let b_pub = b_priv.key_agreement_key()?;

    let mut a_ka = skip_if_not_implemented!(botan::KeyAgreement::new(&a_priv, "KDF2(SHA-384)"));
    let mut b_ka = botan::KeyAgreement::new(&b_priv, "KDF2(SHA-384)")?;

    let salt = rng.read(16)?;

    let a_key = a_ka.agree(32, &b_pub, &salt)?;
    let b_key = b_ka.agree(32, &a_pub, &salt)?;
    assert_eq!(a_key, b_key);

    let mut a_ka = botan::KeyAgreement::new(&a_priv, "Raw")?;
    let mut b_ka = botan::KeyAgreement::new(&b_priv, "Raw")?;

    let a_key = a_ka.agree(0, &b_pub, &[])?;
    let b_key = b_ka.agree(0, &a_pub, &[])?;

    assert_eq!(a_key, b_key);
    assert_eq!(a_key.len(), 384 / 8);
    Ok(())
}

#[test]
fn test_rfc3394_aes_key_wrap() -> Result<(), botan::Error> {
    let kek =
        botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")?;
    let key =
        botan::hex_decode("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")?;

    let wrapped = skip_if_not_implemented!(botan::rfc3394_key_wrap(&kek, &key));

    assert_eq!(
        botan::hex_encode(&wrapped)?,
        "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
    );

    let unwrapped = botan::rfc3394_key_unwrap(&kek, &wrapped)?;

    assert_eq!(unwrapped, key);
    Ok(())
}

#[test]
fn test_aes_key_wrap() -> Result<(), botan::Error> {
    let kek =
        botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")?;
    let key =
        botan::hex_decode("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")?;

    let wrapped = skip_if_not_implemented!(botan::nist_kw_enc("AES-256", false, &kek, &key));

    assert_eq!(
        botan::hex_encode(&wrapped)?,
        "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
    );
    let unwrapped = botan::nist_kw_dec("AES-256", false, &kek, &wrapped)?;

    assert_eq!(unwrapped, key);

    Ok(())
}

#[test]
fn test_pkcs_hash_id() -> Result<(), botan::Error> {
    assert!(botan::pkcs_hash_id("SHA-192").is_err());

    let id = skip_if_not_implemented!(botan::pkcs_hash_id("SHA-384"));

    assert_eq!(
        botan::hex_encode(&id)?,
        "3041300D060960864801650304020205000430"
    );
    Ok(())
}

#[test]
fn test_ct_compare() -> Result<(), botan::Error> {
    let a = vec![1, 2, 3];

    assert!(botan::const_time_compare(&a, &[1, 2, 3]));
    assert!(!botan::const_time_compare(&a, &[1, 2, 3, 4]));
    assert!(!botan::const_time_compare(&a, &[1, 2, 4]));
    assert!(botan::const_time_compare(&a, &a));
    assert!(botan::const_time_compare(&a, &[1, 2, 3]));
    Ok(())
}

#[test]
fn test_scrub_mem() -> Result<(), botan::Error> {
    let mut v = vec![1, 2, 3];
    botan::scrub_mem(&mut v);
    assert_eq!(v, vec![0, 0, 0]);

    let mut a = [1u32, 2u32, 3u32, 2049903u32];
    botan::scrub_mem(&mut a);
    assert_eq!(a, [0, 0, 0, 0]);
    Ok(())
}

#[test]
fn test_mp() -> Result<(), botan::Error> {
    let mut a = botan::MPI::new()?;
    let mut b = botan::MPI::new()?;

    assert_eq!(a.to_u32()?, 0);
    assert_eq!(b.to_u32()?, 0);

    a.set_i32(9)?;
    b.set_i32(81)?;

    assert_eq!(a.get_bit(0), Ok(true));
    assert_eq!(a.get_bit(1), Ok(false));

    assert_eq!(a.to_u32()?, 9);
    assert_eq!(b.to_u32()?, 81);

    let mut c = &a + &b;
    assert_eq!(c.to_u32()?, 90);

    let d = botan::MPI::from_str("0x5A")?;
    assert_eq!(c, d);

    c *= &botan::MPI::from_str("1030")?;

    assert_eq!(c.to_string()?, "92700");

    assert_eq!(format!("{c}"), "92700");
    assert_eq!(format!("{c:x}"), "016a1c");
    assert_eq!(format!("{c:X}"), "016A1C");
    assert_eq!(format!("{c:#x}"), "0x016a1c");
    assert_eq!(format!("{c:#X}"), "0x016A1C");
    assert_eq!(c.to_bin()?, vec![0x01, 0x6a, 0x1c]);

    let mut s = &c << 32;
    assert_eq!(s.to_hex()?, "016A1C00000000");

    s <<= 4;
    s += 5;
    assert_eq!(s.to_hex()?, "16A1C000000005");

    let mut s = s - 19;
    assert_eq!(s.to_hex()?, "16A1BFFFFFFFF2");

    s += 14;

    s >>= 8;
    assert_eq!(s.to_hex()?, "16A1C0000000");

    let mut t = &s >> 28;
    assert_eq!(t, c);

    t += &s;
    t <<= 4;
    assert_eq!(t.to_hex()?, "016A1C0016A1C0");

    let ten = botan::MPI::new_from_u32(10)?;
    let d = &t / &ten;
    assert_eq!(d.to_hex()?, "243600024360");

    t /= &ten;
    assert_eq!(d, t);
    t /= &ten;

    let r = &t % &ten;

    assert_eq!(r.to_string()?, "4");

    let t = -t * &ten;

    assert!(t.is_negative()?);

    assert_eq!(format!("{t}"), "-39814346982240");
    Ok(())
}

#[test]
fn test_fpe() -> Result<(), botan::Error> {
    let modulus = botan::MPI::from_str("1000000000")?;
    let input = botan::MPI::from_str("939210311")?;

    let key = vec![0; 32];
    let tweak = vec![0; 8];

    let fpe = skip_if_not_implemented!(botan::FPE::new_fe1(&modulus, &key, 8, false));

    let ctext = fpe.encrypt(&input, &tweak)?;

    assert_ne!(ctext, input);

    let ptext = fpe.decrypt(&ctext, &tweak)?;

    assert_eq!(ptext, input);
    Ok(())
}

#[test]
fn test_hotp() -> Result<(), botan::Error> {
    let hotp = skip_if_not_implemented!(botan::HOTP::new(&[0xFF], "SHA-1", 6));
    assert_eq!(hotp.generate(23)?, 330795);

    assert!(hotp.check(330795, 23)?);
    assert!(!hotp.check(330795, 22)?);
    assert!(!hotp.check(330796, 23)?);
    Ok(())
}

#[test]
fn test_totp() -> Result<(), botan::Error> {
    let totp = skip_if_not_implemented!(botan::TOTP::new(
        b"1234567890123456789012345678901234567890123456789012345678901234",
        "SHA-512",
        8,
        30,
    ));

    let time = 1000215000;
    let code = 98961851;

    for skew in 0..=29 {
        assert_eq!(totp.generate(time + skew)?, code);
    }

    for skew in 0..=29 {
        assert!(totp.check(code, time + skew, 0)?);
    }

    for skew in 30..=59 {
        assert!(!totp.check(code, time + skew, 0)?);
        assert!(totp.check(code, time + skew, 1)?);
    }

    Ok(())
}

#[test]
fn test_elgamal() -> Result<(), botan::Error> {
    let mut rng = botan::RandomNumberGenerator::new()?;

    let p_bits = 1024;
    let q_bits = 256;

    let elg = skip_if_not_implemented!(botan::Privkey::create_elgamal(p_bits, q_bits, &mut rng));

    // extract the elements:
    let p = elg.get_field("p")?;
    let q = elg.get_field("q")?;
    let g = elg.get_field("g")?;
    let x = elg.get_field("x")?;
    let y = elg.get_field("y")?;

    // check the lengths:
    assert_eq!(p.bit_count()?, p_bits);
    assert_eq!(q.bit_count()?, q_bits);
    assert!(x.bit_count()? <= q_bits);
    assert!(y.bit_count()? <= p_bits);

    // create a public key:
    let elgp = botan::Pubkey::load_elgamal(&p, &g, &y)?;

    // encrypt a message:
    let padding = "PKCS1v15";
    let ptext = rng.read(16)?;
    let ctext = elgp.encrypt(&ptext, padding, &mut rng)?;

    // decrypt with the private key:
    let recovered = elg.decrypt(&ctext, padding)?;
    assert_eq!(recovered, ptext);

    Ok(())
}

#[test]
fn test_dsa() -> Result<(), botan::Error> {
    let mut rng = botan::RandomNumberGenerator::new()?;

    let p_bits = 1024;
    let q_bits = 256;

    let dsa = skip_if_not_implemented!(botan::Privkey::create_dsa(p_bits, q_bits, &mut rng));

    // extract the elements:
    let p = dsa.get_field("p")?;
    let q = dsa.get_field("q")?;
    let g = dsa.get_field("g")?;
    let x = dsa.get_field("x")?;
    let y = dsa.get_field("y")?;

    // check the lengths:
    assert_eq!(p.bit_count()?, p_bits);
    assert_eq!(q.bit_count()?, q_bits);
    assert!(x.bit_count()? <= q_bits);
    assert!(y.bit_count()? <= p_bits);

    // create a public key:
    let dsap = botan::Pubkey::load_dsa(&p, &q, &g, &y)?;

    // sign a message:
    let padding = "EMSA1(SHA-256)";
    let message = rng.read(16)?;

    let signature = dsa.sign(&message, padding, &mut rng)?;

    // verify the signature:

    assert!(dsap.verify(&message, &signature, padding)?);

    Ok(())
}

#[test]
fn test_zfec() -> Result<(), botan::Error> {
    let k = 2;
    let n = 3;
    let input_bytes = b"abcdefghijklmnop";

    let output_shares = skip_if_not_implemented!(botan::zfec_encode(k, n, input_bytes));

    assert_eq!(output_shares.len(), n);
    assert_eq!(output_shares[0], b"abcdefgh");
    assert_eq!(output_shares[1], b"ijklmnop");
    assert_eq!(output_shares[2], b"qrstuvwX");

    let shares_for_decoding = [
        (2, output_shares[2].as_ref()),
        (0, output_shares[0].as_ref()),
    ];
    let share_size = output_shares[0].len();

    let recovered = botan::zfec_decode(k, n, &shares_for_decoding, share_size)?;

    assert_eq!(recovered, input_bytes);

    Ok(())
}

#[cfg(botan_ffi_20230403)]
#[test]
fn test_kyber() -> Result<(), botan::Error> {
    let mut rng = botan::RandomNumberGenerator::new()?;
    let kyber_priv =
        skip_if_not_implemented!(botan::Privkey::create("Kyber", "Kyber-1024-r3", &mut rng));
    let kyber_pub = kyber_priv.pubkey()?;

    let salt = rng.read(12)?;
    let shared_key_len = 32;
    let kdf = "KDF2(SHA-256)";

    let kem_e = skip_if_not_implemented!(botan::KeyEncapsulation::new(&kyber_pub, kdf));
    let (shared_key, encap_key) = kem_e.create_shared_key(&mut rng, &salt, shared_key_len)?;

    assert_eq!(shared_key.len(), shared_key_len);
    assert_eq!(encap_key.len(), 1568);

    let kem_d = botan::KeyDecapsulation::new(&kyber_priv, kdf)?;
    let shared_key_d = kem_d.decrypt_shared_key(&encap_key, &salt, shared_key_len)?;

    assert_eq!(shared_key, shared_key_d);

    Ok(())
}

#[cfg(botan_ffi_20230403)]
#[test]
fn test_ml_kem() -> Result<(), botan::Error> {
    let mut rng = botan::RandomNumberGenerator::new()?;

    for kl in [512, 768, 1024] {
        let params = format!("ML-KEM-{kl}");
        let sk = skip_if_not_implemented!(botan::Privkey::create("ML-KEM", &params, &mut rng));
        let pk = sk.pubkey()?;

        let pk_bytes = pk.raw_bytes()?;
        let pk2 = botan::Pubkey::load_ml_kem(&pk_bytes)?;

        let salt = rng.read(12)?;
        let shared_key_len = 32;
        let kdf = "KDF2(SHA-256)";

        let kem_e = skip_if_not_implemented!(botan::KeyEncapsulation::new(&pk2, kdf));
        let (shared_key, encap_key) = kem_e.create_shared_key(&mut rng, &salt, shared_key_len)?;

        assert_eq!(shared_key.len(), shared_key_len);

        let kem_d = botan::KeyDecapsulation::new(&sk, kdf)?;
        let shared_key_d = kem_d.decrypt_shared_key(&encap_key, &salt, shared_key_len)?;

        assert_eq!(shared_key, shared_key_d);
    }

    Ok(())
}

#[cfg(botan_ffi_20250506)]
#[test]
fn test_asn1_oid() -> Result<(), botan::Error> {
    let oid = botan::OID::from_str("1.2.840.10045.3.1.7")?;

    assert_eq!(oid.as_string()?, "1.2.840.10045.3.1.7");
    assert_eq!(oid.as_name()?, "secp256r1");

    assert_eq!(oid, botan::OID::from_str("secp256r1")?);

    assert_ne!(oid, botan::OID::from_str("1.2.840.113549.1.1.1")?);

    assert!(oid > botan::OID::from_str("1.2.840.10045.3.1.6")?);
    assert!(oid < botan::OID::from_str("1.2.840.10045.3.1.8")?);

    assert!(oid > botan::OID::from_str("1.2.840.10045.3.1")?);
    assert!(oid < botan::OID::from_str("1.2.840.10045.3.2")?);

    assert!(oid > botan::OID::from_str("1.2.840.10045.3")?);
    assert!(oid < botan::OID::from_str("1.2.840.10045.4")?);

    assert!(oid > botan::OID::from_str("1.2.840.10045")?);
    assert!(oid < botan::OID::from_str("1.2.840.10046")?);

    assert!(oid > botan::OID::from_str("1.2.840")?);
    assert!(oid < botan::OID::from_str("1.2.841")?);

    assert!(oid > botan::OID::from_str("1.2")?);
    assert!(oid < botan::OID::from_str("1.3")?);
    Ok(())
}

#[cfg(botan_ffi_20250506)]
#[test]
fn test_ec_group() -> Result<(), botan::Error> {
    let supports_app_groups = botan::EcGroup::supports_application_specific_groups()?;

    let supports_secp256r1 = botan::EcGroup::supports_named_group("secp256r1")?;

    if supports_app_groups {
        assert!(supports_secp256r1);
    }

    assert!(!botan::EcGroup::supports_named_group("nosuchgroup256r1")?);

    if supports_secp256r1 {
        let secp256r1 = botan::EcGroup::from_name("secp256r1")?;

        let from_pem = botan::EcGroup::from_pem(&secp256r1.pem()?)?;
        let from_der = botan::EcGroup::from_der(&secp256r1.der()?)?;
        let from_oid = botan::EcGroup::from_oid(&secp256r1.oid()?)?;

        assert_eq!(secp256r1, from_pem);
        assert_eq!(secp256r1, from_der);
        assert_eq!(secp256r1, from_oid);

        assert_eq!(
            format!("{:x}", secp256r1.p()?),
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
        );

        assert_eq!(secp256r1.oid()?.as_string()?, "1.2.840.10045.3.1.7");
    }

    if supports_app_groups {
        let secp256r1 = botan::EcGroup::from_name("secp256r1")?;

        let curve_oid = botan::OID::from_str("1.3.6.1.4.1.25258.4.666")?;
        let mycustomp256 = botan::EcGroup::from_params(
            &curve_oid,
            &secp256r1.p()?,
            &secp256r1.a()?,
            &secp256r1.b()?,
            &secp256r1.g_x()?,
            &secp256r1.g_y()?,
            &secp256r1.order()?,
        )?;

        let from_oid = botan::EcGroup::from_oid(&curve_oid)?;

        assert_eq!(mycustomp256, from_oid);

        // Equality is for just the params and ignores the OIDs
        assert_eq!(mycustomp256, secp256r1);

        assert!(botan::EcGroup::unregister(&curve_oid)?);
        assert!(!botan::EcGroup::unregister(&curve_oid)?);
    }

    Ok(())
}

#[cfg(botan_ffi_20260506)]
#[test]
fn test_ec_points() -> Result<(), botan::Error> {
    if !botan::EcGroup::supports_named_group("secp256r1")? {
        return Ok(());
    }

    let group = botan::EcGroup::from_name("secp256r1")?;
    let mut rng = botan::RandomNumberGenerator::new()?;

    let forty_two = botan::MPI::new_from_u32(42)?;
    let scalar_forty_two = botan::EcScalar::from_mpi(&group, &forty_two)?;
    assert_eq!(forty_two, scalar_forty_two.to_mpi()?);

    let identity = group.identity()?;
    let generator = group.generator()?;
    let one = botan::EcScalar::from_mpi(&group, &botan::MPI::new_from_u32(1)?)?;
    assert_eq!(identity, &identity + &identity);

    // test all the ADDs
    {
        let a = group.identity()?;
        let b = group.identity()?;

        let _ = &a + &b;
        let _ = &a + b;

        let b = group.identity()?;
        let _ = a + &b;

        let a = group.identity()?;
        let b = group.identity()?;

        let _ = a + b;
    }

    let order_minus_one = group.order()? - 1;
    let order_minus_one_scalar = botan::EcScalar::from_mpi(&group, &order_minus_one)?;
    assert_eq!(
        generator.mul(&order_minus_one_scalar, &mut rng)? + &generator,
        identity
    );
    assert_eq!(generator, generator.mul(&one, &mut rng)?);
    assert_eq!(identity, identity.mul(&one, &mut rng)?);
    assert_eq!(
        generator.negate()?,
        generator.mul(&order_minus_one_scalar, &mut rng)?
    );

    let pkey = botan::Privkey::create_ec("ECDSA", &group, &mut rng)?;
    let private_value = pkey.get_private_value()?;
    let public_key = pkey.pubkey()?;
    let public_value = botan::EcPoint::from_bytes(&group, &public_key.ec_public_point()?)?;

    assert_eq!(pkey.get_group()?, group);
    assert_eq!(public_key.get_group()?, group);

    let result = generator.mul(&private_value, &mut rng)? + &public_value;
    assert!(!result.is_identity()?);

    let x_bytes = hex::encode(result.to_x_bytes()?);
    let y_bytes = hex::encode(result.to_y_bytes()?);
    let xy_bytes = hex::encode(result.to_xy_bytes()?);
    let uncompressed_bytes = hex::encode(result.to_uncompressed()?);
    let compressed_bytes = hex::encode(result.to_compressed()?);

    assert_eq!(xy_bytes, format!("{}{}", x_bytes, y_bytes));
    assert_eq!(uncompressed_bytes, format!("04{}", xy_bytes));
    assert!(compressed_bytes.starts_with("02") || compressed_bytes.starts_with("03"));
    assert_eq!(&compressed_bytes[2..], x_bytes);

    let x_mpi = botan::MPI::from_str(&format!("0x{}", x_bytes))?;
    let y_mpi = botan::MPI::from_str(&format!("0x{}", y_bytes))?;

    assert_eq!(result, botan::EcPoint::from_xy(&group, &x_mpi, &y_mpi)?);
    assert_eq!(
        result,
        botan::EcPoint::from_bytes(&group, &result.to_uncompressed()?)?
    );
    assert_eq!(
        result,
        botan::EcPoint::from_bytes(&group, &result.to_compressed()?)?
    );

    Ok(())
}

#[cfg(botan_ffi_20260811)]
#[test]
fn test_spake2p() -> Result<(), botan::Error> {
    let params = match botan::Spake2pParams::new(botan::Spake2pCiphersuite::P256Sha256) {
        Ok(params) => params,
        Err(e) => {
            assert_eq!(e.error_type(), botan::ErrorType::NotImplemented);
            return Ok(());
        }
    };

    // Each ciphersuite must be recognized, even if unavailable in this build
    for suite in [
        botan::Spake2pCiphersuite::P256Sha256,
        botan::Spake2pCiphersuite::P256Sha512,
        botan::Spake2pCiphersuite::P384Sha256,
        botan::Spake2pCiphersuite::P384Sha512,
        botan::Spake2pCiphersuite::P521Sha512,
    ] {
        if let Err(e) = botan::Spake2pParams::new(suite) {
            assert_ne!(e.error_type(), botan::ErrorType::BadParameter);
        }
    }

    let mut rng = botan::RandomNumberGenerator::new()?;

    let prover_id = b"client";
    let verifier_id = b"server";
    let context = b"botan-rs test";
    let salt = rng.read(16)?;

    let share_size = params.share_size()?;
    let confirmation_size = params.confirmation_size()?;
    assert_eq!(share_size, 65);
    assert_eq!(confirmation_size, 32);

    let secret = params.derive_secret(
        "correct horse battery staple",
        prover_id,
        verifier_id,
        &salt,
    )?;
    assert_eq!(secret.len(), 64);

    let record = params.registration_record(&mut rng, &secret)?;
    assert_eq!(record.len(), 97);

    // A successful exchange
    let mut prover = botan::Spake2pProver::new(&params, &secret, prover_id, verifier_id, context)?;
    let mut verifier =
        botan::Spake2pVerifier::new(&params, &record, prover_id, verifier_id, context)?;

    let share_p = prover.generate_message(&mut rng)?;
    assert_eq!(share_p.len(), share_size);

    let response = verifier.process_message(&mut rng, &share_p)?;
    assert_eq!(response.len(), share_size + confirmation_size);

    let confirm_p = prover.process_message(&mut rng, &response)?;
    assert_eq!(confirm_p.len(), confirmation_size);

    verifier.verify_confirmation(&confirm_p)?;

    let key = prover.shared_secret()?;
    assert!(!key.is_empty());
    assert_eq!(key, verifier.shared_secret()?);

    // An exchange where the prover has the wrong password
    let wrong_secret =
        params.derive_secret("incorrect zebra paperclip", prover_id, verifier_id, &salt)?;
    let mut prover =
        botan::Spake2pProver::new(&params, &wrong_secret, prover_id, verifier_id, context)?;
    let mut verifier =
        botan::Spake2pVerifier::new(&params, &record, prover_id, verifier_id, context)?;

    let share_p = prover.generate_message(&mut rng)?;
    let response = verifier.process_message(&mut rng, &share_p)?;
    let confirm_p = prover.process_message(&mut rng, &response);
    assert!(confirm_p.is_err());
    assert_eq!(
        confirm_p.unwrap_err().error_type(),
        botan::ErrorType::BadAuthCode
    );

    // An exchange where the verifier skips checking the prover's confirmation
    let mut prover = botan::Spake2pProver::new(&params, &secret, prover_id, verifier_id, context)?;
    let mut verifier =
        botan::Spake2pVerifier::new(&params, &record, prover_id, verifier_id, context)?;

    let share_p = prover.generate_message(&mut rng)?;
    let response = verifier.process_message(&mut rng, &share_p)?;
    let _confirm_p = prover.process_message(&mut rng, &response)?;
    verifier.skip_confirmation()?;
    assert_eq!(prover.shared_secret()?, verifier.shared_secret()?);

    // Custom system parameters
    if botan::EcGroup::supports_named_group("secp256r1")? {
        let group = botan::EcGroup::from_name("secp256r1")?;
        match botan::Spake2pParams::new_custom(&group, b"botan-rs test seed", "SHA-256") {
            Ok(custom) => {
                assert_eq!(custom.share_size()?, 65);
            }
            Err(e) => {
                // The group may not support hash to curve in this build
                assert_eq!(e.error_type(), botan::ErrorType::NotImplemented);
            }
        }
    }

    Ok(())
}
