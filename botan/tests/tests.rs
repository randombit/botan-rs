extern crate botan;

use std::str::FromStr;

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
    let mut hash = botan::HashFunction::new("SHA-384")?;

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

    assert_eq!(botan::hex_encode(&digest)?,
               "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7");

    let digest_dup = hash_dup.finish()?;

    assert_eq!(botan::hex_encode(&digest_dup)?,
               "5D15BCEBB965FA77926C23471C96E3A326B363F5F105C3EF17CFD033B9734FA46556F81A26BB3044D2DDA50481325EF7");

    let bad_hash = botan::HashFunction::new("BunnyHash9000");

    assert!(bad_hash.is_err());
    assert_eq!(
        bad_hash.as_ref().unwrap_err().error_type(),
        botan::ErrorType::NotImplemented
    );
    Ok(())
}

#[test]
fn test_mac() -> Result<(), botan::Error> {
    let mut mac = botan::MsgAuthCode::new("HMAC(SHA-384)")?;

    let key_spec = mac.key_spec()?;
    assert_eq!(mac.output_length()?, 48);
    assert_eq!(mac.algo_name()?, "HMAC(SHA-384)");

    assert!(key_spec.is_valid_keylength(20));

    mac.set_key(&[0xAA; 20])?;

    mac.update(&[0xDD; 1])?;
    mac.update(&[0xDD; 29])?;
    mac.update(&[0xDD; 20])?;

    let r = mac.finish()?;

    assert_eq!(botan::hex_encode(&r)?,
               "88062608D3E6AD8A0AA2ACE014C8A86F0AA635D947AC9FEBE83EF4E55966144B2A5AB39DC13814B94E3AB6E101A34F27");
    Ok(())
}

#[test]
fn test_block_cipher() -> Result<(), botan::Error> {
    let mut bc = botan::BlockCipher::new("AES-128")?;

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
    let mut cipher = botan::Cipher::new("AES-128/GCM", botan::CipherDirection::Encrypt)?;

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
    let input = botan::hex_decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")?;
    let output = botan::hex_decode("38C21B6430D9A3E4BC6749405765653AE91051E96CE0D076141DD7B515EC150FDB8A65EE988D206C9F64874664CDBF61257FFAE521B9A5EB5B35E3745F4232025B269A6CD7DCFE19153ECF7341CE2C6A6A87F95F2109841350DA3D24EEED4E4E32D2BED880737670FFE8ED76DB890FD72A0076300E50914984A777C9F2BC843977396C602B24E7A045F04D15CD2EAC01AD8808064CFE5A2DC1AE9FFFA4BF0A6F0C07668097DEEB9C5CA5EC1F9A52F96A403B73FEA2DBBF44473D355553EE7FB1B4D6630777DAF67804BE213089B9F78652CE970C582FD813F87FF0ECBACCE1CA46247E20D09F3E0B4EF6BFCD13244C6877F25E6646252CAD6EB7DBBA3476AAAC83BC3285FF70B50D6CDEDC8E5921944A")?;

    // encode
    let mut cipher = botan::Cipher::new("AES-128/GCM", botan::CipherDirection::Encrypt)?;
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

    assert_eq!(botan::hex_encode(&enc_out)?,
               "38C21B6430D9A3E4BC6749405765653AE91051E96CE0D076141DD7B515EC150FDB8A65EE988D206C9F64874664CDBF61257FFAE521B9A5EB5B35E3745F4232025B269A6CD7DCFE19153ECF7341CE2C6A6A87F95F2109841350DA3D24EEED4E4E32D2BED880737670FFE8ED76DB890FD72A0076300E50914984A777C9F2BC843977396C602B24E7A045F04D15CD2EAC01AD8808064CFE5A2DC1AE9FFFA4BF0A6F0C07668097DEEB9C5CA5EC1F9A52F96A403B73FEA2DBBF44473D355553EE7FB1B4D6630777DAF67804BE213089B9F78652CE970C582FD813F87FF0ECBACCE1CA46247E20D09F3E0B4EF6BFCD13244C6877F25E6646252CAD6EB7DBBA3476AAAC83BC3285FF70B50D6CDEDC8E5921944A");

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
    assert_eq!(botan::hex_encode(&dec_out)?,
               "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

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
fn test_chacha() -> Result<(), botan::Error> {
    let mut cipher = botan::Cipher::new("ChaCha20", botan::CipherDirection::Encrypt)?;

    assert_eq!(cipher.tag_length(), 0);

    let key_spec = cipher.key_spec()?;

    assert!(!key_spec.is_valid_keylength(0));
    assert!(key_spec.is_valid_keylength(16));
    assert!(key_spec.is_valid_keylength(32));
    assert!(!key_spec.is_valid_keylength(48));

    let key = vec![0; 32];

    let expected = botan::hex_decode("76B8E0ADA0F13D90405D6AE55386BD28BDD219B8A08DED1AA836EFCC8B770DC7DA41597C5157488D7724E03FB8D84A376A43B8F41518A11CC387B669")?;

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

    let output = botan::kdf(
        "HKDF(SHA-256)",
        expected_output.len(),
        &secret,
        &salt,
        &label,
    )?;

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

    let output = botan::pbkdf(
        "PBKDF2(SHA-256)",
        expected_output.len(),
        passphrase,
        &salt,
        iterations,
    )?;

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

    let output = botan::scrypt(expected_output.len(), passphrase, &salt, n, r, p)?;

    assert_eq!(output, expected_output);
    Ok(())
}

#[test]
fn test_pwdhash() -> Result<(), botan::Error> {
    let mut rng = botan::RandomNumberGenerator::new()?;
    let salt = rng.read(10)?;
    let msec = 30;
    let (key, r, p, n) =
        botan::derive_key_from_password_timed("Scrypt", 32, "passphrase", &salt, msec)?;
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
        use rand::TryRngCore;

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

    let crl = botan::CRL::load(crl_pem.as_bytes())?;

    let cert = botan::Certificate::load(cert_pem.as_bytes())?;

    assert!(crl.is_revoked(&cert)?);

    Ok(())
}

#[test]
fn test_certs() -> Result<(), botan::Error> {
    let cert_bits = botan::hex_decode("3082035A30820305A003020102020101300C06082A8648CE3D04030105003050310B3009060355040613024445310D300B060355040A0C0462756E64310C300A060355040B0C03627369310D300B06035504051304343536373115301306035504030C0C637363612D6765726D616E79301E170D3037303731393135323731385A170D3238303131393135313830305A3050310B3009060355040613024445310D300B060355040A0C0462756E64310C300A060355040B0C03627369310D300B06035504051304343536373115301306035504030C0C637363612D6765726D616E79308201133081D406072A8648CE3D02013081C8020101302806072A8648CE3D0101021D00D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF303C041C68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43041C2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B0439040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD021D00D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F020101033A000401364A4B0F0102E9502AB9DC6855D90B065A6F5E5E48395F8309D57C11ABAFF21756607EF6757EC9886CA222D83CA04B1A99FA43C5A9BCE1A38201103082010C30360603551D11042F302D8118637363612D6765726D616E79406273692E62756E642E646586116661783A2B343932323839353832373232300E0603551D0F0101FF040403020106301D0603551D0E041604140096452DE588F966C4CCDF161DD1F3F5341B71E7301F0603551D230418301680140096452DE588F966C4CCDF161DD1F3F5341B71E730410603551D20043A30383036060904007F0007030101013029302706082B06010505070201161B687474703A2F2F7777772E6273692E62756E642E64652F6373636130120603551D130101FF040830060101FF020100302B0603551D1004243022800F32303037303731393135323731385A810F32303237313131393135313830305A300C06082A8648CE3D0403010500034100303E021D00C6B41E830217FD4C93B59E9E2B13734E09C182FA63FAEE4115A8EDD5021D00D27938DA01B8951A9064A1B696AEDF181B74968829C138F0EB2F623B")?;

    let cert = botan::Certificate::load(&cert_bits)?;

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

    // Bit flipped from ee
    let bad_ee = b"-----BEGIN CERTIFICATE-----
MIIBoDCCAUagAwIBAgIRAK27a2NlSYEH63xIsAbBA1wwCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEAxMHVGVzdCBDQTAeFw0xODA4MTYyMjMzNDBaFw00NjAxMDEyMjMzNDBa
MBoxGDAWBgNVBAMTD1Rlc3QgrW5kIEVudGl0eTBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABDykQMvlV7GyIJeANLWEs5bXReqpvTEFu3zYPBjOhyx784VPVl84h8c5
ycru3Hk8N/SIITSWzpbjPMp9jRbyDy+jdTBzMCEGA1UdDgQaBBjkPzL+BXHtQJDR
ciwvzeHQKuQZOstyM2swGwYDVR0RBBQwEoIQdGVzdC5leGFtcGxlLmNvbTAMBgNV
HRMBAf8EAjAAMCMGA1UdIwQcMBqAGC4P5X53lid+q2XRjKFcig+mZZh5Ek+2TTAK
BggqhkjOPQQDAgNIADBFAiEAowK8jGhosOxQpOCjlRg0nFceQ0ETITQC43fk0CZA
AzMCIEJSRDmXjX8TMTbSfoTLmhaYJnCL+AfHLZLdHlSLDIzh
-----END CERTIFICATE-----";

    let ca = botan::Certificate::load(ca)?;

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

#[test]
fn test_bcrypt() -> Result<(), botan::Error> {
    let pass = "password";
    let mut rng = botan::RandomNumberGenerator::new_system()?;

    let bcrypt1 = botan::bcrypt_hash(pass, &mut rng, 10)?;

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

    let ecdsa_key = botan::Privkey::create("ECDSA", "secp256r1", &mut rng)?;

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

    let a_pub = botan::Pubkey::load_x25519(&a_pub_bits)?;
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

    let ed_priv = botan::Privkey::create("Ed25519", "", &mut rng)?;

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

    let privkey = botan::Privkey::create("RSA", "1024", &mut rng)?;
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
    let key = botan::Privkey::create("RSA", "1024", &mut rng)?;

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

    let ecdsa_key = botan::Privkey::create("ECDSA", "secp256r1", &mut rng)?;
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

    let ecdsa_key = botan::Privkey::create("ECDSA", "secp256r1", &mut rng)?;
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

    let priv_key = botan::Privkey::create("RSA", "2048", &mut rng)?;
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

    let a_priv = botan::Privkey::create("ECDH", "secp384r1", &mut rng)?;
    let b_priv = botan::Privkey::create("ECDH", "secp384r1", &mut rng)?;

    let a_pub = a_priv.key_agreement_key()?;
    let b_pub = b_priv.key_agreement_key()?;

    let mut a_ka = botan::KeyAgreement::new(&a_priv, "KDF2(SHA-384)")?;
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

    let wrapped = botan::rfc3394_key_wrap(&kek, &key)?;

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

    let wrapped = match botan::nist_kw_enc("AES-256", false, &kek, &key) {
        Ok(s) => s,
        Err(e) => {
            assert_eq!(e.error_type(), botan::ErrorType::NotImplemented);
            return Ok(());
        }
    };

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

    let id = botan::pkcs_hash_id("SHA-384")?;

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

    let fpe = botan::FPE::new_fe1(&modulus, &key, 8, false)?;

    let ctext = fpe.encrypt(&input, &tweak)?;

    assert_ne!(ctext, input);

    let ptext = fpe.decrypt(&ctext, &tweak)?;

    assert_eq!(ptext, input);
    Ok(())
}

#[test]
fn test_hotp() -> Result<(), botan::Error> {
    let hotp = botan::HOTP::new(&[0xFF], "SHA-1", 6)?;
    assert_eq!(hotp.generate(23)?, 330795);

    assert!(hotp.check(330795, 23)?);
    assert!(!hotp.check(330795, 22)?);
    assert!(!hotp.check(330796, 23)?);
    Ok(())
}

#[test]
fn test_totp() -> Result<(), botan::Error> {
    let totp = botan::TOTP::new(
        b"1234567890123456789012345678901234567890123456789012345678901234",
        "SHA-512",
        8,
        30,
    )?;

    assert_eq!(totp.generate(59)?, 90693936);
    assert_eq!(totp.generate(1111111109)?, 25091201);
    assert_eq!(totp.generate(1111111111)?, 99943326);

    assert!(totp.check(90693936, 59, 0)?);
    assert!(!totp.check(90693936, 60, 0)?);
    assert!(totp.check(90693936, 59 + 30, 1)?);
    assert!(!totp.check(90693936, 59 + 31, 1)?);
    Ok(())
}

#[test]
fn test_elgamal() -> Result<(), botan::Error> {
    let mut rng = botan::RandomNumberGenerator::new()?;

    let p_bits = 1024;
    let q_bits = 256;

    let elg = botan::Privkey::create_elgamal(p_bits, q_bits, &mut rng)?;

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

    let dsa = botan::Privkey::create_dsa(p_bits, q_bits, &mut rng)?;

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

    let output_shares = match botan::zfec_encode(k, n, input_bytes) {
        Ok(s) => s,
        Err(e) => {
            assert_eq!(e.error_type(), botan::ErrorType::NotImplemented);
            return Ok(());
        }
    };

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
    let kyber_priv = botan::Privkey::create("Kyber", "Kyber-1024-r3", &mut rng)?;
    let kyber_pub = kyber_priv.pubkey()?;

    let salt = rng.read(12)?;
    let shared_key_len = 32;
    let kdf = "KDF2(SHA-256)";

    let kem_e = botan::KeyEncapsulation::new(&kyber_pub, kdf)?;
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
        let sk = botan::Privkey::create("ML-KEM", &params, &mut rng)?;
        let pk = sk.pubkey()?;

        let pk_bytes = pk.raw_bytes()?;
        let pk2 = botan::Pubkey::load_ml_kem(&pk_bytes)?;

        let salt = rng.read(12)?;
        let shared_key_len = 32;
        let kdf = "KDF2(SHA-256)";

        let kem_e = botan::KeyEncapsulation::new(&pk2, kdf)?;
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

    assert_eq!(
        botan::EcGroup::supports_named_group("nosuchgroup256r1")?,
        false
    );

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
    }

    Ok(())
}
