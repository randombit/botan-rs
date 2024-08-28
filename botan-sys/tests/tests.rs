extern crate botan_sys;

use std::ffi::CString;

use botan_sys::*;

#[test]
fn test_hex() {
    let bin = vec![0x42, 0x23, 0x45, 0x8F];
    let mut out = Vec::new();
    out.resize(bin.len() * 2, 0);

    unsafe {
        assert_eq!(
            botan_hex_encode(bin.as_ptr(), bin.len(), out.as_mut_ptr(), 0),
            0
        );
    }

    assert_eq!(out[0], '4' as _);
    assert_eq!(out[1], '2' as _);
    assert_eq!(out[2], '2' as _);
    assert_eq!(out[3], '3' as _);
    assert_eq!(out[4], '4' as _);
    assert_eq!(out[5], '5' as _);
    assert_eq!(out[6], '8' as _);
    assert_eq!(out[7], 'F' as _);

    let mut decoded = vec![0; 1024];
    let mut out_len = decoded.len();

    unsafe {
        assert_eq!(
            botan_hex_decode(out.as_ptr(), out.len(), decoded.as_mut_ptr(), &mut out_len),
            0
        );
    }

    assert_eq!(out_len, bin.len());
    decoded.resize(out_len, 0);
    assert_eq!(bin, decoded);
}

#[test]
fn test_hash() {
    unsafe {
        let mut hash = std::ptr::null_mut();
        let hash_name = CString::new("SHA-384").unwrap();
        assert_eq!(botan_hash_init(&mut hash, hash_name.as_ptr(), 0u32), 0);

        let input = [97, 98, 99];
        assert_eq!(botan_hash_update(hash, input.as_ptr(), input.len()), 0);
        assert_eq!(botan_hash_update(hash, input.as_ptr(), input.len()), 0);

        let mut output_len = 0;
        assert_eq!(botan_hash_output_length(hash, &mut output_len), 0);
        assert!(output_len == 48);

        let mut digest = vec![0u8; output_len];
        assert_eq!(botan_hash_final(hash, digest.as_mut_ptr()), 0);

        assert_eq!(digest[0], 0xCA);
        assert_eq!(digest[1], 0xF3);
        assert_eq!(digest[47], 0x8D);

        assert_eq!(botan_hash_destroy(hash), 0);
    }
}

#[test]
fn test_version() {
    unsafe {
        let api_version = botan_ffi_api_version();

        assert!(botan_ffi_supports_api(api_version) == 0);
        assert!(botan_ffi_supports_api(api_version + 1) != 0);

        #[cfg(feature = "botan3")]
        {
            assert_eq!(botan_version_major(), 3);
        }

        #[cfg(not(feature = "botan3"))]
        {
            if botan_version_major() == 2 {
                assert!(botan_version_minor() > 8);
            } else {
                assert_eq!(botan_version_major(), 3);
            }
        }
    }
}

#[test]
fn test_rng() {
    unsafe {
        let mut rng = std::ptr::null_mut();
        botan_rng_init(&mut rng, std::ptr::null());

        let mut rng1 = vec![0u8; 16];
        let mut rng2 = vec![0u8; 16];
        assert_eq!(botan_rng_get(rng, rng1.as_mut_ptr(), rng1.len()), 0);
        assert_eq!(botan_rng_get(rng, rng2.as_mut_ptr(), rng2.len()), 0);

        assert!(rng1 != rng2);

        assert_eq!(botan_rng_destroy(rng), 0);
    }
}
