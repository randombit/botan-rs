
use botan_sys::*;
use crate::utils::*;

use crate::rng::RandomNumberGenerator;

const BCRYPT_SIZE : usize = 60;

/// Produce a bcrypt password hash
///
/// # Examples
///
/// ```
/// let rng = botan::RandomNumberGenerator::new().unwrap();
/// let bcrypt1 = botan::bcrypt_hash("password", &rng, 10).unwrap();
/// let bcrypt2 = botan::bcrypt_hash("password", &rng, 10).unwrap();
/// assert_ne!(bcrypt1, bcrypt2); // different salt each time
/// ```
pub fn bcrypt_hash(pass: &str, rng : &RandomNumberGenerator, workfactor: usize) -> Result<String> {

    let mut out = vec![0; BCRYPT_SIZE + 1];
    let mut out_len = out.len();

    call_botan! {
        botan_bcrypt_generate(out.as_mut_ptr(), &mut out_len,
                              make_cstr(pass)?.as_ptr(),
                              rng.handle(),
                              workfactor, 0u32)
    };

    out.resize(out_len - 1, 0);
    Ok(String::from_utf8(out).map_err(|_| Error::ConversionError)?)
}

/// Verify a bcrypt password hash
///
/// # Examples
///
/// ```
/// let rng = botan::RandomNumberGenerator::new().unwrap();
/// let bcrypt = botan::bcrypt_hash("password", &rng, 10).unwrap();
/// assert_eq!(botan::bcrypt_verify("not even close", &bcrypt), Ok(false));
/// assert_eq!(botan::bcrypt_verify("password", &bcrypt), Ok(true));
/// ```
pub fn bcrypt_verify(pass: &str, hash: &str) -> Result<bool> {

    let rc = unsafe {
        botan_bcrypt_is_valid(make_cstr(pass)?.as_ptr(),
                              make_cstr(hash)?.as_ptr())
    };

    if rc == 0 {
        Ok(true)
    }
    else if rc == BOTAN_FFI_INVALID_VERIFIER {
        Ok(false)
    }
    else {
        Err(Error::from(rc))
    }
}
