use crate::utils::*;
use botan_sys::*;

use crate::mp::MPI;

/// Represents an instance of format preserving encryption
///
/// # Examples
///
/// ```
/// use std::str::FromStr;
/// let modulus = botan::MPI::from_str("1000000000").unwrap();
/// let key = vec![0; 32];
/// let rounds = 16;
/// let compat_mode = false;
/// let fpe = botan::FPE::new_fe1(&modulus, &key, rounds, compat_mode).unwrap();
/// let input = botan::MPI::from_str("9392024").unwrap();
/// let tweak = vec![1,2,3,4,5];
/// let ctext = fpe.encrypt(&input, &tweak).unwrap();
/// assert!(ctext < modulus);
/// let ptext = fpe.decrypt(&ctext, &tweak).unwrap();
/// assert_eq!(ptext, input);
/// ```
#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
pub struct FPE {
    obj: botan_fpe_t,
}

botan_impl_drop!(FPE, botan_fpe_destroy);

impl FPE {
    /// Create a new FPE instance, FE1 scheme
    /// Rounds should be 16 or higher for best security
    pub fn new_fe1(modulus: &MPI, key: &[u8], rounds: usize, compat_mode: bool) -> Result<FPE> {
        let flags = u32::from(compat_mode);

        let obj = botan_init!(
            botan_fpe_fe1_init,
            modulus.handle(),
            key.as_ptr(),
            key.len(),
            rounds,
            flags
        )?;

        Ok(FPE { obj })
    }

    /// Encrypt value under the FPE scheme using provided tweak
    pub fn encrypt(&self, x: &MPI, tweak: &[u8]) -> Result<MPI> {
        let r = x.duplicate()?;
        botan_call!(
            botan_fpe_encrypt,
            self.obj,
            r.handle(),
            tweak.as_ptr(),
            tweak.len()
        )?;
        Ok(r)
    }

    /// Decrypt value under the FPE scheme using provided tweak
    pub fn decrypt(&self, x: &MPI, tweak: &[u8]) -> Result<MPI> {
        let r = x.duplicate()?;
        botan_call!(
            botan_fpe_decrypt,
            self.obj,
            r.handle(),
            tweak.as_ptr(),
            tweak.len()
        )?;
        Ok(r)
    }
}
