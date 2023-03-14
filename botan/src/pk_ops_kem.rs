use crate::utils::*;
use botan_sys::*;

use crate::pubkey::{Privkey, Pubkey};
use crate::rng::RandomNumberGenerator;

#[derive(Debug)]
/// An object that can perform key encapsulation
pub struct KeyEncapsulation {
    obj: botan_pk_op_kem_encrypt_t,
    encap_length: usize,
}

unsafe impl Sync for KeyEncapsulation {}
unsafe impl Send for KeyEncapsulation {}

botan_impl_drop!(KeyEncapsulation, botan_pk_op_kem_encrypt_destroy);

impl KeyEncapsulation {
    /// Create a KeyEncapsulation operation
    pub fn new(key: &Pubkey, kdf: &str) -> Result<Self> {
        let kdf = make_cstr(kdf)?;
        let obj = botan_init!(botan_pk_op_kem_encrypt_create, key.handle(), kdf.as_ptr())?;

        let encap_length = botan_usize!(botan_pk_op_kem_encrypt_encapsulated_key_length, obj)?;
        Ok(Self { obj, encap_length })
    }

    /// Return the shared key length
    pub fn shared_key_length(&self, desired_shared_key_length: usize) -> Result<usize> {
        let mut val = 0;
        let rc = unsafe {
            botan_pk_op_kem_encrypt_shared_key_length(self.obj, desired_shared_key_length, &mut val)
        };
        if rc != 0 {
            Err(Error::from_rc(rc))
        } else {
            Ok(val)
        }
    }

    /// Create a new encapsulated key
    pub fn create_shared_key(
        &self,
        rng: &mut RandomNumberGenerator,
        salt: &[u8],
        desired_key_len: usize,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut shared_key_len = self.shared_key_length(desired_key_len)?;
        let mut shared_key = vec![0; shared_key_len];
        let mut encap_key_len = self.encap_length;
        let mut encap_key = vec![0; encap_key_len];

        let rc = unsafe {
            botan_pk_op_kem_encrypt_create_shared_key(
                self.obj,
                rng.handle(),
                salt.as_ptr(),
                salt.len(),
                desired_key_len,
                shared_key.as_mut_ptr(),
                &mut shared_key_len,
                encap_key.as_mut_ptr(),
                &mut encap_key_len,
            )
        };

        if rc != 0 {
            return Err(Error::from_rc(rc));
        }

        Ok((shared_key, encap_key))
    }
}

#[derive(Debug)]
/// An object that can perform key decapsulation
pub struct KeyDecapsulation {
    obj: botan_pk_op_kem_decrypt_t,
}

unsafe impl Sync for KeyDecapsulation {}
unsafe impl Send for KeyDecapsulation {}

botan_impl_drop!(KeyDecapsulation, botan_pk_op_kem_decrypt_destroy);

impl KeyDecapsulation {
    /// Create a KeyDecapsulation operation
    pub fn new(key: &Privkey, kdf: &str) -> Result<Self> {
        let kdf = make_cstr(kdf)?;
        let obj = botan_init!(botan_pk_op_kem_decrypt_create, key.handle(), kdf.as_ptr())?;

        Ok(Self { obj })
    }

    /// Return the shared key length
    pub fn shared_key_length(&self, desired_shared_key_length: usize) -> Result<usize> {
        let mut val = 0;
        let rc = unsafe {
            botan_pk_op_kem_decrypt_shared_key_length(self.obj, desired_shared_key_length, &mut val)
        };
        if rc != 0 {
            Err(Error::from_rc(rc))
        } else {
            Ok(val)
        }
    }

    /// Decrypt an encapsulated key
    pub fn decrypt_shared_key(
        &self,
        encapsulated_key: &[u8],
        salt: &[u8],
        desired_key_len: usize,
    ) -> Result<Vec<u8>> {
        let mut shared_key_len = self.shared_key_length(desired_key_len)?;
        let mut shared_key = vec![0; shared_key_len];

        let rc = unsafe {
            botan_pk_op_kem_decrypt_shared_key(
                self.obj,
                salt.as_ptr(),
                salt.len(),
                encapsulated_key.as_ptr(),
                encapsulated_key.len(),
                desired_key_len,
                shared_key.as_mut_ptr(),
                &mut shared_key_len,
            )
        };

        if rc != 0 {
            return Err(Error::from_rc(rc));
        }

        Ok(shared_key)
    }
}
