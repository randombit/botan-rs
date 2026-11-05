use crate::utils::*;
use botan_sys::*;

use crate::pubkey::{OpLock, Privkey, Pubkey};
use crate::rng::RandomNumberGenerator;

// Each operation object holds the lock of the key it was created from, and
// acquires it around every FFI call; see the comment on `OpLock` in pubkey.rs

#[derive(Debug)]
/// An object that can perform key encapsulation
pub struct KeyEncapsulation {
    obj: botan_pk_op_kem_encrypt_t,
    encap_length: usize,
    op_lock: OpLock,
}

unsafe impl Sync for KeyEncapsulation {}
unsafe impl Send for KeyEncapsulation {}

botan_impl_drop!(KeyEncapsulation, botan_pk_op_kem_encrypt_destroy);

impl KeyEncapsulation {
    /// Create a KeyEncapsulation operation
    pub fn new<K: crate::KdfAlgorithmIdentifier>(key: &Pubkey, kdf: K) -> Result<Self> {
        let kdf = kdf.botan_name();
        let kdf = make_cstr(&kdf)?;
        let op_lock = key.op_lock();
        let (obj, encap_length) = {
            let _lock = op_lock.guard()?;
            let obj = botan_init!(botan_pk_op_kem_encrypt_create, key.handle(), kdf.as_ptr())?;
            let encap_length = botan_usize!(botan_pk_op_kem_encrypt_encapsulated_key_length, obj)?;
            (obj, encap_length)
        };
        Ok(Self {
            obj,
            encap_length,
            op_lock,
        })
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

        let _lock = self.op_lock.guard()?;
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
    op_lock: OpLock,
}

unsafe impl Sync for KeyDecapsulation {}
unsafe impl Send for KeyDecapsulation {}

botan_impl_drop!(KeyDecapsulation, botan_pk_op_kem_decrypt_destroy);

impl KeyDecapsulation {
    /// Create a KeyDecapsulation operation
    pub fn new<K: crate::KdfAlgorithmIdentifier>(key: &Privkey, kdf: K) -> Result<Self> {
        let kdf = kdf.botan_name();
        let kdf = make_cstr(&kdf)?;
        let op_lock = key.op_lock();
        let obj = {
            let _lock = op_lock.guard()?;
            botan_init!(botan_pk_op_kem_decrypt_create, key.handle(), kdf.as_ptr())?
        };
        Ok(Self { obj, op_lock })
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

        let _lock = self.op_lock.guard()?;
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
