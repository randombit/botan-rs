use crate::utils::*;
use botan_sys::*;

use crate::pubkey::{OpLock, Privkey, Pubkey};
use crate::rng::RandomNumberGenerator;

// Each operation object holds the lock of the key it was created from, and
// acquires it around every FFI call; see the comment on `OpLock` in pubkey.rs

#[derive(Debug)]
/// An object that can generate signatures
///
/// # Examples
///
/// ```
/// let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
/// let rsa = botan::Privkey::create("RSA", "2048", &mut rng).unwrap();
/// let mut signer = botan::Signer::new(&rsa, "PKCS1v15(SHA-256)").unwrap();
/// signer.update(&[1,2,3]).unwrap();
/// let signature = signer.finish(&mut rng).unwrap();
/// ```
pub struct Signer {
    obj: botan_pk_op_sign_t,
    sig_len: usize,
    op_lock: OpLock,
}

unsafe impl Sync for Signer {}
unsafe impl Send for Signer {}

botan_impl_drop!(Signer, botan_pk_op_sign_destroy);

impl Signer {
    /// Create a new signature operator
    pub fn new<P: crate::SignatureParamsIdentifier>(key: &Privkey, padding: P) -> Result<Signer> {
        Self::create(key, padding, 0)
    }

    /// Create a new signature operator that outputs DER-formatted signatures
    pub fn new_with_der_formatted_signatures<P: crate::SignatureParamsIdentifier>(
        key: &Privkey,
        padding: P,
    ) -> Result<Signer> {
        Self::create(key, padding, 1)
    }

    fn create<P: crate::SignatureParamsIdentifier>(
        key: &Privkey,
        padding: P,
        flags: u32,
    ) -> Result<Signer> {
        let padding = padding.botan_name();
        let padding = make_cstr(&padding)?;
        let op_lock = key.op_lock();
        let (obj, sig_len) = {
            let _lock = op_lock.guard()?;
            let obj = botan_init!(
                botan_pk_op_sign_create,
                key.handle(),
                padding.as_ptr(),
                flags
            )?;
            let sig_len = botan_usize!(botan_pk_op_sign_output_length, obj)?;
            (obj, sig_len)
        };
        Ok(Signer {
            obj,
            sig_len,
            op_lock,
        })
    }

    /// Return an upper bound on the length of the output signature
    pub fn signature_length(&self) -> usize {
        self.sig_len
    }

    /// Add more bytes of the message that will be signed
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        let _lock = self.op_lock.guard()?;
        botan_call!(botan_pk_op_sign_update, self.obj, data.as_ptr(), data.len())
    }

    /// Complete and return the signature
    pub fn finish(&mut self, rng: &mut RandomNumberGenerator) -> Result<Vec<u8>> {
        let _lock = self.op_lock.guard()?;
        let rng_handle = rng.handle();
        call_botan_ffi_returning_vec_u8(self.sig_len, &|out_buf, out_len| unsafe {
            botan_pk_op_sign_finish(self.obj, rng_handle, out_buf, out_len)
        })
    }
}

#[derive(Debug)]
/// An object that can perform public key decryption
pub struct Decryptor {
    obj: botan_pk_op_decrypt_t,
    op_lock: OpLock,
}

unsafe impl Sync for Decryptor {}
unsafe impl Send for Decryptor {}

botan_impl_drop!(Decryptor, botan_pk_op_decrypt_destroy);

impl Decryptor {
    /// Create a new decryption object
    pub fn new<P: crate::EncryptionParamsIdentifier>(
        key: &Privkey,
        padding: P,
    ) -> Result<Decryptor> {
        let padding = padding.botan_name();
        let padding = make_cstr(&padding)?;
        let op_lock = key.op_lock();
        let obj = {
            let _lock = op_lock.guard()?;
            botan_init!(
                botan_pk_op_decrypt_create,
                key.handle(),
                padding.as_ptr(),
                0u32
            )?
        };
        Ok(Decryptor { obj, op_lock })
    }

    /// Decrypt a message
    pub fn decrypt(&mut self, ctext: &[u8]) -> Result<Vec<u8>> {
        let _lock = self.op_lock.guard()?;
        let mut ptext_len = 0;

        botan_call!(
            botan_pk_op_decrypt_output_length,
            self.obj,
            ctext.len(),
            &mut ptext_len
        )?;

        call_botan_ffi_returning_vec_u8(ptext_len, &|out_buf, out_len| unsafe {
            botan_pk_op_decrypt(self.obj, out_buf, out_len, ctext.as_ptr(), ctext.len())
        })
    }
}

#[derive(Debug)]
/// An object that can perform public key signature verification
pub struct Verifier {
    obj: botan_pk_op_verify_t,
    op_lock: OpLock,
}

unsafe impl Sync for Verifier {}
unsafe impl Send for Verifier {}

botan_impl_drop!(Verifier, botan_pk_op_verify_destroy);

impl Verifier {
    /// Create a new verifier object
    pub fn new<P: crate::SignatureParamsIdentifier>(key: &Pubkey, padding: P) -> Result<Verifier> {
        Self::create(key, padding, 0)
    }

    /// Create a new verifier object
    pub fn new_with_der_formatted_signatures<P: crate::SignatureParamsIdentifier>(
        key: &Pubkey,
        padding: P,
    ) -> Result<Verifier> {
        Self::create(key, padding, 1)
    }

    fn create<P: crate::SignatureParamsIdentifier>(
        key: &Pubkey,
        padding: P,
        flags: u32,
    ) -> Result<Verifier> {
        let padding = padding.botan_name();
        let padding = make_cstr(&padding)?;
        let op_lock = key.op_lock();
        let obj = {
            let _lock = op_lock.guard()?;
            botan_init!(
                botan_pk_op_verify_create,
                key.handle(),
                padding.as_ptr(),
                flags
            )?
        };
        Ok(Verifier { obj, op_lock })
    }

    /// Add more bytes of the message that will be verified
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        let _lock = self.op_lock.guard()?;
        botan_call!(
            botan_pk_op_verify_update,
            self.obj,
            data.as_ptr(),
            data.len()
        )
    }

    /// Verify the provided signature and return true if valid
    pub fn finish(&mut self, signature: &[u8]) -> Result<bool> {
        let _lock = self.op_lock.guard()?;
        match unsafe { botan_pk_op_verify_finish(self.obj, signature.as_ptr(), signature.len()) } {
            0 => Ok(true),
            BOTAN_FFI_INVALID_VERIFIER => Ok(false),
            e => Err(Error::from_rc(e)),
        }
    }
}

#[derive(Debug)]
/// An object that performs public key encryption
///
/// # Examples
///
/// ```
/// let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
/// let rsa = botan::Privkey::create("RSA", "2048", &mut rng).unwrap();
/// let rsa_pub = rsa.pubkey().unwrap();
/// let mut enc = botan::Encryptor::new(&rsa_pub, "OAEP(SHA-256)").unwrap();
/// let ctext = enc.encrypt(&[1,2,3], &mut rng).unwrap();
/// ```
pub struct Encryptor {
    obj: botan_pk_op_encrypt_t,
    op_lock: OpLock,
}

unsafe impl Sync for Encryptor {}
unsafe impl Send for Encryptor {}

botan_impl_drop!(Encryptor, botan_pk_op_encrypt_destroy);

impl Encryptor {
    /// Create a new public key encryptor object
    pub fn new<P: crate::EncryptionParamsIdentifier>(
        key: &Pubkey,
        padding: P,
    ) -> Result<Encryptor> {
        let padding = padding.botan_name();
        let padding = make_cstr(&padding)?;
        let op_lock = key.op_lock();
        let obj = {
            let _lock = op_lock.guard()?;
            botan_init!(
                botan_pk_op_encrypt_create,
                key.handle(),
                padding.as_ptr(),
                0u32
            )?
        };
        Ok(Encryptor { obj, op_lock })
    }

    /// Encrypt a message using the provided public key
    pub fn encrypt(&mut self, ptext: &[u8], rng: &mut RandomNumberGenerator) -> Result<Vec<u8>> {
        let _lock = self.op_lock.guard()?;
        let mut ctext_len = 0;
        botan_call!(
            botan_pk_op_encrypt_output_length,
            self.obj,
            ptext.len(),
            &mut ctext_len
        )?;

        let rng_handle = rng.handle();

        call_botan_ffi_returning_vec_u8(ctext_len, &|out_buf, out_len| unsafe {
            botan_pk_op_encrypt(
                self.obj,
                rng_handle,
                out_buf,
                out_len,
                ptext.as_ptr(),
                ptext.len(),
            )
        })
    }
}

#[derive(Debug)]
/// An object that performs key agreement
pub struct KeyAgreement {
    obj: botan_pk_op_ka_t,
    op_lock: OpLock,
}

unsafe impl Sync for KeyAgreement {}
unsafe impl Send for KeyAgreement {}

botan_impl_drop!(KeyAgreement, botan_pk_op_key_agreement_destroy);

impl KeyAgreement {
    /// Create a new key agreement operator
    pub fn new<K: crate::KdfAlgorithmIdentifier>(key: &Privkey, kdf: K) -> Result<KeyAgreement> {
        let kdf = kdf.botan_name();
        let kdf = make_cstr(&kdf)?;
        let op_lock = key.op_lock();
        let obj = {
            let _lock = op_lock.guard()?;
            botan_init!(
                botan_pk_op_key_agreement_create,
                key.handle(),
                kdf.as_ptr(),
                0u32
            )?
        };
        Ok(KeyAgreement { obj, op_lock })
    }

    /// Perform key agreement operation
    pub fn agree(
        &mut self,
        requested_output: usize,
        counterparty_key: &[u8],
        salt: &[u8],
    ) -> Result<Vec<u8>> {
        let _lock = self.op_lock.guard()?;
        let mut ka_len = requested_output;

        if ka_len == 0 {
            ka_len = botan_usize!(botan_pk_op_key_agreement_size, self.obj)?;
        }

        call_botan_ffi_returning_vec_u8(ka_len, &|out_buf, out_len| unsafe {
            botan_pk_op_key_agreement(
                self.obj,
                out_buf,
                out_len,
                counterparty_key.as_ptr(),
                counterparty_key.len(),
                salt.as_ptr(),
                salt.len(),
            )
        })
    }
}
