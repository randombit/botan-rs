use crate::utils::*;
use botan_sys::*;

use crate::mp::MPI;
use crate::pk_ops::*;
use crate::rng::RandomNumberGenerator;

#[derive(Debug)]
/// A public key object
pub struct Pubkey {
    obj: botan_pubkey_t,
}

unsafe impl Sync for Pubkey {}
unsafe impl Send for Pubkey {}

botan_impl_drop!(Pubkey, botan_pubkey_destroy);

#[derive(Debug)]
/// A private key object
pub struct Privkey {
    obj: botan_privkey_t,
}

unsafe impl Sync for Privkey {}
unsafe impl Send for Privkey {}

botan_impl_drop!(Privkey, botan_privkey_destroy);

impl Privkey {
    pub(crate) fn handle(&self) -> botan_privkey_t {
        self.obj
    }

    /// Create a new private key
    ///
    pub fn create(alg: &str, params: &str, rng: &mut RandomNumberGenerator) -> Result<Privkey> {
        let obj = botan_init!(
            botan_privkey_create,
            make_cstr(alg)?.as_ptr(),
            make_cstr(params)?.as_ptr(),
            rng.handle()
        )?;

        Ok(Privkey { obj })
    }

    /// Load an RSA private key (p,q,e)
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// let p = botan::MPI::from_str("289698020102256958291511331409682926199").unwrap();
    /// let q = botan::MPI::from_str("293497288893125842977275290547344412783").unwrap();
    /// let e = botan::MPI::from_str("65537").unwrap();
    /// let rsa = botan::Privkey::load_rsa(&p, &q, &e).unwrap();
    /// ```
    pub fn load_rsa(p: &MPI, q: &MPI, e: &MPI) -> Result<Privkey> {
        let obj = botan_init!(botan_privkey_load_rsa, p.handle(), q.handle(), e.handle())?;
        Ok(Privkey { obj })
    }

    /// Load an Ed25519 private key
    ///
    /// # Examples
    ///
    /// ```
    /// let v = vec![0x42; 32];
    /// let key = botan::Privkey::load_ed25519(&v).unwrap();
    /// ```
    pub fn load_ed25519(key: &[u8]) -> Result<Privkey> {
        let obj = botan_init!(botan_privkey_load_ed25519, key.as_ptr())?;
        Ok(Privkey { obj })
    }

    /// Load an X25519 private key
    ///
    /// # Examples
    ///
    /// ```
    /// let v = vec![0x42; 32];
    /// let key = botan::Privkey::load_x25519(&v).unwrap();
    /// ```
    pub fn load_x25519(key: &[u8]) -> Result<Privkey> {
        let obj = botan_init!(botan_privkey_load_x25519, key.as_ptr())?;
        Ok(Privkey { obj })
    }

    /// Load a PKCS#1 encoded RSA private key
    pub fn load_rsa_pkcs1(pkcs1: &[u8]) -> Result<Privkey> {
        let obj = botan_init!(botan_privkey_load_rsa_pkcs1, pkcs1.as_ptr(), pkcs1.len())?;
        Ok(Privkey { obj })
    }

    /// Load an DH private key (p,g,x)
    pub fn load_dh(p: &MPI, g: &MPI, x: &MPI) -> Result<Privkey> {
        let obj = botan_init!(botan_privkey_load_dh, p.handle(), g.handle(), x.handle())?;
        Ok(Privkey { obj })
    }

    /// Load an DSA private key (p,q,g,x)
    pub fn load_dsa(p: &MPI, q: &MPI, g: &MPI, x: &MPI) -> Result<Privkey> {
        let obj = botan_init!(
            botan_privkey_load_dsa,
            p.handle(),
            q.handle(),
            g.handle(),
            x.handle()
        )?;
        Ok(Privkey { obj })
    }

    /// Load an ECDSA private key with specified curve and secret scalar
    pub fn load_ecdsa(s: &MPI, curve_name: &str) -> Result<Privkey> {
        let curve_name = make_cstr(curve_name)?;
        let obj = botan_init!(botan_privkey_load_ecdsa, s.handle(), curve_name.as_ptr())?;
        Ok(Privkey { obj })
    }

    /// Load an ECDH private key with specified curve and secret scalar
    pub fn load_ecdh(s: &MPI, curve_name: &str) -> Result<Privkey> {
        let curve_name = make_cstr(curve_name)?;
        let obj = botan_init!(botan_privkey_load_ecdh, s.handle(), curve_name.as_ptr())?;
        Ok(Privkey { obj })
    }

    /// Load DER bytes as an unencrypted PKCS#8 private key
    pub fn load_der(der: &[u8]) -> Result<Privkey> {
        let obj = botan_init!(
            botan_privkey_load,
            ptr::null_mut(),
            der.as_ptr(),
            der.len(),
            ptr::null()
        )?;
        Ok(Privkey { obj })
    }

    /// Load PEM string as an unencrypted PKCS#8 private key
    pub fn load_pem(pem: &str) -> Result<Privkey> {
        let cpem = make_cstr(pem)?;
        let obj = botan_init!(
            botan_privkey_load,
            ptr::null_mut(),
            cpem.as_ptr() as *const u8,
            pem.len(),
            ptr::null()
        )?;

        Ok(Privkey { obj })
    }

    /// Load DER bytes as an encrypted PKCS#8 private key
    pub fn load_encrypted_der(der: &[u8], passphrase: &str) -> Result<Privkey> {
        let passphrase = make_cstr(passphrase)?;
        let obj = botan_init!(
            botan_privkey_load,
            ptr::null_mut(),
            der.as_ptr(),
            der.len(),
            passphrase.as_ptr()
        )?;
        Ok(Privkey { obj })
    }

    /// Load PEM string as an encrypted PKCS#8 private key
    pub fn load_encrypted_pem(pem: &str, passphrase: &str) -> Result<Privkey> {
        let passphrase = make_cstr(passphrase)?;
        let cpem = make_cstr(pem)?;
        let obj = botan_init!(
            botan_privkey_load,
            ptr::null_mut(),
            cpem.as_ptr() as *const u8,
            pem.len(),
            passphrase.as_ptr()
        )?;

        Ok(Privkey { obj })
    }

    /// Check if the key seems to be valid
    pub fn check_key(&self, rng: &mut RandomNumberGenerator) -> Result<bool> {
        let flags = 1u32;
        let rc = unsafe { botan_privkey_check_key(self.obj, rng.handle(), flags) };

        if rc == 0 {
            Ok(true)
        } else if rc == -1 {
            Ok(false)
        } else {
            Err(Error::from_rc(rc))
        }
    }

    /// Return the public key associated with this private key
    pub fn pubkey(&self) -> Result<Pubkey> {
        let obj = botan_init!(botan_privkey_export_pubkey, self.obj)?;
        Ok(Pubkey { obj })
    }

    /// Return the name of the algorithm
    pub fn algo_name(&self) -> Result<String> {
        let name_len = 32;
        call_botan_ffi_returning_string(name_len, &|out_buf, out_len| unsafe {
            botan_privkey_algo_name(self.obj, out_buf as *mut c_char, out_len)
        })
    }

    /// DER encode the key (unencrypted)
    pub fn der_encode(&self) -> Result<Vec<u8>> {
        let der_len = 4096; // fixme
        call_botan_ffi_returning_vec_u8(der_len, &|out_buf, out_len| unsafe {
            botan_privkey_export(self.obj, out_buf, out_len, 0u32)
        })
    }

    /// DER encode the key (encrypted)
    pub fn der_encode_encrypted(
        &self,
        passphrase: &str,
        rng: &mut RandomNumberGenerator,
    ) -> Result<Vec<u8>> {
        let iterations = 150_000;
        self.der_encode_encrypted_with_options(
            passphrase,
            "AES-256/CBC",
            "SHA-512",
            iterations,
            rng,
        )
    }

    /// DER encode the key (encrypted), specifying cipher/hash options
    pub fn der_encode_encrypted_with_options(
        &self,
        passphrase: &str,
        cipher: &str,
        pbkdf: &str,
        pbkdf_iter: usize,
        rng: &mut RandomNumberGenerator,
    ) -> Result<Vec<u8>> {
        let der_len = 4096; // fixme
        let passphrase = make_cstr(passphrase)?;
        let cipher = make_cstr(cipher)?;
        let pbkdf = make_cstr(pbkdf)?;

        call_botan_ffi_returning_vec_u8(der_len, &|out_buf, out_len| unsafe {
            botan_privkey_export_encrypted_pbkdf_iter(
                self.obj,
                out_buf,
                out_len,
                rng.handle(),
                passphrase.as_ptr(),
                pbkdf_iter,
                cipher.as_ptr(),
                pbkdf.as_ptr(),
                0u32,
            )
        })
    }

    /// PEM encode the key (encrypted)
    pub fn pem_encode_encrypted(
        &self,
        passphrase: &str,
        rng: &mut RandomNumberGenerator,
    ) -> Result<String> {
        let iterations = 150_000;
        self.pem_encode_encrypted_with_options(
            passphrase,
            "AES-256/CBC",
            "SHA-512",
            iterations,
            rng,
        )
    }

    /// PEM encode the key (encrypted), specifying cipher/hash options
    pub fn pem_encode_encrypted_with_options(
        &self,
        passphrase: &str,
        cipher: &str,
        pbkdf: &str,
        pbkdf_iter: usize,
        rng: &mut RandomNumberGenerator,
    ) -> Result<String> {
        let pem_len = 4096; // fixme

        let passphrase = make_cstr(passphrase)?;
        let cipher = make_cstr(cipher)?;
        let pbkdf = make_cstr(pbkdf)?;

        call_botan_ffi_returning_string(pem_len, &|out_buf, out_len| unsafe {
            botan_privkey_export_encrypted_pbkdf_iter(
                self.obj,
                out_buf,
                out_len,
                rng.handle(),
                passphrase.as_ptr(),
                pbkdf_iter,
                cipher.as_ptr(),
                pbkdf.as_ptr(),
                1u32,
            )
        })
    }

    /// PEM encode the private key (unencrypted)
    pub fn pem_encode(&self) -> Result<String> {
        let pem_len = 4096; // fixme
        call_botan_ffi_returning_string(pem_len, &|out_buf, out_len| unsafe {
            botan_privkey_export(self.obj, out_buf, out_len, 1u32)
        })
    }

    /// Return the key agrement key, only valid for DH/ECDH
    pub fn key_agreement_key(&self) -> Result<Vec<u8>> {
        let ka_key_len = 512; // fixme
        call_botan_ffi_returning_vec_u8(ka_key_len, &|out_buf, out_len| unsafe {
            botan_pk_op_key_agreement_export_public(self.obj, out_buf, out_len)
        })
    }

    /// Get a value for the private key
    /// The which parameter selects a field which is algorithm specific
    pub fn get_field(&self, which: &str) -> Result<MPI> {
        let which = make_cstr(which)?;

        let r = MPI::new()?;
        botan_call!(
            botan_privkey_get_field,
            r.handle(),
            self.obj,
            which.as_ptr()
        )?;
        Ok(r)
    }

    /// Get the public and private key associated with this key
    pub fn get_ed25519_key(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut out = vec![0; 64];
        botan_call!(
            botan_privkey_ed25519_get_privkey,
            self.obj,
            out.as_mut_ptr()
        )?;
        let pubkey = out.split_off(32);

        Ok((pubkey, out))
    }

    /// Get the X25519 private key
    pub fn get_x25519_key(&self) -> Result<Vec<u8>> {
        let mut out = vec![0; 32];
        botan_call!(botan_privkey_x25519_get_privkey, self.obj, out.as_mut_ptr())?;
        Ok(out)
    }

    /// Sign a message using the specified padding method
    pub fn sign(
        &self,
        message: &[u8],
        padding: &str,
        rng: &mut RandomNumberGenerator,
    ) -> Result<Vec<u8>> {
        let mut signer = Signer::new(self, padding)?;
        signer.update(message)?;
        signer.finish(rng)
    }

    /// Decrypt a message that was encrypted using the specified padding method
    pub fn decrypt(&self, ctext: &[u8], padding: &str) -> Result<Vec<u8>> {
        let mut decryptor = Decryptor::new(self, padding)?;
        decryptor.decrypt(ctext)
    }

    /// Perform key agreement
    pub fn agree(
        &self,
        other_key: &[u8],
        output_len: usize,
        salt: &[u8],
        kdf: &str,
    ) -> Result<Vec<u8>> {
        let mut op = KeyAgreement::new(self, kdf)?;
        op.agree(output_len, other_key, salt)
    }
}

impl Pubkey {
    pub(crate) fn from_handle(obj: botan_pubkey_t) -> Pubkey {
        Pubkey { obj }
    }

    pub(crate) fn handle(&self) -> botan_pubkey_t {
        self.obj
    }

    /// Load a DER encoded public key
    pub fn load_der(der: &[u8]) -> Result<Pubkey> {
        let obj = botan_init!(botan_pubkey_load, der.as_ptr(), der.len())?;
        Ok(Pubkey { obj })
    }

    /// Load a PEM encoded public key
    pub fn load_pem(pem: &str) -> Result<Pubkey> {
        let obj = botan_init!(
            botan_pubkey_load,
            make_cstr(pem)?.as_ptr() as *const u8,
            pem.len()
        )?;
        Ok(Pubkey { obj })
    }

    /// Load an RSA public key (n,e)
    pub fn load_rsa(n: &MPI, e: &MPI) -> Result<Pubkey> {
        let obj = botan_init!(botan_pubkey_load_rsa, n.handle(), e.handle())?;
        Ok(Pubkey { obj })
    }

    /// Load an DH public key (p,g,y)
    pub fn load_dh(p: &MPI, g: &MPI, y: &MPI) -> Result<Pubkey> {
        let obj = botan_init!(botan_pubkey_load_dh, p.handle(), g.handle(), y.handle())?;
        Ok(Pubkey { obj })
    }

    /// Load an DSA public key (p,q,g,y)
    pub fn load_dsa(p: &MPI, q: &MPI, g: &MPI, y: &MPI) -> Result<Pubkey> {
        let obj = botan_init!(
            botan_pubkey_load_dsa,
            p.handle(),
            q.handle(),
            g.handle(),
            y.handle()
        )?;
        Ok(Pubkey { obj })
    }

    /// Load an ECDSA public key (x,y) for the specified curve
    pub fn load_ecdsa(pub_x: &MPI, pub_y: &MPI, curve_name: &str) -> Result<Pubkey> {
        let curve_name = make_cstr(curve_name)?;
        let obj = botan_init!(
            botan_pubkey_load_ecdsa,
            pub_x.handle(),
            pub_y.handle(),
            curve_name.as_ptr()
        )?;
        Ok(Pubkey { obj })
    }

    /// Load an ECDH public key (x,y) for the specified curve
    pub fn load_ecdh(pub_x: &MPI, pub_y: &MPI, curve_name: &str) -> Result<Pubkey> {
        let curve_name = make_cstr(curve_name)?;
        let obj = botan_init!(
            botan_pubkey_load_ecdh,
            pub_x.handle(),
            pub_y.handle(),
            curve_name.as_ptr()
        )?;
        Ok(Pubkey { obj })
    }

    /// Load an Ed25519 public key
    pub fn load_ed25519(key: &[u8]) -> Result<Pubkey> {
        let obj = botan_init!(botan_pubkey_load_ed25519, key.as_ptr())?;
        Ok(Pubkey { obj })
    }

    /// Load an X25519 key
    pub fn load_x25519(key: &[u8]) -> Result<Pubkey> {
        let obj = botan_init!(botan_pubkey_load_x25519, key.as_ptr())?;
        Ok(Pubkey { obj })
    }

    /// Return estimated bit strength of this key
    pub fn estimated_strength(&self) -> Result<usize> {
        botan_usize!(botan_pubkey_estimated_strength, self.obj)
    }

    /// Check key for problems
    pub fn check_key(&self, rng: &mut RandomNumberGenerator) -> Result<bool> {
        let flags = 1u32;
        let rc = unsafe { botan_pubkey_check_key(self.obj, rng.handle(), flags) };

        if rc == 0 {
            Ok(true)
        } else if rc == -1 {
            Ok(false)
        } else {
            Err(Error::from_rc(rc))
        }
    }

    /// Return hash of the public key data
    pub fn fingerprint(&self, hash: &str) -> Result<String> {
        let hash = make_cstr(hash)?;
        let fprint_len = 64; // hashes > 512 bits are rare
        call_botan_ffi_returning_string(fprint_len, &|out_buf, out_len| unsafe {
            botan_pubkey_fingerprint(self.obj, hash.as_ptr(), out_buf, out_len)
        })
    }

    /// DER encode this public key
    pub fn der_encode(&self) -> Result<Vec<u8>> {
        let der_len = 4096; // fixme
        call_botan_ffi_returning_vec_u8(der_len, &|out_buf, out_len| unsafe {
            botan_pubkey_export(self.obj, out_buf, out_len, 0u32)
        })
    }

    /// PEM encode this public key
    pub fn pem_encode(&self) -> Result<String> {
        let pem_len = 4096; // fixme
        call_botan_ffi_returning_string(pem_len, &|out_buf, out_len| unsafe {
            botan_pubkey_export(self.obj, out_buf, out_len, 1u32)
        })
    }

    /// Return the name of the algorithm
    pub fn algo_name(&self) -> Result<String> {
        let name_len = 32;
        call_botan_ffi_returning_string(name_len, &|out_buf, out_len| unsafe {
            botan_pubkey_algo_name(self.obj, out_buf as *mut c_char, out_len)
        })
    }

    /// Get a value for the public key
    /// The which parameter selects a field which is algorithm specific
    pub fn get_field(&self, which: &str) -> Result<MPI> {
        let which = make_cstr(which)?;

        let r = MPI::new()?;
        botan_call!(botan_pubkey_get_field, r.handle(), self.obj, which.as_ptr())?;
        Ok(r)
    }

    /// Return the 32-byte Ed25519 public key
    pub fn get_ed25519_key(&self) -> Result<Vec<u8>> {
        let mut out = vec![0; 32];

        botan_call!(botan_pubkey_ed25519_get_pubkey, self.obj, out.as_mut_ptr())?;

        Ok(out)
    }

    /// Get the X25519 public key
    pub fn get_x25519_key(&self) -> Result<Vec<u8>> {
        let mut out = vec![0; 32];
        botan_call!(botan_pubkey_x25519_get_pubkey, self.obj, out.as_mut_ptr())?;
        Ok(out)
    }

    /// Encrypt a message using the specified padding method
    pub fn encrypt(
        &self,
        message: &[u8],
        padding: &str,
        rng: &mut RandomNumberGenerator,
    ) -> Result<Vec<u8>> {
        let mut op = Encryptor::new(self, padding)?;
        op.encrypt(message, rng)
    }

    /// Verify a message that was signed using the specified padding method
    pub fn verify(&self, message: &[u8], signature: &[u8], padding: &str) -> Result<bool> {
        let mut op = Verifier::new(self, padding)?;
        op.update(message)?;
        op.finish(signature)
    }
}

/// Return the identifier used for PKCS1 v1.5 signatures for the specified hash
pub fn pkcs_hash_id(hash_algo: &str) -> Result<Vec<u8>> {
    let hash_algo = make_cstr(hash_algo)?;
    let id_len = 32; // largest currently is 20 bytes
    call_botan_ffi_returning_vec_u8(id_len, &|out_buf, out_len| unsafe {
        botan_pkcs_hash_id(hash_algo.as_ptr(), out_buf, out_len)
    })
}
