use crate::utils::*;
use botan_sys::*;

use crate::pubkey::Pubkey;

#[derive(Debug)]
/// X.509 certificate
pub struct Certificate {
    obj: botan_x509_cert_t,
}

botan_impl_drop!(Certificate, botan_x509_cert_destroy);

impl Clone for Certificate {
    fn clone(&self) -> Certificate {
        self.duplicate()
            .expect("copying X509 cert object succeeded")
    }
}

/// Indicates if the certificate key is allowed for a particular usage
#[derive(Debug, Copy, Clone)]
pub enum CertUsage {
    /// No particular usage restrictions
    NoRestrictions,
    /// Allowed for digital signature
    DigitalSignature,
    /// Allowed for "non-repudiation" (whatever that means)
    NonRepudiation,
    /// Allowed for enciphering symmetric keys
    KeyEncipherment,
    /// Allowed for enciphering plaintext messages
    DataEncipherment,
    /// Allowed for key agreement
    KeyAgreement,
    /// Allowed for signing certificates
    CertificateSign,
    /// Allowed for signing CRLs
    CrlSign,
    /// Allowed only for encryption
    EncipherOnly,
    /// Allowed only for decryption
    DecipherOnly,
}

impl From<X509KeyConstraints> for CertUsage {
    fn from(err: X509KeyConstraints) -> CertUsage {
        match err {
            X509KeyConstraints::NO_CONSTRAINTS => CertUsage::NoRestrictions,
            X509KeyConstraints::DIGITAL_SIGNATURE => CertUsage::DigitalSignature,
            X509KeyConstraints::NON_REPUDIATION => CertUsage::NonRepudiation,
            X509KeyConstraints::KEY_ENCIPHERMENT => CertUsage::KeyEncipherment,
            X509KeyConstraints::DATA_ENCIPHERMENT => CertUsage::DataEncipherment,
            X509KeyConstraints::KEY_AGREEMENT => CertUsage::KeyAgreement,
            X509KeyConstraints::KEY_CERT_SIGN => CertUsage::CertificateSign,
            X509KeyConstraints::CRL_SIGN => CertUsage::CrlSign,
            X509KeyConstraints::ENCIPHER_ONLY => CertUsage::EncipherOnly,
            X509KeyConstraints::DECIPHER_ONLY => CertUsage::DecipherOnly,
        }
    }
}

impl From<CertUsage> for X509KeyConstraints {
    fn from(err: CertUsage) -> X509KeyConstraints {
        match err {
            CertUsage::NoRestrictions => X509KeyConstraints::NO_CONSTRAINTS,
            CertUsage::DigitalSignature => X509KeyConstraints::DIGITAL_SIGNATURE,
            CertUsage::NonRepudiation => X509KeyConstraints::NON_REPUDIATION,
            CertUsage::KeyEncipherment => X509KeyConstraints::KEY_ENCIPHERMENT,
            CertUsage::DataEncipherment => X509KeyConstraints::DATA_ENCIPHERMENT,
            CertUsage::KeyAgreement => X509KeyConstraints::KEY_AGREEMENT,
            CertUsage::CertificateSign => X509KeyConstraints::KEY_CERT_SIGN,
            CertUsage::CrlSign => X509KeyConstraints::CRL_SIGN,
            CertUsage::EncipherOnly => X509KeyConstraints::ENCIPHER_ONLY,
            CertUsage::DecipherOnly => X509KeyConstraints::DECIPHER_ONLY,
        }
    }
}

#[derive(Debug, Copy, Clone)]
/// Represents result of cert validation
pub enum CertValidationStatus {
    /// Successful validation, with possible detail code
    Success(i32),
    /// Failed validation, with reason code
    Failed(i32),
}

impl CertValidationStatus {
    /// Return true if the validation was successful
    #[must_use]
    pub fn success(&self) -> bool {
        match self {
            CertValidationStatus::Success(_) => true,
            CertValidationStatus::Failed(_) => false,
        }
    }
}

impl ToString for CertValidationStatus {
    fn to_string(&self) -> String {
        let code = match self {
            CertValidationStatus::Success(x) => x,
            CertValidationStatus::Failed(x) => x,
        };

        unsafe {
            let result_str = botan_x509_cert_validation_status(*code);

            let cstr = CStr::from_ptr(result_str);
            cstr.to_str().unwrap().to_owned()
        }
    }
}

impl Certificate {
    pub(crate) fn handle(&self) -> botan_x509_cert_t {
        self.obj
    }

    /// Load a X.509 certificate from DER or PEM representation
    pub fn load(data: &[u8]) -> Result<Certificate> {
        let mut obj = ptr::null_mut();
        call_botan! { botan_x509_cert_load(&mut obj, data.as_ptr(), data.len()) };
        Ok(Certificate { obj })
    }

    /// Read an X.509 certificate from a file
    pub fn from_file(fsname: &str) -> Result<Certificate> {
        let fsname = make_cstr(fsname)?;

        let mut obj = ptr::null_mut();
        call_botan! { botan_x509_cert_load_file(&mut obj, fsname.as_ptr()) };
        Ok(Certificate { obj })
    }

    /// Return the serial number of this certificate
    pub fn serial_number(&self) -> Result<Vec<u8>> {
        let sn_len = 32; // PKIX upper bound is 20
        call_botan_ffi_returning_vec_u8(sn_len, &|out_buf, out_len| unsafe {
            botan_x509_cert_get_serial_number(self.obj, out_buf, out_len)
        })
    }

    /// Return the fingerprint of this certificate
    pub fn fingerprint(&self, hash: &str) -> Result<Vec<u8>> {
        let fprint_len = 128;
        let hash = make_cstr(hash)?;
        call_botan_ffi_returning_vec_u8(fprint_len, &|out_buf, out_len| unsafe {
            botan_x509_cert_get_fingerprint(self.obj, hash.as_ptr(), out_buf, out_len)
        })
    }

    /// Duplicate the certificate object
    ///
    /// Since certificate objects are immutable, duplication just involves
    /// atomic incrementing a reference count, so is quite cheap
    pub fn duplicate(&self) -> Result<Certificate> {
        let mut obj = ptr::null_mut();
        call_botan! { botan_x509_cert_dup(&mut obj, self.obj) }
        Ok(Certificate { obj })
    }

    /// Return the authority key id, if set
    pub fn authority_key_id(&self) -> Result<Vec<u8>> {
        let akid_len = 32;
        call_botan_ffi_returning_vec_u8(akid_len, &|out_buf, out_len| unsafe {
            botan_x509_cert_get_authority_key_id(self.obj, out_buf, out_len)
        })
    }

    /// Return the subject key id, if set
    pub fn subject_key_id(&self) -> Result<Vec<u8>> {
        let skid_len = 32;
        call_botan_ffi_returning_vec_u8(skid_len, &|out_buf, out_len| unsafe {
            botan_x509_cert_get_subject_key_id(self.obj, out_buf, out_len)
        })
    }

    /// Return the byte representation of the public key
    pub fn public_key_bits(&self) -> Result<Vec<u8>> {
        let pk_len = 4096; // fixme
        call_botan_ffi_returning_vec_u8(pk_len, &|out_buf, out_len| unsafe {
            botan_x509_cert_get_public_key_bits(self.obj, out_buf, out_len)
        })
    }

    /// Return the public key included in this certificate
    pub fn public_key(&self) -> Result<Pubkey> {
        let mut key = ptr::null_mut();
        call_botan! { botan_x509_cert_get_public_key(self.obj, &mut key) };
        Ok(Pubkey::from_handle(key))
    }

    /// Return a free-form string representation of this certificate
    pub fn to_string(&self) -> Result<String> {
        let as_str_len = 4096;
        call_botan_ffi_returning_string(as_str_len, &|out_buf, out_len| unsafe {
            botan_x509_cert_to_string(self.obj, out_buf as *mut c_char, out_len)
        })
    }

    /// Test if the certificate is allowed for a particular usage
    pub fn allows_usage(&self, usage: CertUsage) -> Result<bool> {
        let usage_bit: X509KeyConstraints = X509KeyConstraints::from(usage);

        let rc = unsafe { botan_x509_cert_allowed_usage(self.obj, usage_bit as u32) };

        if rc == 0 {
            Ok(true)
        } else if rc == 1 {
            Ok(false)
        } else {
            Err(Error::from(rc))
        }
    }
    /// Attempt to verify this certificate
    pub fn verify(
        &self,
        intermediates: &[&Certificate],
        trusted: &[&Certificate],
        trusted_path: Option<&str>,
        hostname: Option<&str>,
        reference_time: Option<u64>,
    ) -> Result<CertValidationStatus> {
        let required_key_strength = 110;

        let trusted_path = make_cstr(trusted_path.unwrap_or(""))?;
        let hostname = make_cstr(hostname.unwrap_or(""))?;

        // TODO: more idiomatic way to do this?
        let mut trusted_h = Vec::new();
        for t in trusted {
            trusted_h.push(t.handle());
        }

        let mut intermediates_h = Vec::new();
        for t in intermediates {
            intermediates_h.push(t.handle());
        }

        // TODO this information is lost :(
        let mut result = 0;

        let rc = unsafe {
            botan_x509_cert_verify(
                &mut result,
                self.obj,
                intermediates_h.as_ptr(),
                intermediates_h.len(),
                trusted_h.as_ptr(),
                trusted_h.len(),
                trusted_path.as_ptr(),
                required_key_strength,
                hostname.as_ptr(),
                reference_time.unwrap_or(0),
            )
        };

        if rc == 0 {
            Ok(CertValidationStatus::Success(result))
        } else if rc == 1 {
            Ok(CertValidationStatus::Failed(result))
        } else {
            Err(Error::from(rc))
        }
    }

    /// Return true if the provided hostname is valid for this certificate
    pub fn matches_hostname(&self, hostname: &str) -> Result<bool> {
        let hostname = make_cstr(hostname)?;
        let rc = unsafe { botan_x509_cert_hostname_match(self.obj, hostname.as_ptr()) };

        if rc == 0 {
            Ok(true)
        } else if rc == -1 {
            Ok(false)
        } else {
            Err(Error::from(rc))
        }
    }
}
