#[cfg(botan_ffi_20251104)]
use core::net::Ipv4Addr;

use crate::utils::*;
#[cfg(botan_ffi_20251104)]
use crate::{
    pubkey::Privkey,
    x509_ext::{ASBlocks, IpAddrBlocks},
    RandomNumberGenerator, CRL, MPI, OID,
};
use botan_sys::*;

use crate::pubkey::Pubkey;

#[derive(Debug)]
/// X.509 certificate
pub struct Certificate {
    obj: botan_x509_cert_t,
}

unsafe impl Sync for Certificate {}
unsafe impl Send for Certificate {}

botan_impl_drop!(Certificate, botan_x509_cert_destroy);

impl Clone for Certificate {
    fn clone(&self) -> Certificate {
        self.duplicate()
            .expect("copying X509 cert object succeeded")
    }
}

/// Indicates if the certificate key is allowed for a particular usage
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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

#[cfg(botan_ffi_20251104)]
impl CertUsage {
    pub(crate) fn to_bits(constraints: &[Self]) -> u32 {
        constraints
            .iter()
            .map(|usage| X509KeyConstraints::from(*usage))
            .fold(0, |acc, constraint| acc | (constraint as u32))
    }

    pub(crate) fn from_bits(bits: u32) -> Vec<Self> {
        if bits == 0 {
            return vec![Self::NoRestrictions];
        }

        let all_constraints = [
            X509KeyConstraints::DIGITAL_SIGNATURE,
            X509KeyConstraints::NON_REPUDIATION,
            X509KeyConstraints::KEY_ENCIPHERMENT,
            X509KeyConstraints::DATA_ENCIPHERMENT,
            X509KeyConstraints::KEY_AGREEMENT,
            X509KeyConstraints::KEY_CERT_SIGN,
            X509KeyConstraints::CRL_SIGN,
            X509KeyConstraints::ENCIPHER_ONLY,
            X509KeyConstraints::DECIPHER_ONLY,
        ];

        all_constraints
            .into_iter()
            .filter(|&constraint| (bits & constraint as u32) != 0)
            .map(CertUsage::from)
            .collect()
    }
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

impl core::fmt::Display for CertValidationStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let code = match self {
            CertValidationStatus::Success(x) => x,
            CertValidationStatus::Failed(x) => x,
        };

        unsafe {
            let result_str = botan_x509_cert_validation_status(*code);

            let cstr = CStr::from_ptr(result_str);
            write!(f, "{}", cstr.to_str().unwrap())
        }
    }
}

impl Certificate {
    pub(crate) fn handle(&self) -> botan_x509_cert_t {
        self.obj
    }

    /// Load a X.509 certificate from DER or PEM representation
    pub fn load(data: &[u8]) -> Result<Certificate> {
        let obj = botan_init!(botan_x509_cert_load, data.as_ptr(), data.len())?;
        Ok(Certificate { obj })
    }

    /// Read an X.509 certificate from a file
    pub fn from_file(fsname: &str) -> Result<Certificate> {
        let fsname = make_cstr(fsname)?;
        let obj = botan_init!(botan_x509_cert_load_file, fsname.as_ptr())?;
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
        let obj = botan_init!(botan_x509_cert_dup, self.obj)?;
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

    /// Return the certificate notBefore time in seconds since epoch
    pub fn not_before_raw(&self) -> Result<u64> {
        let mut timestamp = 0u64;
        let rc = unsafe { botan_x509_cert_not_before(self.obj, &mut timestamp) };
        if rc != 0 {
            Err(Error::from_rc(rc))
        } else {
            Ok(timestamp)
        }
    }

    /// Return the certificate notAfter time in seconds since epoch
    pub fn not_after_raw(&self) -> Result<u64> {
        let mut timestamp = 0u64;
        let rc = unsafe { botan_x509_cert_not_after(self.obj, &mut timestamp) };
        if rc != 0 {
            Err(Error::from_rc(rc))
        } else {
            Ok(timestamp)
        }
    }

    #[cfg(feature = "std")]
    /// Return the certificate notBefore time as a SystemTime
    pub fn not_before(&self) -> Result<std::time::SystemTime> {
        use std::time::{Duration, UNIX_EPOCH};
        Ok(UNIX_EPOCH + Duration::from_secs(self.not_before_raw()?))
    }

    #[cfg(feature = "std")]
    /// Return the certificate notBefore time as a SystemTime
    pub fn not_after(&self) -> Result<std::time::SystemTime> {
        use std::time::{Duration, UNIX_EPOCH};
        Ok(UNIX_EPOCH + Duration::from_secs(self.not_after_raw()?))
    }

    /// Return the byte representation of the public key
    pub fn public_key_bits(&self) -> Result<Vec<u8>> {
        #[cfg(not(botan_ffi_20230403))]
        {
            let pk_len = 4096; // fixme
            call_botan_ffi_returning_vec_u8(pk_len, &|out_buf, out_len| unsafe {
                botan_x509_cert_get_public_key_bits(self.obj, out_buf, out_len)
            })
        }

        #[cfg(botan_ffi_20230403)]
        {
            call_botan_ffi_viewing_vec_u8(&|ctx, cb| unsafe {
                botan_x509_cert_view_public_key_bits(self.obj, ctx, cb)
            })
        }
    }

    /// Return the public key included in this certificate
    pub fn public_key(&self) -> Result<Pubkey> {
        let mut key = ptr::null_mut();
        botan_call!(botan_x509_cert_get_public_key, self.obj, &mut key)?;
        Ok(Pubkey::from_handle(key))
    }

    #[cfg(botan_ffi_20251104)]
    pub fn ocsp_responder(&self) -> Result<String> {
        call_botan_ffi_viewing_str_fn(&|ctx, cb| unsafe {
            botan_x509_cert_get_ocsp_responder(self.obj, ctx, cb)
        })
    }

    #[cfg(botan_ffi_20251104)]
    pub fn issuer_dn(&self, key: &str) -> Result<Vec<String>> {
        let mut count = 0;
        let key = make_cstr(key)?;
        botan_call!(
            botan_x509_cert_get_issuer_dn_count,
            self.obj,
            key.as_ptr(),
            &mut count
        )?;
        let mut entries = Vec::new();
        for i in 0..count {
            let item = call_botan_ffi_returning_string(0, &|out_buf, out_len| unsafe {
                botan_x509_cert_get_issuer_dn(self.obj, key.as_ptr(), i, out_buf, out_len)
            })?;
            entries.push(item);
        }
        Ok(entries)
    }

    #[cfg(botan_ffi_20251104)]
    pub fn subject_dn(&self, key: &str) -> Result<Vec<String>> {
        let mut count = 0;
        let key = make_cstr(key)?;
        botan_call!(
            botan_x509_cert_get_subject_dn_count,
            self.obj,
            key.as_ptr(),
            &mut count
        )?;
        let mut entries = Vec::new();
        for i in 0..count {
            let item = call_botan_ffi_returning_string(0, &|out_buf, out_len| unsafe {
                botan_x509_cert_get_subject_dn(self.obj, key.as_ptr(), i, out_buf, out_len)
            })?;
            entries.push(item);
        }
        Ok(entries)
    }

    #[cfg(botan_ffi_20251104)]
    pub fn subject_name(&self) -> Result<String> {
        call_botan_ffi_viewing_str_fn(&|ctx, cb| unsafe {
            botan_x509_cert_get_subject_name(self.obj, ctx, cb)
        })
    }

    #[cfg(botan_ffi_20251104)]
    pub fn issuer_name(&self) -> Result<String> {
        call_botan_ffi_viewing_str_fn(&|ctx, cb| unsafe {
            botan_x509_cert_get_issuer_name(self.obj, ctx, cb)
        })
    }

    /// Return a free-form string representation of this certificate
    pub fn to_string(&self) -> Result<String> {
        #[cfg(not(botan_ffi_20230403))]
        {
            let as_str_len = 4096;
            call_botan_ffi_returning_string(as_str_len, &|out_buf, out_len| unsafe {
                botan_x509_cert_to_string(self.obj, out_buf as *mut c_char, out_len)
            })
        }

        #[cfg(botan_ffi_20230403)]
        {
            call_botan_ffi_viewing_str_fn(&|ctx, cb| unsafe {
                botan_x509_cert_view_as_string(self.obj, ctx, cb)
            })
        }
    }

    /// Return the certificate in PEM form
    #[cfg(botan_ffi_20251104)]
    pub fn to_pem(&self) -> Result<String> {
        call_botan_ffi_viewing_str_fn(&|ctx, cb| unsafe {
            botan_x509_cert_view_pem(self.obj, ctx, cb)
        })
    }

    #[cfg(botan_ffi_20251104)]
    pub fn is_ca(&self) -> Result<(bool, Option<usize>)> {
        let mut is_ca = 0;
        let mut limit = 0;
        botan_call!(botan_x509_cert_is_ca, self.obj, &mut is_ca, &mut limit)?;
        let is_ca = interp_as_bool(is_ca, "botan_x509_cert_is_ca")?;
        if is_ca {
            Ok((true, Some(limit)))
        } else {
            Ok((false, None))
        }
    }

    #[cfg(botan_ffi_20251104)]
    pub fn is_self_signed(&self) -> Result<bool> {
        let mut out = 0;
        botan_call!(botan_x509_cert_is_self_signed, self.obj, &mut out)?;
        interp_as_bool(out, "botan_x509_cert_is_self_signed")
    }

    /// Test if the certificate is allowed for a particular usage
    pub fn allows_usage(&self, usage: CertUsage) -> Result<bool> {
        let usage_bit: X509KeyConstraints = X509KeyConstraints::from(usage);

        // Return logic is inverted for this function
        let r = botan_bool_in_rc!(botan_x509_cert_allowed_usage, self.obj, usage_bit as u32)?;
        Ok(!r)
    }

    ///
    #[cfg(botan_ffi_20251104)]
    pub fn allowed_usage(&self) -> Result<Vec<CertUsage>> {
        let mut usage = 0;
        botan_call!(botan_x509_cert_get_allowed_usage, self.obj, &mut usage)?;
        Ok(CertUsage::from_bits(usage))
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

        let trusted_h = trusted.iter().map(|t| t.handle()).collect::<Vec<_>>();
        let intermediates_h = intermediates.iter().map(|i| i.handle()).collect::<Vec<_>>();

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
            Err(Error::from_rc(rc))
        }
    }

    /// Attempt to verify this certificate
    pub fn verify_with_crl(
        &self,
        intermediates: &[&Certificate],
        trusted: &[&Certificate],
        trusted_path: Option<&str>,
        hostname: Option<&str>,
        reference_time: Option<u64>,
        crls: &[&CRL],
    ) -> Result<CertValidationStatus> {
        let required_key_strength = 110;

        let trusted_path = make_cstr(trusted_path.unwrap_or(""))?;
        let hostname = make_cstr(hostname.unwrap_or(""))?;

        let trusted_h = trusted.iter().map(|t| t.handle()).collect::<Vec<_>>();
        let intermediates_h = intermediates.iter().map(|i| i.handle()).collect::<Vec<_>>();
        let crls_h = crls.iter().map(|c| c.handle()).collect::<Vec<_>>();

        let mut result = 0;

        let rc = unsafe {
            botan_x509_cert_verify_with_crl(
                &mut result,
                self.obj,
                intermediates_h.as_ptr(),
                intermediates_h.len(),
                trusted_h.as_ptr(),
                trusted_h.len(),
                crls_h.as_ptr(),
                crls_h.len(),
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
            Err(Error::from_rc(rc))
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
            Err(Error::from_rc(rc))
        }
    }

    #[cfg(botan_ffi_20251104)]
    pub fn ext_ip_addr_blocks(&self) -> Result<IpAddrBlocks> {
        IpAddrBlocks::from_cert(self)
    }

    #[cfg(botan_ffi_20251104)]
    pub fn ext_as_blocks(&self) -> Result<ASBlocks> {
        ASBlocks::from_cert(self)
    }
}

#[cfg(botan_ffi_20251104)]
#[derive(Debug)]
/// X.509 certificate Builder
pub struct CertificateBuilder {
    obj: botan_x509_cert_params_builder_t,
}
#[cfg(botan_ffi_20251104)]
unsafe impl Sync for CertificateBuilder {}
#[cfg(botan_ffi_20251104)]
unsafe impl Send for CertificateBuilder {}
#[cfg(botan_ffi_20251104)]
botan_impl_drop!(CertificateBuilder, botan_x509_cert_params_builder_destroy);

#[cfg(botan_ffi_20251104)]
impl CertificateBuilder {
    pub fn new() -> Result<CertificateBuilder> {
        let obj = botan_init!(botan_x509_cert_params_builder_create,)?;
        Ok(CertificateBuilder { obj })
    }

    pub fn add_common_name(&mut self, name: &str) -> Result<()> {
        let name = make_cstr(name)?;
        botan_call!(
            botan_x509_cert_params_builder_add_common_name,
            self.obj,
            name.as_ptr()
        )
    }

    pub fn add_country(&mut self, country: &str) -> Result<()> {
        let country = make_cstr(country)?;
        botan_call!(
            botan_x509_cert_params_builder_add_country,
            self.obj,
            country.as_ptr()
        )
    }

    pub fn add_organization(&mut self, organization: &str) -> Result<()> {
        let organization = make_cstr(organization)?;
        botan_call!(
            botan_x509_cert_params_builder_add_organization,
            self.obj,
            organization.as_ptr()
        )
    }

    pub fn add_organizational_unit(&mut self, org_unit: &str) -> Result<()> {
        let org_unit = make_cstr(org_unit)?;
        botan_call!(
            botan_x509_cert_params_builder_add_organizational_unit,
            self.obj,
            org_unit.as_ptr()
        )
    }

    pub fn add_locality(&mut self, locality: &str) -> Result<()> {
        let locality = make_cstr(locality)?;
        botan_call!(
            botan_x509_cert_params_builder_add_locality,
            self.obj,
            locality.as_ptr()
        )
    }

    pub fn add_state(&mut self, state: &str) -> Result<()> {
        let state = make_cstr(state)?;
        botan_call!(
            botan_x509_cert_params_builder_add_state,
            self.obj,
            state.as_ptr()
        )
    }

    pub fn add_serial_number(&mut self, serial_number: &str) -> Result<()> {
        let serial_number = make_cstr(serial_number)?;
        botan_call!(
            botan_x509_cert_params_builder_add_serial_number,
            self.obj,
            serial_number.as_ptr()
        )
    }

    pub fn add_email(&mut self, email: &str) -> Result<()> {
        let email = make_cstr(email)?;
        botan_call!(
            botan_x509_cert_params_builder_add_email,
            self.obj,
            email.as_ptr()
        )
    }

    pub fn add_uri(&mut self, uri: &str) -> Result<()> {
        let uri = make_cstr(uri)?;
        botan_call!(
            botan_x509_cert_params_builder_add_uri,
            self.obj,
            uri.as_ptr()
        )
    }

    pub fn add_ipv4(&mut self, ip: Ipv4Addr) -> Result<()> {
        botan_call!(
            botan_x509_cert_params_builder_add_ipv4,
            self.obj,
            ip.to_bits()
        )
    }

    pub fn add_dns(&mut self, dns: &str) -> Result<()> {
        let dns = make_cstr(dns)?;
        botan_call!(
            botan_x509_cert_params_builder_add_dns,
            self.obj,
            dns.as_ptr()
        )
    }

    pub fn add_xmpp(&mut self, xmpp: &str) -> Result<()> {
        let xmpp = make_cstr(xmpp)?;
        botan_call!(
            botan_x509_cert_params_builder_add_xmpp,
            self.obj,
            xmpp.as_ptr()
        )
    }
    pub fn set_as_ca_certificate(&mut self, limit: Option<usize>) -> Result<()> {
        botan_call!(
            botan_x509_cert_params_builder_set_as_ca_certificate,
            self.obj,
            limit
                .as_ref()
                .map_or(std::ptr::null(), |exp| exp as *const _)
        )
    }

    pub fn add_constraints(&mut self, usage: &[CertUsage]) -> Result<()> {
        botan_call!(
            botan_x509_cert_params_builder_add_allowed_usage,
            self.obj,
            CertUsage::to_bits(usage)
        )
    }

    pub fn add_ex_constraint(&mut self, oid: &OID) -> Result<()> {
        botan_call!(
            botan_x509_cert_params_builder_add_allowed_extended_usage,
            self.obj,
            oid.handle()
        )
    }

    pub fn add_ext_ip_addr_blocks(
        &mut self,
        ip_addr_blocks: &IpAddrBlocks,
        is_critical: bool,
    ) -> Result<()> {
        botan_call!(
            botan_x509_cert_params_builder_add_ext_ip_addr_blocks,
            self.obj,
            ip_addr_blocks.handle(),
            is_critical as c_int
        )
    }

    pub fn add_ext_as_blocks(&mut self, as_blocks: &ASBlocks, is_critical: bool) -> Result<()> {
        botan_call!(
            botan_x509_cert_params_builder_add_ext_as_blocks,
            self.obj,
            as_blocks.handle(),
            is_critical as c_int
        )
    }

    #[cfg(botan_ffi_20251104)]
    pub fn into_self_signed(
        &self,
        key: &Privkey,
        rng: &mut RandomNumberGenerator,
        not_before: u64,
        not_after: u64,
        serial_number: Option<&MPI>,
        hash_fn: Option<&str>,
        padding: Option<&str>,
    ) -> Result<Certificate> {
        let hash_fn = make_optional_cstr(hash_fn)?;
        let padding = make_optional_cstr(padding)?;
        let serial_handle = serial_number.map(|sn| sn.handle());
        let serial_ptr = serial_handle
            .as_ref()
            .map_or(std::ptr::null(), |handle| handle as *const _);

        let obj = botan_init!(
            botan_x509_cert_params_builder_into_self_signed,
            key.handle(),
            self.obj,
            rng.handle(),
            not_before,
            not_after,
            serial_ptr,
            hash_fn
                .as_ref()
                .map_or(std::ptr::null(), |hash_fn| hash_fn.as_ptr()),
            padding
                .as_ref()
                .map_or(std::ptr::null(), |padding| padding.as_ptr())
        )?;
        Ok(Certificate { obj })
    }

    #[cfg(botan_ffi_20251104)]
    pub fn into_request(
        &self,
        key: &Privkey,
        rng: &mut RandomNumberGenerator,
        hash_fn: Option<&str>,
        padding: Option<&str>,
        challenge_password: Option<&str>,
    ) -> Result<CertificateRequest> {
        let hash_fn = make_optional_cstr(hash_fn)?;
        let padding = make_optional_cstr(padding)?;
        let challenge = make_optional_cstr(challenge_password)?;

        let obj = botan_init!(
            botan_x509_cert_params_builder_into_pkcs10_req,
            key.handle(),
            self.obj,
            rng.handle(),
            hash_fn
                .as_ref()
                .map_or(std::ptr::null(), |hash_fn| hash_fn.as_ptr()),
            padding
                .as_ref()
                .map_or(std::ptr::null(), |padding| padding.as_ptr()),
            challenge
                .as_ref()
                .map_or(std::ptr::null(), |challenge| challenge.as_ptr())
        )?;

        Ok(CertificateRequest { obj })
    }
}

#[cfg(botan_ffi_20251104)]
#[derive(Debug)]
pub struct CertificateRequest {
    obj: botan_x509_pkcs10_req_t,
}

#[cfg(botan_ffi_20251104)]
unsafe impl Sync for CertificateRequest {}
#[cfg(botan_ffi_20251104)]
unsafe impl Send for CertificateRequest {}

#[cfg(botan_ffi_20251104)]
botan_impl_drop!(CertificateRequest, botan_x509_pkcs10_req_destroy);

#[cfg(botan_ffi_20251104)]
impl CertificateRequest {
    pub fn load(data: &[u8]) -> Result<CertificateRequest> {
        let obj = botan_init!(botan_x509_pkcs10_req_load, data.as_ptr(), data.len())?;
        Ok(CertificateRequest { obj })
    }

    pub fn from_file(fsname: &str) -> Result<CertificateRequest> {
        let fsname = make_cstr(fsname)?;
        let obj = botan_init!(botan_x509_pkcs10_req_load_file, fsname.as_ptr())?;
        Ok(CertificateRequest { obj })
    }

    pub fn verify(&self, key: &Pubkey) -> Result<bool> {
        let mut result = 0;
        botan_call!(
            botan_x509_pkcs10_req_verify_signature,
            self.obj,
            key.handle(),
            &mut result
        )?;
        interp_as_bool(result, "botan_x509_pkcs10_req_verify_signature")
    }

    pub fn public_key(&self) -> Result<Pubkey> {
        let mut key = ptr::null_mut();
        botan_call!(botan_x509_pkcs10_req_get_public_key, self.obj, &mut key)?;
        Ok(Pubkey::from_handle(key))
    }

    pub fn allowed_usage(&self) -> Result<Vec<CertUsage>> {
        let mut usage = 0;
        botan_call!(
            botan_x509_pkcs10_req_get_allowed_usage,
            self.obj,
            &mut usage
        )?;
        Ok(CertUsage::from_bits(usage))
    }

    pub fn is_ca(&self) -> Result<(bool, Option<usize>)> {
        let mut is_ca = 0;
        let mut limit = 0;
        botan_call!(
            botan_x509_pkcs10_req_is_ca,
            self.obj,
            &mut is_ca,
            &mut limit
        )?;
        let is_ca = interp_as_bool(is_ca, "botan_x509_pkcs10_req_is_ca")?;
        if is_ca {
            Ok((true, Some(limit)))
        } else {
            Ok((false, None))
        }
    }

    pub fn sign(
        &self,
        issuing_cert: &Certificate,
        issuing_key: &Privkey,
        rng: &mut RandomNumberGenerator,
        not_before: u64,
        not_after: u64,
        serial_number: Option<&MPI>,
        hash_fn: Option<&str>,
        padding: Option<&str>,
    ) -> Result<Certificate> {
        let hash_fn = make_optional_cstr(hash_fn)?;
        let padding = make_optional_cstr(padding)?;
        let serial_handle = serial_number.map(|sn| sn.handle());
        let serial_ptr = serial_handle
            .as_ref()
            .map_or(std::ptr::null(), |handle| handle as *const _);

        let obj = botan_init!(
            botan_x509_pkcs10_req_sign,
            self.obj,
            issuing_cert.handle(),
            issuing_key.handle(),
            rng.handle(),
            not_before,
            not_after,
            serial_ptr,
            hash_fn
                .as_ref()
                .map_or(std::ptr::null(), |hash_fn| hash_fn.as_ptr()),
            padding
                .as_ref()
                .map_or(std::ptr::null(), |padding| padding.as_ptr())
        )?;
        Ok(Certificate { obj })
    }

    pub fn to_pem(&self) -> Result<String> {
        call_botan_ffi_viewing_str_fn(&|ctx, cb| unsafe {
            botan_x509_pkcs10_req_view_pem(self.obj, ctx, cb)
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        call_botan_ffi_viewing_vec_u8(&|ctx, cb| unsafe {
            botan_x509_pkcs10_req_view_der(self.obj, ctx, cb)
        })
    }
}
