#[cfg(botan_ffi_20260811)]
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::{CRL, utils::*};
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
    pub fn fingerprint<A: crate::HashAlgorithmIdentifier>(&self, hash: A) -> Result<Vec<u8>> {
        let fprint_len = 128;
        let hash = hash.botan_name();
        let hash = make_cstr(&hash)?;
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

    #[cfg(botan_ffi_20260303)]
    /// Return the listed addresses of OCSP Responders
    pub fn ocsp_responders(&self) -> Result<Vec<String>> {
        let mut count = 0;
        botan_call!(
            botan_x509_cert_view_string_values_count,
            self.obj,
            X509ValueType::BOTAN_X509_OCSP_RESPONDER_URLS as i32,
            &mut count
        )?;
        let mut urls = Vec::new();
        for i in 0..count {
            let item = call_botan_ffi_viewing_str_fn(&|ctx, cb| unsafe {
                botan_x509_cert_view_string_values(
                    self.obj,
                    X509ValueType::BOTAN_X509_OCSP_RESPONDER_URLS as i32,
                    i,
                    ctx,
                    cb,
                )
            })?;
            urls.push(item);
        }
        Ok(urls)
    }

    #[cfg(botan_ffi_20260303)]
    /// Get a value for a specific subject distinguished name parameter.
    ///
    /// See `subject_dn()` for valid values.
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

    #[cfg(botan_ffi_20260303)]
    /// Get a value for a specific subject distinguished name parameter.
    ///
    /// Valid values:
    /// - "X520.Country", "X520.State", "X520.Organization", "X520.OrganizationalUnit", "X520.CommonName"
    /// - "Email" / "RFC822"
    /// - "DNS"
    /// - "URI"
    /// - "IP"
    ///
    /// ... and more. See `Botan::X509_Certificate.subject_info()`.
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

    #[cfg(botan_ffi_20260303)]
    /// Check if the certificate is marked as a certificate authority
    pub fn is_ca(&self) -> Result<bool> {
        botan_bool_in_rc!(botan_x509_cert_is_ca, self.obj)
    }

    #[cfg(botan_ffi_20260303)]
    /// Get the CA path limit for this certificate, if it has one
    pub fn path_limit(&self) -> Result<usize> {
        let mut path_limit = 0;
        botan_call!(
            botan_x509_cert_get_path_length_constraint,
            self.obj,
            &mut path_limit
        )?;
        Ok(path_limit)
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

    #[cfg(botan_ffi_20260303)]
    /// Get the PEM encoding of this certificate
    pub fn pem_encode(&self) -> Result<String> {
        call_botan_ffi_viewing_str_fn(&|ctx, cb| unsafe {
            botan_x509_cert_view_string_values(
                self.obj,
                X509ValueType::BOTAN_X509_PEM_ENCODING as i32,
                0,
                ctx,
                cb,
            )
        })
    }

    #[cfg(botan_ffi_20260303)]
    /// Get the DER encoding of this certificate
    pub fn der_encode(&self) -> Result<Vec<u8>> {
        call_botan_ffi_viewing_vec_u8(&|ctx, cb| unsafe {
            botan_x509_cert_view_binary_values(
                self.obj,
                X509ValueType::BOTAN_X509_DER_ENCODING as i32,
                0,
                ctx,
                cb,
            )
        })
    }

    /// Test if the certificate is allowed for a particular usage
    pub fn allows_usage(&self, usage: CertUsage) -> Result<bool> {
        let usage_bit: X509KeyConstraints = X509KeyConstraints::from(usage);

        // Return logic is inverted for this function
        let r = botan_bool_in_rc!(botan_x509_cert_allowed_usage, self.obj, usage_bit as u32)?;
        Ok(!r)
    }

    /// Get values from the IP Address Blocks extension.
    /// If the extension is not present, this will return `Err`.
    ///
    /// Returns all values in the extension, in the form of (v4, v6).
    /// Each contains a vec of families. Each family is a tuple (SAFI, ranges).
    /// Both SAFI and the ranges may be `None`, if ranges is `None` the family was marked as "inherit".
    /// The ranges are vecs of (min address, max address) tuples.
    #[cfg(botan_ffi_20260811)]
    #[allow(clippy::type_complexity)]
    pub fn ext_ip_addr_blocks(
        &self,
    ) -> Result<(
        Vec<(Option<u8>, Option<Vec<(Ipv4Addr, Ipv4Addr)>>)>,
        Vec<(Option<u8>, Option<Vec<(Ipv6Addr, Ipv6Addr)>>)>,
    )> {
        let mut v4_count = 0;
        let mut v6_count = 0;
        botan_call!(
            botan_x509_ext_ip_addr_blocks_get_counts,
            self.obj,
            &mut v4_count,
            &mut v6_count
        )?;

        let mut v4 = Vec::with_capacity(v4_count);
        let mut v6 = Vec::with_capacity(v6_count);

        for (ipv6, stop) in [(false, v4_count), (true, v6_count)] {
            for i in 0..stop {
                let size = if ipv6 { 16 } else { 4 };

                let mut has_safi = 0;
                let mut safi = 0;
                let mut present = 0;
                let mut count = 0;
                botan_call!(
                    botan_x509_ext_ip_addr_blocks_get_family,
                    self.obj,
                    ipv6.into(),
                    i,
                    &mut has_safi,
                    &mut safi,
                    &mut present,
                    &mut count
                )?;
                let safi = if has_safi == 1 { Some(safi) } else { None };

                let mut ranges = None;
                if present == 1 {
                    let mut rg = Vec::with_capacity(count);
                    for entry in 0..count {
                        let (min, max) = call_botan_ffi_returning_vec_pair(
                            size,
                            size,
                            &|min, _, max, out_len| unsafe {
                                botan_x509_ext_ip_addr_blocks_get_address(
                                    self.obj,
                                    ipv6.into(),
                                    i,
                                    entry,
                                    min,
                                    max,
                                    out_len,
                                )
                            },
                        )?;
                        rg.push((min, max))
                    }
                    ranges = Some(rg);
                }

                fn map_ranges<T, F>(
                    ranges: Option<Vec<(Vec<u8>, Vec<u8>)>>,
                    f: F,
                ) -> Option<Vec<(T, T)>>
                where
                    F: Fn(Vec<u8>) -> T,
                {
                    ranges.map(|ranges| ranges.into_iter().map(|(lo, hi)| (f(lo), f(hi))).collect())
                }

                if ipv6 {
                    v6.push((
                        safi,
                        map_ranges(ranges, |v| Ipv6Addr::from(<[u8; 16]>::try_from(v).unwrap())),
                    ));
                } else {
                    v4.push((
                        safi,
                        map_ranges(ranges, |v| Ipv4Addr::from(<[u8; 4]>::try_from(v).unwrap())),
                    ))
                }
            }
        }

        Ok((v4, v6))
    }

    #[cfg(botan_ffi_20260811)]
    fn ext_as_blocks_impl(&self, asnum: bool) -> Result<Option<Vec<(u32, u32)>>> {
        let mut present = 0;
        let mut count = 0;
        botan_call!(
            botan_x509_ext_as_blocks_get_info,
            self.obj,
            asnum.into(),
            &mut present,
            &mut count
        )?;
        if present == 0 {
            return Ok(None);
        }

        let mut values = Vec::with_capacity(count);
        for i in 0..count {
            let mut min = 0;
            let mut max = 0;
            botan_call!(
                botan_x509_ext_as_blocks_get_entry_at,
                self.obj,
                asnum.into(),
                i,
                &mut min,
                &mut max
            )?;
            values.push((min, max));
        }

        Ok(Some(values))
    }

    /// Get values from the AS Blocks extension.
    /// If the extension is not present or AS numbers are not present in the extension, this will return `Err`.
    ///
    /// Returns all AS numbers contained in the extension.
    /// Each tuple in the vector are the minimum and maximum values of a range respectively.
    /// If AS numbers are marked as "inherit", `None` is returned instead.
    #[cfg(botan_ffi_20260811)]
    pub fn ext_as_blocks_asnum(&self) -> Result<Option<Vec<(u32, u32)>>> {
        self.ext_as_blocks_impl(true)
    }

    /// Get values from the AS Blocks extension.
    /// If the extension is not present or RDIs are not present in the extension, this will return `Err`.
    ///
    /// Returns all RDIs contained in the extension.
    /// Each tuple in the vector are the minimum and maximum values of a range respectively.
    /// If RDIs are marked as "inherit", `None` is returned instead.
    #[cfg(botan_ffi_20260811)]
    pub fn ext_as_blocks_rdi(&self) -> Result<Option<Vec<(u32, u32)>>> {
        self.ext_as_blocks_impl(false)
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
        self.verify_with_crl(
            intermediates,
            trusted,
            trusted_path,
            hostname,
            reference_time,
            &[],
        )
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
        let intermediates_h = intermediates.iter().map(|t| t.handle()).collect::<Vec<_>>();
        let crls_h = crls.iter().map(|t| t.handle()).collect::<Vec<_>>();

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
}
