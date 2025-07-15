use crate::utils::*;
#[cfg(botan_ffi_20251104)]
use crate::{Certificate, Privkey, Pubkey, RandomNumberGenerator, MPI};
use botan_sys::*;

#[derive(Debug)]
/// X.509 certificate revocation list
pub struct CRL {
    obj: botan_x509_crl_t,
}

unsafe impl Sync for CRL {}
unsafe impl Send for CRL {}

botan_impl_drop!(CRL, botan_x509_crl_destroy);

#[cfg(botan_ffi_20251104)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CrlReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
}

#[cfg(botan_ffi_20251104)]
impl From<X509CrlCode> for CrlReason {
    fn from(value: X509CrlCode) -> Self {
        match value {
            X509CrlCode::UNSPECIFIED => CrlReason::Unspecified,
            X509CrlCode::KEY_COMPROMISE => CrlReason::KeyCompromise,
            X509CrlCode::CA_COMPROMISE => CrlReason::CaCompromise,
            X509CrlCode::AFFILIATION_CHANGED => CrlReason::AffiliationChanged,
            X509CrlCode::SUPERSEDED => CrlReason::Superseded,
            X509CrlCode::CESSATION_OF_OPERATION => CrlReason::CessationOfOperation,
            X509CrlCode::CERTIFICATE_HOLD => CrlReason::CertificateHold,
            X509CrlCode::REMOVE_FROM_CRL => CrlReason::RemoveFromCrl,
            X509CrlCode::PRIVILIGE_WITHDRAWN => CrlReason::PrivilegeWithdrawn,
            X509CrlCode::AA_COMPROMISE => CrlReason::AaCompromise,
        }
    }
}

#[cfg(botan_ffi_20251104)]
impl From<CrlReason> for X509CrlCode {
    fn from(value: CrlReason) -> Self {
        match value {
            CrlReason::Unspecified => X509CrlCode::UNSPECIFIED,
            CrlReason::KeyCompromise => X509CrlCode::KEY_COMPROMISE,
            CrlReason::CaCompromise => X509CrlCode::CA_COMPROMISE,
            CrlReason::AffiliationChanged => X509CrlCode::AFFILIATION_CHANGED,
            CrlReason::Superseded => X509CrlCode::SUPERSEDED,
            CrlReason::CessationOfOperation => X509CrlCode::CESSATION_OF_OPERATION,
            CrlReason::CertificateHold => X509CrlCode::CERTIFICATE_HOLD,
            CrlReason::RemoveFromCrl => X509CrlCode::REMOVE_FROM_CRL,
            CrlReason::PrivilegeWithdrawn => X509CrlCode::PRIVILIGE_WITHDRAWN,
            CrlReason::AaCompromise => X509CrlCode::AA_COMPROMISE,
        }
    }
}

#[cfg(botan_ffi_20251104)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlEntry {
    pub serial: MPI,
    pub expire_time: u64,
    pub reason: CrlReason,
}

impl CRL {
    pub(crate) fn handle(&self) -> botan_x509_crl_t {
        self.obj
    }

    /// Load a X.509 CRL from DER or PEM representation
    pub fn load(data: &[u8]) -> Result<Self> {
        let obj = botan_init!(botan_x509_crl_load, data.as_ptr(), data.len())?;
        Ok(Self { obj })
    }

    /// Read an X.509 CRL from a file
    pub fn from_file(fsname: &str) -> Result<Self> {
        let fsname = make_cstr(fsname)?;
        let obj = botan_init!(botan_x509_crl_load_file, fsname.as_ptr())?;
        Ok(Self { obj })
    }

    #[cfg(botan_ffi_20251104)]
    pub fn new(
        rng: &mut RandomNumberGenerator,
        ca_cert: &Certificate,
        ca_key: &Privkey,
        issue_time: u64,
        next_update: u32,
        hash_fn: Option<&str>,
        padding: Option<&str>,
    ) -> Result<Self> {
        let hash_fn = make_optional_cstr(hash_fn)?;
        let padding = make_optional_cstr(padding)?;

        let obj = botan_init!(
            botan_x509_crl_create,
            rng.handle(),
            ca_cert.handle(),
            ca_key.handle(),
            issue_time,
            next_update,
            hash_fn
                .as_ref()
                .map_or(std::ptr::null(), |hash_fn| hash_fn.as_ptr()),
            padding
                .as_ref()
                .map_or(std::ptr::null(), |padding| padding.as_ptr())
        )?;

        Ok(Self { obj })
    }

    #[cfg(botan_ffi_20251104)]
    pub fn revoke(
        &self,
        rng: &mut RandomNumberGenerator,
        ca_cert: &Certificate,
        ca_key: &Privkey,
        issue_time: u64,
        next_update: u32,
        revoked: &[&Certificate],
        reason: CrlReason,
        hash_fn: Option<&str>,
        padding: Option<&str>,
    ) -> Result<Self> {
        let hash_fn = make_optional_cstr(hash_fn)?;
        let padding = make_optional_cstr(padding)?;

        let mut revoked_h = Vec::new();
        for c in revoked {
            revoked_h.push(c.handle());
        }

        let obj = botan_init!(
            botan_x509_crl_update,
            self.obj,
            rng.handle(),
            ca_cert.handle(),
            ca_key.handle(),
            issue_time,
            next_update,
            revoked_h.as_ptr(),
            revoked_h.len(),
            X509CrlCode::from(reason) as u8,
            hash_fn
                .as_ref()
                .map_or(std::ptr::null(), |hash_fn| hash_fn.as_ptr()),
            padding
                .as_ref()
                .map_or(std::ptr::null(), |padding| padding.as_ptr())
        )?;

        Ok(Self { obj })
    }

    /// Return true if the provided CRL is listed as revoked in the CRL
    pub fn is_revoked(&self, cert: &crate::Certificate) -> Result<bool> {
        let rc = unsafe { botan_x509_is_revoked(self.obj, cert.handle()) };

        // Return value of this function is weird!!
        match rc {
            0 => Ok(true),
            -1 => Ok(false),
            _ => Err(Error::from_rc(rc)),
        }
    }

    #[cfg(botan_ffi_20251104)]
    pub fn revoked(&self) -> Result<Vec<CrlEntry>> {
        let mut entries = Vec::new();
        let mut count = 0;
        botan_call!(botan_x509_crl_get_count, self.obj, &mut count)?;
        for i in 0..count {
            let mut expire_time = 0;
            let mut reason = 0;
            let serial = MPI::new()?;
            botan_call!(
                botan_x509_crl_get_entry,
                self.obj,
                i,
                serial.handle(),
                &mut expire_time,
                &mut reason
            )?;
            entries.push(CrlEntry {
                serial,
                expire_time,
                reason: CrlReason::from(X509CrlCode::try_from(reason).map_err(|_| {
                    Error::with_message(
                        ErrorType::InternalError,
                        "Unexpected CRL reason code".to_string(),
                    )
                })?),
            })
        }

        Ok(entries)
    }

    #[cfg(botan_ffi_20251104)]
    pub fn verify(&self, key: &Pubkey) -> Result<bool> {
        let mut result = 0;
        botan_call!(
            botan_x509_crl_verify_signature,
            self.obj,
            key.handle(),
            &mut result
        )?;
        interp_as_bool(result, "botan_x509_crl_verify_signature")
    }

    #[cfg(botan_ffi_20251104)]
    pub fn to_pem(&self) -> Result<String> {
        call_botan_ffi_viewing_str_fn(&|ctx, cb| unsafe {
            botan_x509_crl_view_pem(self.obj, ctx, cb)
        })
    }

    #[cfg(botan_ffi_20251104)]
    pub fn to_der(&self) -> Result<Vec<u8>> {
        call_botan_ffi_viewing_vec_u8(&|ctx, cb| unsafe {
            botan_x509_crl_view_der(self.obj, ctx, cb)
        })
    }
}
