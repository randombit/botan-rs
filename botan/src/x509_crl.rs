use crate::{utils::*, Pubkey};
#[cfg(botan_ffi_20260303)]
use crate::{Certificate, Privkey, RandomNumberGenerator, MPI};
use botan_sys::*;

#[derive(Debug)]
/// X.509 certificate revocation list
pub struct CRL {
    obj: botan_x509_crl_t,
}

unsafe impl Sync for CRL {}
unsafe impl Send for CRL {}

botan_impl_drop!(CRL, botan_x509_crl_destroy);

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

    #[cfg(botan_ffi_20260303)]
    /// Create a new CRL without entries
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

    #[cfg(botan_ffi_20260303)]
    #[allow(clippy::too_many_arguments)]
    /// Add new entries to the CRL, does not modify the CRL in place
    pub fn revoke(
        &self,
        rng: &mut RandomNumberGenerator,
        ca_cert: &Certificate,
        ca_key: &Privkey,
        issue_time: u64,
        next_update: u32,
        new_entries: &[&CRLEntry],
        hash_fn: Option<&str>,
        padding: Option<&str>,
    ) -> Result<Self> {
        let hash_fn = make_optional_cstr(hash_fn)?;
        let padding = make_optional_cstr(padding)?;

        let mut new_entries_h = Vec::new();
        for c in new_entries {
            new_entries_h.push(c.handle());
        }

        let obj = botan_init!(
            botan_x509_crl_update,
            self.obj,
            rng.handle(),
            ca_cert.handle(),
            ca_key.handle(),
            issue_time,
            next_update,
            new_entries_h.as_ptr(),
            new_entries_h.len(),
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

    #[cfg(botan_ffi_20260303)]
    /// Get all the entries listed in this CRL.
    pub fn revoked(&self) -> Result<Vec<CRLEntry>> {
        let mut entries = Vec::new();
        let mut count = 0;
        botan_call!(botan_x509_crl_entries_count, self.obj, &mut count)?;
        for i in 0..count {
            let obj = botan_init_at!(
                botan_x509_crl_entries,
                self.obj,
                i
                ;
            )?;
            entries.push(CRLEntry { obj })
        }

        Ok(entries)
    }

    /// Verify the signature of this CRL against a public key.
    #[cfg(botan_ffi_20260303)]
    pub fn verify(&self, key: &Pubkey) -> Result<bool> {
        let res = botan_bool_in_rc!(botan_x509_crl_verify_signature, self.obj, key.handle())?;
        Ok(res)
    }

    /// Get the PEM encoding of this CRL
    #[cfg(botan_ffi_20260303)]
    pub fn pem_encode(&self) -> Result<String> {
        call_botan_ffi_viewing_str_fn(&|ctx, cb| unsafe {
            botan_x509_crl_view_string_values(
                self.obj,
                X509ValueType::BOTAN_X509_PEM_ENCODING as i32,
                0,
                ctx,
                cb,
            )
        })
    }

    /// Get the DER encoding of this CRL
    #[cfg(botan_ffi_20260303)]
    pub fn der_encode(&self) -> Result<Vec<u8>> {
        call_botan_ffi_viewing_vec_u8(&|ctx, cb| unsafe {
            botan_x509_crl_view_binary_values(
                self.obj,
                X509ValueType::BOTAN_X509_DER_ENCODING as i32,
                0,
                ctx,
                cb,
            )
        })
    }
}

/// Reason a certificate was revoked for
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg(botan_ffi_20260303)]
#[allow(missing_docs)]
pub enum CRLReason {
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

#[cfg(botan_ffi_20260303)]
impl From<X509CrlReasonCode> for CRLReason {
    fn from(value: X509CrlReasonCode) -> Self {
        match value {
            X509CrlReasonCode::BOTAN_CRL_ENTRY_UNSPECIFIED => CRLReason::Unspecified,
            X509CrlReasonCode::BOTAN_CRL_ENTRY_KEY_COMPROMISE => CRLReason::KeyCompromise,
            X509CrlReasonCode::BOTAN_CRL_ENTRY_CA_COMPROMISE => CRLReason::CaCompromise,
            X509CrlReasonCode::BOTAN_CRL_ENTRY_AFFILIATION_CHANGED => CRLReason::AffiliationChanged,
            X509CrlReasonCode::BOTAN_CRL_ENTRY_SUPERSEDED => CRLReason::Superseded,
            X509CrlReasonCode::BOTAN_CRL_ENTRY_CESSATION_OF_OPERATION => {
                CRLReason::CessationOfOperation
            }
            X509CrlReasonCode::BOTAN_CRL_ENTRY_CERTIFICATE_HOLD => CRLReason::CertificateHold,
            X509CrlReasonCode::BOTAN_CRL_ENTRY_REMOVE_FROM_CRL => CRLReason::RemoveFromCrl,
            X509CrlReasonCode::BOTAN_CRL_ENTRY_PRIVILEGE_WITHDRAWN => CRLReason::PrivilegeWithdrawn,
            X509CrlReasonCode::BOTAN_CRL_ENTRY_AA_COMPROMISE => CRLReason::AaCompromise,
        }
    }
}

#[cfg(botan_ffi_20260303)]
impl From<CRLReason> for X509CrlReasonCode {
    fn from(value: CRLReason) -> Self {
        match value {
            CRLReason::Unspecified => X509CrlReasonCode::BOTAN_CRL_ENTRY_UNSPECIFIED,
            CRLReason::KeyCompromise => X509CrlReasonCode::BOTAN_CRL_ENTRY_KEY_COMPROMISE,
            CRLReason::CaCompromise => X509CrlReasonCode::BOTAN_CRL_ENTRY_CA_COMPROMISE,
            CRLReason::AffiliationChanged => X509CrlReasonCode::BOTAN_CRL_ENTRY_AFFILIATION_CHANGED,
            CRLReason::Superseded => X509CrlReasonCode::BOTAN_CRL_ENTRY_SUPERSEDED,
            CRLReason::CessationOfOperation => {
                X509CrlReasonCode::BOTAN_CRL_ENTRY_CESSATION_OF_OPERATION
            }
            CRLReason::CertificateHold => X509CrlReasonCode::BOTAN_CRL_ENTRY_CERTIFICATE_HOLD,
            CRLReason::RemoveFromCrl => X509CrlReasonCode::BOTAN_CRL_ENTRY_REMOVE_FROM_CRL,
            CRLReason::PrivilegeWithdrawn => X509CrlReasonCode::BOTAN_CRL_ENTRY_PRIVILEGE_WITHDRAWN,
            CRLReason::AaCompromise => X509CrlReasonCode::BOTAN_CRL_ENTRY_AA_COMPROMISE,
        }
    }
}

#[cfg(botan_ffi_20260303)]
#[derive(Debug)]
/// X.509 certificate revocation entry
pub struct CRLEntry {
    obj: botan_x509_crl_entry_t,
}

#[cfg(botan_ffi_20260303)]
unsafe impl Sync for CRLEntry {}

#[cfg(botan_ffi_20260303)]
unsafe impl Send for CRLEntry {}

#[cfg(botan_ffi_20260303)]
botan_impl_drop!(CRLEntry, botan_x509_crl_entry_destroy);

#[cfg(botan_ffi_20260303)]
impl CRLEntry {
    pub(crate) fn handle(&self) -> botan_x509_crl_entry_t {
        self.obj
    }

    /// Create a new CRL entry
    pub fn new(cert: &Certificate, reason: CRLReason) -> Result<Self> {
        let obj = botan_init!(
            botan_x509_crl_entry_create,
            cert.handle(),
            X509CrlReasonCode::from(reason) as i32
        )?;
        Ok(Self { obj })
    }

    /// Get the serial number of the revoked certificate
    pub fn serial_number(&self) -> Result<MPI> {
        let obj = botan_init_at!(botan_x509_crl_entry_serial_number, self.obj ;)?;
        MPI::from_handle(obj)
    }

    /// Get the revocation date for the revoked certificate, as seconds since the UNIX epoch
    pub fn revocation_date(&self) -> Result<u64> {
        let mut time = 0;
        botan_call!(botan_x509_crl_entry_revocation_date, self.obj, &mut time)?;
        Ok(time)
    }

    /// Get the reason this certificate was revoked
    pub fn reason(&self) -> Result<CRLReason> {
        let mut reason = 0;
        botan_call!(botan_x509_crl_entry_reason, self.obj, &mut reason)?;
        Ok(X509CrlReasonCode::try_from(reason)
            .map_err(|_| {
                Error::with_message(
                    ErrorType::InternalError,
                    "Unexpected CRL reason code".to_string(),
                )
            })?
            .into())
    }
}
