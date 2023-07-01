use crate::utils::*;
use botan_sys::*;

#[derive(Debug)]
/// X.509 certificate revocation list
///
/// Warning: as of the current version you cannot do much useful
/// operations with CRLs, due to limitations of the API currently
/// exported by the C++ library
pub struct CRL {
    obj: botan_x509_crl_t,
}

unsafe impl Sync for CRL {}
unsafe impl Send for CRL {}

botan_impl_drop!(CRL, botan_x509_crl_destroy);

impl CRL {
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
}
