
use botan_sys::*;
use utils::*;

use pubkey::Pubkey;

#[derive(Debug)]
/// X.509 certificate
pub struct Certificate {
    obj: botan_x509_cert_t
}

impl Drop for Certificate {
    fn drop(&mut self) {
        unsafe { botan_x509_cert_destroy(self.obj) };
    }
}

impl Certificate {

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
        call_botan_ffi_returning_vec_u8(sn_len, &|out_buf, out_len| {
            unsafe { botan_x509_cert_get_serial_number(self.obj, out_buf, out_len) }
        })
    }

    /// Return the fingerprint of this certificate
    pub fn fingerprint(&self, hash: &str) -> Result<Vec<u8>> {
        let fprint_len = 128;
        let hash = make_cstr(hash)?;
        call_botan_ffi_returning_vec_u8(fprint_len, &|out_buf, out_len| {
            unsafe { botan_x509_cert_get_fingerprint(self.obj, hash.as_ptr(), out_buf, out_len) }
        })
    }

    /// Return the authority key id, if set
    pub fn authority_key_id(&self) -> Result<Vec<u8>> {
        let akid_len = 32;
        call_botan_ffi_returning_vec_u8(akid_len, &|out_buf, out_len| {
            unsafe { botan_x509_cert_get_authority_key_id(self.obj, out_buf, out_len) }
        })
    }

    /// Return the subject key id, if set
    pub fn subject_key_id(&self) -> Result<Vec<u8>> {
        let skid_len = 32;
        call_botan_ffi_returning_vec_u8(skid_len, &|out_buf, out_len| {
            unsafe { botan_x509_cert_get_subject_key_id(self.obj, out_buf, out_len) }
        })
    }

    /// Return the byte representation of the public key
    pub fn public_key_bits(&self) -> Result<Vec<u8>> {
        let pk_len = 4096; // fixme
        call_botan_ffi_returning_vec_u8(pk_len, &|out_buf, out_len| {
            unsafe { botan_x509_cert_get_public_key_bits(self.obj, out_buf, out_len) }
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
        call_botan_ffi_returning_string(as_str_len, &|out_buf, out_len| {
            unsafe { botan_x509_cert_to_string(self.obj, out_buf as *mut c_char, out_len) }
        })
    }

    /// Return true if the provided hostname is valid for this certificate
    pub fn matches_hostname(&self, hostname: &str) -> Result<bool> {
        let hostname = make_cstr(hostname)?;
        let rc = unsafe { botan_x509_cert_hostname_match(self.obj, hostname.as_ptr()) };

        if rc == 0 {
            Ok(true)
        }
        else if rc == -1 {
            Ok(false)
        }
        else {
            Err(Error::from(rc))
        }
    }
}
