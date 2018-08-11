
use botan_sys::*;
use utils::*;

use pubkey::Pubkey;

#[derive(Debug)]
pub struct Certificate {
    obj: botan_x509_cert_t
}

impl Drop for Certificate {
    fn drop(&mut self) {
        unsafe { botan_x509_cert_destroy(self.obj) };
    }
}

impl Certificate {

    pub fn load(data: &[u8]) -> Result<Certificate> {
        let mut obj = ptr::null_mut();
        call_botan! { botan_x509_cert_load(&mut obj, data.as_ptr(), data.len()) };
        Ok(Certificate { obj })
    }

    pub fn from_file(fsname: &str) -> Result<Certificate> {
        let fsname = CString::new(fsname).unwrap();

        let mut obj = ptr::null_mut();
        call_botan! { botan_x509_cert_load_file(&mut obj, fsname.as_ptr()) };
        Ok(Certificate { obj })
    }

    pub fn serial_number(&self) -> Result<Vec<u8>> {
        let sn_len = 32; // PKIX upper bound is 20
        call_botan_ffi_returning_vec_u8(sn_len, &|out_buf, out_len| {
            unsafe { botan_x509_cert_get_serial_number(self.obj, out_buf, out_len) }
        })
    }

    pub fn fingerprint(&self, hash: &str) -> Result<Vec<u8>> {
        let fprint_len = 128;
        let hash = CString::new(hash).unwrap();
        call_botan_ffi_returning_vec_u8(fprint_len, &|out_buf, out_len| {
            unsafe { botan_x509_cert_get_fingerprint(self.obj, hash.as_ptr(), out_buf, out_len) }
        })
    }

    pub fn authority_key_id(&self) -> Result<Vec<u8>> {
        let akid_len = 32;
        call_botan_ffi_returning_vec_u8(akid_len, &|out_buf, out_len| {
            unsafe { botan_x509_cert_get_authority_key_id(self.obj, out_buf, out_len) }
        })
    }

    pub fn subject_key_id(&self) -> Result<Vec<u8>> {
        let skid_len = 32;
        call_botan_ffi_returning_vec_u8(skid_len, &|out_buf, out_len| {
            unsafe { botan_x509_cert_get_subject_key_id(self.obj, out_buf, out_len) }
        })
    }

    pub fn public_key_bits(&self) -> Result<Vec<u8>> {
        let pk_len = 4096; // fixme
        call_botan_ffi_returning_vec_u8(pk_len, &|out_buf, out_len| {
            unsafe { botan_x509_cert_get_public_key_bits(self.obj, out_buf, out_len) }
        })
    }

    pub fn public_key(&self) -> Result<Pubkey> {
        let mut key = ptr::null_mut();
        call_botan! { botan_x509_cert_get_public_key(self.obj, &mut key) };
        Ok(Pubkey::from_handle(key))
    }

    pub fn to_string(&self) -> Result<String> {
        let as_str_len = 4096;
        call_botan_ffi_returning_string(as_str_len, &|out_buf, out_len| {
            unsafe { botan_x509_cert_to_string(self.obj, out_buf as *mut c_char, out_len) }
        })
    }

    pub fn matches_hostname(&self, hostname: &str) -> Result<bool> {
        let hostname = CString::new(hostname).unwrap();
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
