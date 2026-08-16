use crate::utils::*;
use botan_sys::*;
use core::cmp::Ordering;

#[derive(Debug)]
/// ASN.1 object identifier
///
/// Creating this object requires Botan 3.8 or later; with older versions
/// an error of type [`ErrorType::NotImplemented`](crate::ErrorType::NotImplemented) is returned
pub struct OID {
    obj: botan_asn1_oid_t,
}

unsafe impl Sync for OID {}
unsafe impl Send for OID {}

botan_impl_drop!(OID, botan_oid_destroy);

impl OID {
    pub(crate) fn handle(&self) -> botan_asn1_oid_t {
        self.obj
    }

    pub(crate) fn from_handle(obj: botan_asn1_oid_t) -> Result<Self> {
        Ok(Self { obj })
    }

    /// Create an OID from a string
    ///
    /// This can be either a dotted decimal ("1.2.3.4") or a name
    pub fn from_str(s: &str) -> Result<Self> {
        let obj = botan_init!(botan_oid_from_string, make_cstr(s)?.as_ptr())?;
        Ok(Self { obj })
    }

    /// Register a new named OID to the internal state
    pub fn register(oid: &Self, name: &str) -> Result<()> {
        botan_call!(botan_oid_register, oid.obj, make_cstr(name)?.as_ptr())
    }

    /// Return the OID formatted as a dotted decimal
    pub fn as_string(&self) -> Result<String> {
        botan_view_str!(botan_oid_view_string, self.obj)
    }

    /// Return the OID formatted as a name
    pub fn as_name(&self) -> Result<String> {
        botan_view_str!(botan_oid_view_name, self.obj)
    }

    /// Compare two OIDs for equality
    pub fn equals(&self, other: &Self) -> Result<bool> {
        botan_bool_in_rc!(botan_oid_equal, self.obj, other.obj)
    }

    /// Compare two OIDs with an arbitrary ordering
    pub fn compare(&self, other: &Self) -> Result<Ordering> {
        let mut r = 0;

        botan_call!(botan_oid_cmp, &mut r, self.obj, other.obj)?;

        match r {
            -1 => Ok(Ordering::Less),
            0 => Ok(Ordering::Equal),
            1 => Ok(Ordering::Greater),
            r => Err(Error::with_message(
                ErrorType::ConversionError,
                format!("Unexpected botan_oid_cmp result {r}"),
            )),
        }
    }
}

impl PartialOrd for OID {
    fn partial_cmp(&self, other: &OID) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for OID {
    fn eq(&self, other: &OID) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for OID {}

impl Ord for OID {
    fn cmp(&self, other: &OID) -> Ordering {
        self.compare(other).expect("botan_oid_cmp should succeed")
    }
}
