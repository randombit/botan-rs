use crate::utils::*;
use botan_sys::*;
use core::cmp::Ordering;

#[cfg(botan_ffi_20250506)]
#[derive(Debug)]
/// ASN.1 object identifier
pub struct OID {
    obj: botan_asn1_oid_t,
}

#[cfg(botan_ffi_20250506)]
unsafe impl Sync for OID {}
#[cfg(botan_ffi_20250506)]
unsafe impl Send for OID {}

#[cfg(botan_ffi_20250506)]
botan_impl_drop!(OID, botan_oid_destroy);

#[cfg(botan_ffi_20250506)]
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
        call_botan_ffi_viewing_str_fn(&|ctx, cb| unsafe {
            botan_oid_view_string(self.obj, ctx, cb)
        })
    }

    /// Return the OID formatted as a name
    pub fn as_name(&self) -> Result<String> {
        call_botan_ffi_viewing_str_fn(&|ctx, cb| unsafe { botan_oid_view_name(self.obj, ctx, cb) })
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

#[cfg(botan_ffi_20250506)]
impl PartialOrd for OID {
    fn partial_cmp(&self, other: &OID) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(botan_ffi_20250506)]
impl PartialEq for OID {
    fn eq(&self, other: &OID) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

#[cfg(botan_ffi_20250506)]
impl Eq for OID {}

#[cfg(botan_ffi_20250506)]
impl Ord for OID {
    fn cmp(&self, other: &OID) -> Ordering {
        self.compare(other).expect("botan_oid_cmp should succeed")
    }
}
