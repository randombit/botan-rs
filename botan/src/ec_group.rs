use crate::{utils::*, MPI};
use botan_sys::*;

#[cfg(botan_ffi_20250506)]
use crate::OID;

#[cfg(botan_ffi_20250506)]
#[derive(Debug)]
/// An elliptic curve group
pub struct EcGroup {
    obj: botan_ec_group_t,
}

#[cfg(botan_ffi_20250506)]
unsafe impl Sync for EcGroup {}
#[cfg(botan_ffi_20250506)]
unsafe impl Send for EcGroup {}

#[cfg(botan_ffi_20250506)]
botan_impl_drop!(EcGroup, botan_ec_group_destroy);

#[cfg(botan_ffi_20250506)]
impl EcGroup {
    /// Does this build configuration support application specific groups
    pub fn supports_application_specific_groups() -> Result<bool> {
        let mut result = 0;
        botan_call!(
            botan_ec_group_supports_application_specific_group,
            &mut result
        )?;
        interp_as_bool(
            result,
            "botan_ec_group_supports_appplication_specific_group",
        )
    }

    /// Check if a specific named group is supported
    pub fn supports_named_group(name: &str) -> Result<bool> {
        let mut result = 0;
        let name = make_cstr(name)?;
        botan_call!(
            botan_ec_group_supports_named_group,
            name.as_ptr(),
            &mut result
        )?;
        interp_as_bool(result, "botan_ec_group_supports_named_group")
    }

    /// Create a group from a named/well known set of parameters
    pub fn from_name(name: &str) -> Result<Self> {
        let obj = botan_init!(botan_ec_group_from_name, make_cstr(name)?.as_ptr())?;
        Ok(Self { obj })
    }

    /// Create a group from a named/well known set of parameters
    pub fn from_oid(oid: &OID) -> Result<Self> {
        let obj = botan_init!(botan_ec_group_from_oid, oid.handle())?;
        Ok(Self { obj })
    }

    /// Parse the PEM encoding of an EC group
    pub fn from_pem(pem: &str) -> Result<Self> {
        let obj = botan_init!(botan_ec_group_from_pem, make_cstr(pem)?.as_ptr())?;
        Ok(Self { obj })
    }

    /// Parse the DER encoding of an EC group
    pub fn from_der(ber: &[u8]) -> Result<Self> {
        let obj = botan_init!(botan_ec_group_from_ber, ber.as_ptr(), ber.len())?;
        Ok(Self { obj })
    }

    /// Initial an EcGroup from a custom set of parameters
    ///
    /// # Warning
    ///
    /// Do not use this unless you know what you are doing
    pub fn from_params(
        oid: &OID,
        p: &MPI,
        a: &MPI,
        b: &MPI,
        g_x: &MPI,
        g_y: &MPI,
        order: &MPI,
    ) -> Result<Self> {
        let obj = botan_init!(
            botan_ec_group_from_params,
            oid.handle(),
            p.handle(),
            a.handle(),
            b.handle(),
            g_x.handle(),
            g_y.handle(),
            order.handle()
        )?;
        Ok(Self { obj })
    }

    /// Return the DER encoding of the group
    pub fn der(&self) -> Result<Vec<u8>> {
        call_botan_ffi_viewing_vec_u8(&|ctx, cb| unsafe {
            botan_ec_group_view_der(self.obj, ctx, cb)
        })
    }

    /// Return the PEM encoding of the group
    pub fn pem(&self) -> Result<String> {
        call_botan_ffi_viewing_str_fn(&|ctx, cb| unsafe {
            botan_ec_group_view_pem(self.obj, ctx, cb)
        })
    }

    /// Return the groups parameter p
    pub fn p(&self) -> Result<MPI> {
        MPI::from_handle(botan_init!(botan_ec_group_get_p, self.obj)?)
    }

    /// Return the groups parameter a
    pub fn a(&self) -> Result<MPI> {
        MPI::from_handle(botan_init!(botan_ec_group_get_a, self.obj)?)
    }

    /// Return the groups parameter b
    pub fn b(&self) -> Result<MPI> {
        MPI::from_handle(botan_init!(botan_ec_group_get_b, self.obj)?)
    }

    /// Return the groups order
    pub fn order(&self) -> Result<MPI> {
        MPI::from_handle(botan_init!(botan_ec_group_get_order, self.obj)?)
    }

    /// Return the groups generator x coordinate
    pub fn g_x(&self) -> Result<MPI> {
        MPI::from_handle(botan_init!(botan_ec_group_get_g_x, self.obj)?)
    }

    /// Return the groups generator y coordinate
    pub fn g_y(&self) -> Result<MPI> {
        MPI::from_handle(botan_init!(botan_ec_group_get_g_y, self.obj)?)
    }

    /// Return the groups object identifier
    pub fn oid(&self) -> Result<OID> {
        OID::from_handle(botan_init!(botan_ec_group_get_curve_oid, self.obj)?)
    }

    /// Check two groups for equality
    pub fn equals(&self, other: &Self) -> Result<bool> {
        botan_bool_in_rc!(botan_ec_group_equal, self.obj, other.obj)
    }
}

#[cfg(botan_ffi_20250506)]
impl PartialEq for EcGroup {
    fn eq(&self, other: &EcGroup) -> bool {
        self.equals(other)
            .expect("botan_ec_group_equal should succeed")
    }
}

#[cfg(botan_ffi_20250506)]
impl Eq for EcGroup {}
