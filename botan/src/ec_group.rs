use crate::{MPI, utils::*};
use botan_sys::*;

use crate::OID;

use crate::EcPoint;

#[derive(Debug)]
/// An elliptic curve group
///
/// Creating this object requires Botan 3.8 or later; with older versions
/// an error of type [`ErrorType::NotImplemented`](crate::ErrorType::NotImplemented) is returned
pub struct EcGroup {
    obj: botan_ec_group_t,
}

unsafe impl Sync for EcGroup {}
unsafe impl Send for EcGroup {}

botan_impl_drop!(EcGroup, botan_ec_group_destroy);

impl EcGroup {
    pub(crate) fn handle(&self) -> botan_ec_group_t {
        self.obj
    }

    #[allow(dead_code)]
    pub(crate) fn from_handle(obj: botan_ec_group_t) -> Self {
        Self { obj }
    }

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

    /// Unregister a previously registered group.
    ///
    /// Using this is discouraged for normal use. This is only useful or necessary if
    /// you are registering a very large number of distinct groups, and need to worry about memory constraints.
    ///
    /// Returns true if the group was found and unregistered.
    ///
    /// This requires Botan 3.11 or later; with older versions an error of type
    /// [`ErrorType::NotImplemented`](crate::ErrorType::NotImplemented) is returned
    pub fn unregister(oid: &OID) -> Result<bool> {
        botan_bool_in_rc!(botan_ec_group_unregister, oid.handle())
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
        botan_view_vec!(botan_ec_group_view_der, self.obj)
    }

    /// Return the PEM encoding of the group
    pub fn pem(&self) -> Result<String> {
        botan_view_str!(botan_ec_group_view_pem, self.obj)
    }

    /// Return the group's parameter p
    pub fn p(&self) -> Result<MPI> {
        MPI::from_handle(botan_init!(botan_ec_group_get_p, self.obj)?)
    }

    /// Return the group's parameter a
    pub fn a(&self) -> Result<MPI> {
        MPI::from_handle(botan_init!(botan_ec_group_get_a, self.obj)?)
    }

    /// Return the group's parameter b
    pub fn b(&self) -> Result<MPI> {
        MPI::from_handle(botan_init!(botan_ec_group_get_b, self.obj)?)
    }

    /// Return the group's order
    pub fn order(&self) -> Result<MPI> {
        MPI::from_handle(botan_init!(botan_ec_group_get_order, self.obj)?)
    }

    /// Return the group's generator x coordinate
    pub fn g_x(&self) -> Result<MPI> {
        MPI::from_handle(botan_init!(botan_ec_group_get_g_x, self.obj)?)
    }

    /// Return the group's generator y coordinate
    pub fn g_y(&self) -> Result<MPI> {
        MPI::from_handle(botan_init!(botan_ec_group_get_g_y, self.obj)?)
    }

    /// Return the group's object identifier
    pub fn oid(&self) -> Result<OID> {
        OID::from_handle(botan_init!(botan_ec_group_get_curve_oid, self.obj)?)
    }

    /// Return the group's identity element
    ///
    /// This requires Botan 3.12 or later; with older versions an error of type
    /// [`ErrorType::NotImplemented`](crate::ErrorType::NotImplemented) is returned
    pub fn identity(&self) -> Result<EcPoint> {
        EcPoint::identity(self)
    }

    /// Return the group's generator element
    ///
    /// This requires Botan 3.12 or later; with older versions an error of type
    /// [`ErrorType::NotImplemented`](crate::ErrorType::NotImplemented) is returned
    pub fn generator(&self) -> Result<EcPoint> {
        EcPoint::generator(self)
    }

    /// Check two groups for equality
    pub fn equals(&self, other: &Self) -> Result<bool> {
        botan_bool_in_rc!(botan_ec_group_equal, self.obj, other.obj)
    }
}

impl PartialEq for EcGroup {
    fn eq(&self, other: &EcGroup) -> bool {
        self.equals(other)
            .expect("botan_ec_group_equal should succeed")
    }
}

impl Eq for EcGroup {}
