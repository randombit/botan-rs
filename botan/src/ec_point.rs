use crate::{MPI, RandomNumberGenerator, utils::*};
use botan_sys::*;
use core::ops::Add;

use crate::EcGroup;

#[derive(Debug)]
/// An Integer modulo the prime group order of an elliptic curve
///
/// Creating this object requires Botan 3.12 or later; with older versions
/// an error of type [`ErrorType::NotImplemented`](crate::ErrorType::NotImplemented) is returned
pub struct EcScalar {
    obj: botan_ec_scalar_t,
}

unsafe impl Sync for EcScalar {}
unsafe impl Send for EcScalar {}

botan_impl_drop!(EcScalar, botan_ec_scalar_destroy);

impl EcScalar {
    pub(crate) fn handle(&self) -> botan_ec_scalar_t {
        self.obj
    }

    pub(crate) fn from_handle(obj: botan_ec_scalar_t) -> Self {
        Self { obj }
    }

    /// Create a new scalar with a random value
    pub fn random(group: &EcGroup, rng: &mut RandomNumberGenerator) -> Result<Self> {
        let obj = botan_init!(botan_ec_scalar_random, group.handle(), rng.handle())?;
        Ok(Self { obj })
    }

    /// Convert from an MPI to a scalar, fails if the MPI is negative or too large
    pub fn from_mpi(group: &EcGroup, mpi: &MPI) -> Result<Self> {
        let obj = botan_init!(botan_ec_scalar_from_mp, group.handle(), mpi.handle())?;
        Ok(Self { obj })
    }

    /// Convert from a scalar to an MPI
    pub fn to_mpi(&self) -> Result<MPI> {
        let obj = botan_init_at!(botan_ec_scalar_to_mp, self.obj;)?;
        MPI::from_handle(obj)
    }
}

#[derive(Debug)]
/// An elliptic curve point
///
/// Creating this object requires Botan 3.12 or later; with older versions
/// an error of type [`ErrorType::NotImplemented`](crate::ErrorType::NotImplemented) is returned
pub struct EcPoint {
    obj: botan_ec_point_t,
}

unsafe impl Sync for EcPoint {}
unsafe impl Send for EcPoint {}

botan_impl_drop!(EcPoint, botan_ec_point_destroy);

impl EcPoint {
    pub(crate) fn handle(&self) -> botan_ec_point_t {
        self.obj
    }

    /// Create a point set to the group identity
    pub fn identity(group: &EcGroup) -> Result<Self> {
        let obj = botan_init!(botan_ec_point_identity, group.handle())?;
        Ok(Self { obj })
    }

    /// Create a point set to the group generator
    pub fn generator(group: &EcGroup) -> Result<Self> {
        let obj = botan_init!(botan_ec_point_generator, group.handle())?;
        Ok(Self { obj })
    }

    /// Create a point from a set of (x,y) integers
    /// The integers must be within the field and must satisfy the curve equation
    pub fn from_xy(group: &EcGroup, x: &MPI, y: &MPI) -> Result<Self> {
        let obj = botan_init!(
            botan_ec_point_from_xy,
            group.handle(),
            x.handle(),
            y.handle()
        )?;
        Ok(Self { obj })
    }

    /// Create a point from a SEC1 compressed or uncompressed format
    pub fn from_bytes(group: &EcGroup, bytes: &[u8]) -> Result<Self> {
        let obj = botan_init!(
            botan_ec_point_from_bytes,
            group.handle(),
            bytes.as_ptr(),
            bytes.len()
        )?;
        Ok(Self { obj })
    }

    /// Check if this point is the group identity
    pub fn is_identity(&self) -> Result<bool> {
        botan_bool_in_rc!(botan_ec_point_is_identity, self.obj)
    }

    /// Check if this point and another one are equal
    pub fn is_equal(&self, other: &EcPoint) -> Result<bool> {
        botan_bool_in_rc!(botan_ec_point_equal, self.obj, other.obj)
    }

    /// Create a new point with the negated value of this one
    pub fn negate(&self) -> Result<EcPoint> {
        let obj = botan_init!(botan_ec_point_negate, self.obj)?;
        Ok(Self { obj })
    }

    /// Add another point to this one, creating a new point
    pub fn pt_add(&self, other: &EcPoint) -> Result<EcPoint> {
        let obj = botan_init!(botan_ec_point_add, self.obj, other.handle())?;
        Ok(Self { obj })
    }

    /// Multiply this point by a scalar, creating a new point
    pub fn mul(&self, scalar: &EcScalar, rng: &mut RandomNumberGenerator) -> Result<Self> {
        let obj = botan_init!(botan_ec_point_mul, self.obj, scalar.handle(), rng.handle())?;
        Ok(Self { obj })
    }

    /// Get the fixed length encoding of the affine x coordinate
    pub fn to_x_bytes(&self) -> Result<Vec<u8>> {
        botan_view_vec!(botan_ec_point_view_x_bytes, self.obj)
    }

    /// Get the fixed length encoding of the affine y coordinate
    pub fn to_y_bytes(&self) -> Result<Vec<u8>> {
        botan_view_vec!(botan_ec_point_view_y_bytes, self.obj)
    }

    /// Get the fixed length encoding of the affine x and y coordinates
    pub fn to_xy_bytes(&self) -> Result<Vec<u8>> {
        botan_view_vec!(botan_ec_point_view_xy_bytes, self.obj)
    }

    /// Get the fixed length SEC1 uncompressed encoding
    pub fn to_uncompressed(&self) -> Result<Vec<u8>> {
        botan_view_vec!(botan_ec_point_view_uncompressed, self.obj)
    }

    /// Get the fixed length SEC1 compressed encoding
    pub fn to_compressed(&self) -> Result<Vec<u8>> {
        botan_view_vec!(botan_ec_point_view_compressed, self.obj)
    }
}

impl PartialEq for EcPoint {
    fn eq(&self, other: &Self) -> bool {
        self.is_equal(other)
            .expect("botan_ec_point_equal should succeed")
    }
}

impl Eq for EcPoint {}

impl<'b> Add<&'b EcPoint> for &EcPoint {
    type Output = EcPoint;

    fn add(self, other: &'b EcPoint) -> Self::Output {
        self.pt_add(other)
            .expect("botan_ec_point_add should succeed")
    }
}

impl Add<&EcPoint> for EcPoint {
    type Output = EcPoint;

    fn add(self, other: &EcPoint) -> EcPoint {
        (&self).add(other)
    }
}

impl Add<EcPoint> for &EcPoint {
    type Output = EcPoint;

    fn add(self, other: EcPoint) -> EcPoint {
        self.add(&other)
    }
}

impl Add<EcPoint> for EcPoint {
    type Output = EcPoint;

    fn add(self, other: EcPoint) -> EcPoint {
        (&self).add(&other)
    }
}
