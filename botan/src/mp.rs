use crate::utils::*;
use botan_sys::*;

use crate::rng::RandomNumberGenerator;

use core::cmp::{Eq, Ord, Ordering};
use core::fmt;
use core::str::FromStr;

use core::ops::{
    Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Shl, ShlAssign, Shr,
    ShrAssign, Sub, SubAssign,
};

/// A big integer type
#[allow(clippy::upper_case_acronyms)]
pub struct MPI {
    obj: botan_mp_t,
}

botan_impl_drop!(MPI, botan_mp_destroy);

impl Clone for MPI {
    fn clone(&self) -> MPI {
        self.duplicate().expect("copying MPI object failed")
    }
}

impl MPI {
    pub(crate) fn handle(&self) -> botan_mp_t {
        self.obj
    }

    /// Crate a new (zero-valued) MPI
    pub fn new() -> Result<MPI> {
        let obj = botan_init!(botan_mp_init)?;
        Ok(MPI { obj })
    }

    /// Crate a new MPI setting value from an array of bytes (big-endian)
    pub fn new_from_bytes(val: &[u8]) -> Result<MPI> {
        let mut mpi = MPI::new()?;
        mpi.set_bytes(val)?;
        Ok(mpi)
    }

    /// Crate a new MPI setting value from a i32
    pub fn new_from_i32(val: i32) -> Result<MPI> {
        let mut mpi = MPI::new()?;
        mpi.set_i32(val)?;
        Ok(mpi)
    }

    /// Crate a new MPI setting value from a u32
    pub fn new_from_u32(val: u32) -> Result<MPI> {
        let mut mpi = MPI::new()?;
        mpi.mp_add_u32_assign(val)?;
        Ok(mpi)
    }

    /// Crate a new MPI duplicating the value of self
    pub fn duplicate(&self) -> Result<MPI> {
        let mpi = MPI::new()?;
        botan_call!(botan_mp_set_from_mp, mpi.obj, self.obj)?;
        Ok(mpi)
    }

    /// Set self to value specified with an i32
    pub fn set_i32(&mut self, val: i32) -> Result<()> {
        botan_call!(botan_mp_set_from_int, self.obj, val)
    }

    /// Set self to value specified with a string
    pub fn set_str(&mut self, val: &str) -> Result<()> {
        let cstr = make_cstr(val)?;
        botan_call!(botan_mp_set_from_str, self.obj, cstr.as_ptr())
    }

    /// Set self to value specified with an array of bytes (big-endian)
    pub fn set_bytes(&mut self, val: &[u8]) -> Result<()> {
        botan_call!(botan_mp_from_bin, self.obj, val.as_ptr(), val.len())
    }

    /// Set self to zero
    pub fn clear(&mut self) -> Result<()> {
        botan_call!(botan_mp_clear, self.obj)
    }

    /// Set a specific bit of self
    pub fn set_bit(&mut self, bit: usize) -> Result<()> {
        botan_call!(botan_mp_set_bit, self.obj, bit)
    }

    /// Clear a specific bit of self
    pub fn clear_bit(&mut self, bit: usize) -> Result<()> {
        botan_call!(botan_mp_clear_bit, self.obj, bit)
    }

    /// Return the value of a bit in self
    pub fn get_bit(&self, bit: usize) -> Result<bool> {
        botan_bool_in_rc!(botan_mp_get_bit, self.obj, bit)
    }

    /// Randomize self to an integer of specified bit size
    pub fn randomize(&mut self, rng: &mut RandomNumberGenerator, bits: usize) -> Result<()> {
        botan_call!(botan_mp_rand_bits, self.obj, rng.handle(), bits)
    }

    /// Randomize self to an integer within specified range
    pub fn random_range(
        &mut self,
        rng: &mut RandomNumberGenerator,
        lower: &MPI,
        upper: &MPI,
    ) -> Result<()> {
        botan_call!(
            botan_mp_rand_range,
            self.obj,
            rng.handle(),
            lower.handle(),
            upper.handle()
        )
    }

    /// Return value of self as decimal string
    pub fn to_string(&self) -> Result<String> {
        let bit_count = self.bit_count()? as f64;
        let log_base = core::f64::consts::LOG2_10;
        let bn_digits = 1 + (bit_count / log_base) as usize;

        call_botan_ffi_returning_string(bn_digits, &|out_buf, out_len| unsafe {
            botan_mp_to_str(self.obj, 10, out_buf as *mut c_char, out_len)
        })
    }

    /// Return value of self as hex string
    pub fn to_hex(&self) -> Result<String> {
        let byte_count = self.byte_count()?;

        let mut r =
            call_botan_ffi_returning_string(byte_count * 2 + 1, &|out_buf, out_len| unsafe {
                botan_mp_to_str(self.obj, 16, out_buf as *mut c_char, out_len)
            })?;

        if cfg!(feature = "botan3") {
            Ok(r.split_off(2)) // remove leading 0x
        } else {
            Ok(r)
        }
    }

    /// Return value of self as a byte array (big endian)
    pub fn to_bin(&self) -> Result<Vec<u8>> {
        let bytes = self.byte_count()?;
        let mut output = vec![0; bytes];
        botan_call!(botan_mp_to_bin, self.obj, output.as_mut_ptr())?;
        Ok(output)
    }

    /// Return number of significant bits
    pub fn bit_count(&self) -> Result<usize> {
        let mut bits = 0;
        botan_call!(botan_mp_num_bits, self.obj, &mut bits)?;
        Ok(bits)
    }

    /// Return number of significant bytes
    pub fn byte_count(&self) -> Result<usize> {
        let mut bytes = 0;
        botan_call!(botan_mp_num_bytes, self.obj, &mut bytes)?;
        Ok(bytes)
    }

    /// Return self as a u32, if it fits
    pub fn to_u32(&self) -> Result<u32> {
        let mut val = 0;
        botan_call!(botan_mp_to_uint32, self.obj, &mut val)?;
        Ok(val)
    }

    /// Return true if self is an integer >= 0
    pub fn is_positive(&self) -> Result<bool> {
        botan_bool_in_rc!(botan_mp_is_positive, self.obj)
    }

    /// Return true if self is an integer < 0
    pub fn is_negative(&self) -> Result<bool> {
        botan_bool_in_rc!(botan_mp_is_negative, self.obj)
    }

    /// Return true if self is an integer == 0
    pub fn is_zero(&self) -> Result<bool> {
        botan_bool_in_rc!(botan_mp_is_zero, self.obj)
    }

    /// Return true if self is odd
    pub fn is_odd(&self) -> Result<bool> {
        botan_bool_in_rc!(botan_mp_is_odd, self.obj)
    }

    /// Return true if self is even
    pub fn is_even(&self) -> Result<bool> {
        botan_bool_in_rc!(botan_mp_is_even, self.obj)
    }

    /// Return true if self equals other
    pub fn equals(&self, other: &MPI) -> Result<bool> {
        botan_bool_in_rc!(botan_mp_equal, self.obj, other.obj)
    }

    /// Compare self with other
    pub fn compare(&self, other: &MPI) -> Result<Ordering> {
        let mut r = 0;

        botan_call!(botan_mp_cmp, &mut r, self.obj, other.obj)?;

        match r {
            -1 => Ok(Ordering::Less),
            0 => Ok(Ordering::Equal),
            1 => Ok(Ordering::Greater),
            r => Err(Error::with_message(
                ErrorType::ConversionError,
                format!("Unexpected botan_mp_cmp result {r}"),
            )),
        }
    }

    /// Flip the sign of self
    pub fn flip_sign(&mut self) -> Result<()> {
        botan_call!(botan_mp_flip_sign, self.obj)
    }

    /// Addition operator
    pub fn mp_add(&self, other: &MPI) -> Result<MPI> {
        let r = MPI::new()?;
        botan_call!(botan_mp_add, r.obj, self.obj, other.obj)?;
        Ok(r)
    }

    /// Addition operator, assignment version
    pub fn mp_add_assign(&mut self, other: &MPI) -> Result<()> {
        botan_call!(botan_mp_add, self.obj, self.obj, other.obj)
    }

    /// Addition operator
    pub fn mp_add_u32(&self, other: u32) -> Result<MPI> {
        let r = MPI::new()?;
        botan_call!(botan_mp_add_u32, r.obj, self.obj, other)?;
        Ok(r)
    }

    /// Addition operator, assignment version
    pub fn mp_add_u32_assign(&mut self, other: u32) -> Result<()> {
        botan_call!(botan_mp_add_u32, self.obj, self.obj, other)
    }

    /// Subtraction operator
    pub fn mp_sub(&self, other: &MPI) -> Result<MPI> {
        let r = MPI::new()?;
        botan_call!(botan_mp_sub, r.obj, self.obj, other.obj)?;
        Ok(r)
    }

    /// Subtraction operator, assignment version
    pub fn mp_sub_assign(&mut self, other: &MPI) -> Result<()> {
        botan_call!(botan_mp_sub, self.obj, self.obj, other.obj)
    }

    /// Subtraction operator
    pub fn mp_sub_u32(&self, other: u32) -> Result<MPI> {
        let r = MPI::new()?;
        botan_call!(botan_mp_sub_u32, r.obj, self.obj, other)?;
        Ok(r)
    }

    /// Subtraction operator, assignment version
    pub fn mp_sub_u32_assign(&mut self, other: u32) -> Result<()> {
        botan_call!(botan_mp_sub_u32, self.obj, self.obj, other)
    }

    /// Multiplication operator
    pub fn mp_mul(&self, other: &MPI) -> Result<MPI> {
        let r = MPI::new()?;
        botan_call!(botan_mp_mul, r.obj, self.obj, other.obj)?;
        Ok(r)
    }

    /// Multiplication operator, assignment version
    pub fn mp_mul_assign(&mut self, other: &MPI) -> Result<()> {
        botan_call!(botan_mp_mul, self.obj, self.obj, other.obj)
    }

    /// Bitwise left shift
    pub fn mp_shl(&self, shift: usize) -> Result<MPI> {
        let r = MPI::new()?;
        botan_call!(botan_mp_lshift, r.obj, self.obj, shift)?;
        Ok(r)
    }

    /// Bitwise left shift, assignment version
    pub fn mp_shl_assign(&mut self, shift: usize) -> Result<()> {
        botan_call!(botan_mp_lshift, self.obj, self.obj, shift)
    }

    /// Bitwise right shift
    pub fn mp_shr(&self, shift: usize) -> Result<MPI> {
        let r = MPI::new()?;
        botan_call!(botan_mp_rshift, r.obj, self.obj, shift)?;
        Ok(r)
    }

    /// Bitwise right shift, assignment version
    pub fn mp_shr_assign(&mut self, shift: usize) -> Result<()> {
        botan_call!(botan_mp_rshift, self.obj, self.obj, shift)
    }

    /// Division/modulo operator
    pub fn divrem(&self, z: &MPI) -> Result<(MPI, MPI)> {
        let q = MPI::new()?;
        let r = MPI::new()?;

        botan_call!(botan_mp_div, q.obj, r.obj, self.obj, z.obj)?;

        Ok((q, r))
    }

    /// Swap two MPI values
    pub fn swap(&mut self, other: &mut MPI) -> Result<()> {
        botan_call!(botan_mp_swap, self.obj, other.obj)
    }

    /// Perform a primality test on self
    ///
    /// # Examples
    ///
    /// ```
    /// use core::str::FromStr;
    /// let n = botan::MPI::from_str("1111111111111111111").unwrap();
    /// let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
    /// assert!(n.is_prime(&mut rng, 128).unwrap());
    /// ```
    pub fn is_prime(&self, rng: &mut RandomNumberGenerator, test_prob: usize) -> Result<bool> {
        botan_bool_in_rc!(botan_mp_is_prime, self.obj, rng.handle(), test_prob)
    }

    /// Return the greatest common divisor of x and y
    /// # Examples
    ///
    /// ```
    /// use core::str::FromStr;
    /// let x = botan::MPI::from_str("1111111111111111").unwrap();
    /// let y = botan::MPI::from_str("111111111111").unwrap();
    /// assert_eq!(botan::MPI::gcd(&x, &y).unwrap(), botan::MPI::from_str("1111").unwrap());
    /// ```
    pub fn gcd(x: &MPI, y: &MPI) -> Result<MPI> {
        let r = MPI::new()?;
        botan_call!(botan_mp_gcd, r.obj, x.obj, y.obj)?;
        Ok(r)
    }

    /// Return the inverse of x modulo m, or 0 if gcd(x,m) > 1
    pub fn modular_inverse(x: &MPI, m: &MPI) -> Result<MPI> {
        let r = MPI::new()?;
        botan_call!(botan_mp_mod_inverse, r.obj, x.obj, m.obj)?;
        Ok(r)
    }

    /// Return (x^e) mod m
    pub fn powmod(x: &MPI, e: &MPI, m: &MPI) -> Result<MPI> {
        let r = MPI::new()?;
        botan_call!(botan_mp_powmod, r.obj, x.obj, e.obj, m.obj)?;
        Ok(r)
    }
}

impl PartialOrd for MPI {
    fn partial_cmp(&self, other: &MPI) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for MPI {
    fn eq(&self, other: &MPI) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for MPI {}

impl Ord for MPI {
    fn cmp(&self, other: &MPI) -> Ordering {
        self.compare(other).expect("botan_mp_cmp should succeed")
    }
}

impl FromStr for MPI {
    type Err = Error;

    fn from_str(s: &str) -> Result<MPI> {
        let mut mpi = MPI::new()?;
        mpi.set_str(s)?;
        Ok(mpi)
    }
}

impl fmt::Debug for MPI {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let s = self.to_string().map_err(|_| fmt::Error)?;

        if cfg!(feature = "botan3") {
            write!(formatter, "{s}")
        } else {
            let is_positive = self.is_positive().map_err(|_| fmt::Error)?;
            formatter.pad_integral(is_positive, "", &s)
        }
    }
}

impl fmt::Display for MPI {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl fmt::UpperHex for MPI {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let s = self.to_hex().map_err(|_| fmt::Error)?;
        let is_positive = self.is_positive().map_err(|_| fmt::Error)?;
        formatter.pad_integral(is_positive, "0x", &s)
    }
}

impl fmt::LowerHex for MPI {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let mut s = self.to_hex().map_err(|_| fmt::Error)?;
        let is_positive = self.is_positive().map_err(|_| fmt::Error)?;
        s.make_ascii_lowercase();
        formatter.pad_integral(is_positive, "0x", &s)
    }
}

impl<'a> Add<&'a MPI> for MPI {
    type Output = MPI;

    fn add(mut self, other: &MPI) -> MPI {
        self.mp_add_assign(other)
            .expect("MPI::mp_add_assign succeeded");
        self
    }
}

impl<'a, 'b> Add<&'a MPI> for &'b MPI {
    type Output = MPI;

    fn add(self, other: &MPI) -> MPI {
        self.mp_add(other).expect("MPI::mp_add succeeded")
    }
}

impl Add<u32> for MPI {
    type Output = MPI;

    fn add(mut self, other: u32) -> MPI {
        self.mp_add_u32_assign(other)
            .expect("MPI::mp_add_u32_assign succeeded");
        self
    }
}

impl<'a> Add<u32> for &'a MPI {
    type Output = MPI;

    fn add(self, other: u32) -> MPI {
        self.mp_add_u32(other).expect("MPI::mp_add_u32 succeeded")
    }
}

impl<'a> AddAssign<&'a MPI> for MPI {
    fn add_assign(&mut self, other: &MPI) {
        self.mp_add_assign(other)
            .expect("MPI::mp_add_assign succeeded");
    }
}

impl AddAssign<u32> for MPI {
    fn add_assign(&mut self, other: u32) {
        self.mp_add_u32_assign(other)
            .expect("MPI::mp_add_u32_assign succeeded");
    }
}

impl<'a> Sub<&'a MPI> for MPI {
    type Output = MPI;

    fn sub(mut self, other: &MPI) -> MPI {
        self.mp_sub_assign(other)
            .expect("MPI::mp_sub_assign succeeded");
        self
    }
}

impl<'a, 'b> Sub<&'a MPI> for &'b MPI {
    type Output = MPI;

    fn sub(self, other: &MPI) -> MPI {
        self.mp_sub(other).expect("MPI::mp_sub succeeded")
    }
}

impl Sub<u32> for MPI {
    type Output = MPI;

    fn sub(mut self, other: u32) -> MPI {
        self.mp_sub_u32_assign(other)
            .expect("MPI::mp_sub_u32_assign succeeded");
        self
    }
}

impl<'a> Sub<u32> for &'a MPI {
    type Output = MPI;

    fn sub(self, other: u32) -> MPI {
        self.mp_sub_u32(other).expect("MPI::mp_sub_u32 succeeded")
    }
}

impl<'a> SubAssign<&'a MPI> for MPI {
    fn sub_assign(&mut self, other: &MPI) {
        self.mp_sub_assign(other)
            .expect("MPI::mp_sub_assign succeeded");
    }
}

impl SubAssign<u32> for MPI {
    fn sub_assign(&mut self, other: u32) {
        self.mp_sub_u32_assign(other)
            .expect("MPI::mp_sub_u32_assign succeeded");
    }
}

impl<'a> Mul<&'a MPI> for MPI {
    type Output = MPI;

    fn mul(mut self, other: &MPI) -> MPI {
        self.mp_mul_assign(other)
            .expect("MPI::mp_mul_assign succeeded");
        self
    }
}

impl<'a, 'b> Mul<&'a MPI> for &'b MPI {
    type Output = MPI;

    fn mul(self, other: &MPI) -> MPI {
        self.mp_mul(other).expect("MPI::mp_mul succeeded")
    }
}

impl<'a> MulAssign<&'a MPI> for MPI {
    fn mul_assign(&mut self, other: &MPI) {
        self.mp_mul_assign(other)
            .expect("MPI::mp_mul_assign succeeded");
    }
}

impl<'a, 'b> Div<&'b MPI> for &'a MPI {
    type Output = MPI;

    #[inline]
    fn div(self, other: &MPI) -> MPI {
        let (q, _r) = self.divrem(other).expect("MPI::divrem succeeded");
        q
    }
}

impl<'a> DivAssign<&'a MPI> for MPI {
    fn div_assign(&mut self, other: &'a MPI) {
        *self = &*self / other;
    }
}

impl<'a, 'b> Rem<&'b MPI> for &'a MPI {
    type Output = MPI;

    fn rem(self, other: &MPI) -> MPI {
        let (_q, r) = self.divrem(other).expect("MPI::divrem succeeded");
        r
    }
}

impl<'a> RemAssign<&'a MPI> for MPI {
    fn rem_assign(&mut self, other: &MPI) {
        *self = &*self % other;
    }
}

impl<'a> Shl<usize> for &'a MPI {
    type Output = MPI;

    fn shl(self, shift: usize) -> MPI {
        self.mp_shl(shift).expect("MPI::mp_shl succeeded")
    }
}

impl ShlAssign<usize> for MPI {
    fn shl_assign(&mut self, shift: usize) {
        self.mp_shl_assign(shift)
            .expect("MPI::mp_shl_assign succeeded")
    }
}

impl<'a> Shr<usize> for &'a MPI {
    type Output = MPI;

    fn shr(self, shift: usize) -> MPI {
        self.mp_shr(shift).expect("MPI::mp_shr succeeded")
    }
}

impl ShrAssign<usize> for MPI {
    fn shr_assign(&mut self, shift: usize) {
        self.mp_shr_assign(shift)
            .expect("MPI::mp_shr_assign succeeded")
    }
}

impl Neg for MPI {
    type Output = MPI;

    fn neg(mut self) -> MPI {
        self.flip_sign().expect("MPI::flip_sign succeeded");
        self
    }
}
