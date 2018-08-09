use botan_sys::*;
use utils::*;

use rng::RandomNumberGenerator;

use std::cmp::{Eq, Ord, Ordering};

/*
use std::ops::{Add, AddAssign};
               Sub, SubAssign,
               Mul, MulAssign,
               Div, DivAssign,
               Rem, RemAssign,
               Shl, ShlAssign,
               Shr, ShrAssign,
               Neg};
*/

#[derive(Debug)]
/// A big integer type
pub struct MPI {
    obj: botan_mp_t,
}

impl Drop for MPI {
    fn drop(&mut self) {
        unsafe { botan_mp_destroy(self.obj); }
    }
}

impl Clone for MPI {
    fn clone(&self) -> MPI {
        self.duplicate().expect("copying MPI object failed")
    }
}

impl MPI {

    pub(crate) fn handle(&self) -> botan_mp_t { self.obj }

    pub fn new() -> Result<MPI> {
        let mut obj = ptr::null_mut();
        call_botan! { botan_mp_init(&mut obj) };
        Ok(MPI { obj })
    }

    pub fn new_from_str(val: &str) -> Result<MPI> {
        let mut mpi = MPI::new()?;
        mpi.set_str(val)?;
        Ok(mpi)
    }

    pub fn duplicate(&self) -> Result<MPI> {
        let mpi = MPI::new()?;
        call_botan! { botan_mp_set_from_mp(mpi.obj, self.obj) };
        Ok(mpi)
    }

    pub fn set_i32(&mut self, val: i32) -> Result<()> {
        call_botan! { botan_mp_set_from_int(self.obj, val) };
        Ok(())
    }

    pub fn set_str(&mut self, val: &str) -> Result<()> {
        let cstr = make_cstr(val)?;
        call_botan! { botan_mp_set_from_str(self.obj, cstr.as_ptr()) };
        Ok(())
    }

    pub fn clear(&self) -> Result<()> {
        call_botan! { botan_mp_clear(self.obj) };
        Ok(())
    }

    pub fn set_bit(&mut self, bit: usize) -> Result<()> {
        call_botan! { botan_mp_set_bit(self.obj, bit) };
        Ok(())
    }

    pub fn clear_bit(&mut self, bit: usize) -> Result<()> {
        call_botan! { botan_mp_clear_bit(self.obj, bit) };
        Ok(())
    }

    pub fn get_bit(&self, bit: usize) -> Result<bool> {
        let rc = unsafe { botan_mp_get_bit(self.obj, bit) };
        match rc {
            0 => Ok(false),
            1 => Ok(true),
            e => Err(Error::from(e))
        }
    }

    pub fn randomize(&mut self, rng: &RandomNumberGenerator, bits: usize) -> Result<()> {
        call_botan! { botan_mp_rand_bits(self.obj, rng.handle(), bits) };
        Ok(())
    }

    pub fn random_range(&mut self,
                        rng: &RandomNumberGenerator,
                        lower: &MPI,
                        upper: &MPI) -> Result<()> {
        call_botan! { botan_mp_rand_range(self.obj, rng.handle(), lower.handle(), upper.handle()) }
        Ok(())
    }

    pub fn to_string(&self) -> Result<String> {
        let bit_count = self.bit_count()? as f64;
        let log_base = (10f64).log2();
        let bn_digits = 1 + (bit_count / log_base) as usize;

        call_botan_ffi_returning_string(bn_digits, &|out_buf, out_len| {
            unsafe { botan_mp_to_str(self.obj, 10, out_buf as *mut c_char, out_len) }
        })
    }

    pub fn to_hex(&self) -> Result<String> {
        let byte_count = self.byte_count()?;

        call_botan_ffi_returning_string(byte_count*2 + 1, &|out_buf, out_len| {
            unsafe { botan_mp_to_str(self.obj, 16, out_buf as *mut c_char, out_len) }
        })
    }

/*
    TODO:

    pub fn botan_mp_to_hex(mp: botan_mp_t, out: *mut c_char) -> c_int;

    pub fn botan_mp_set_from_radix_str(
        dest: botan_mp_t,
        str: *const c_char,
        radix: usize,
    ) -> c_int;
    pub fn botan_mp_to_bin(mp: botan_mp_t, vec: *mut u8) -> c_int;
    pub fn botan_mp_from_bin(mp: botan_mp_t, vec: *const u8, vec_len: usize) -> c_int;

     */

    pub fn bit_count(&self) -> Result<usize> {
        let mut bits = 0;
        call_botan! { botan_mp_num_bits(self.obj, &mut bits) };
        Ok(bits)
    }

    pub fn byte_count(&self) -> Result<usize> {
        let mut bytes = 0;
        call_botan! { botan_mp_num_bytes(self.obj, &mut bytes) };
        Ok(bytes)
    }

    pub fn to_u32(&self) -> Result<u32> {
        let mut val = 0;
        call_botan! { botan_mp_to_uint32(self.obj, &mut val) };
        Ok(val)
    }

    pub fn is_positive(&self) -> Result<bool> {
        match unsafe { botan_mp_is_positive(self.obj) } {
            0 => Ok(false),
            1 => Ok(true),
            e => Err(Error::from(e))
        }
    }

    pub fn is_negative(&self) -> Result<bool> {
        match unsafe { botan_mp_is_negative(self.obj) } {
            0 => Ok(false),
            1 => Ok(true),
            e => Err(Error::from(e))
        }
    }

    pub fn is_zero(&self) -> Result<bool> {
        match unsafe { botan_mp_is_zero(self.obj) } {
            0 => Ok(false),
            1 => Ok(true),
            e => Err(Error::from(e))
        }
    }

    pub fn is_odd(&self) -> Result<bool> {
        match unsafe { botan_mp_is_odd(self.obj) } {
            0 => Ok(false),
            1 => Ok(true),
            e => Err(Error::from(e))
        }
    }

    pub fn is_even(&self) -> Result<bool> {
        match unsafe { botan_mp_is_even(self.obj) } {
            0 => Ok(false),
            1 => Ok(true),
            e => Err(Error::from(e))
        }
    }

    pub fn equals(&self, other: &MPI) -> Result<bool> {
        match unsafe { botan_mp_equal(self.obj, other.obj) } {
            0 => Ok(false),
            1 => Ok(true),
            e => Err(Error::from(e))
        }
    }

    pub fn compare(&self, other: &MPI) -> Result<Ordering> {
        let mut r = 0;

        call_botan! { botan_mp_cmp(&mut r, self.obj, other.obj) };

        match r {
            -1 => Ok(Ordering::Less),
            0 => Ok(Ordering::Equal),
            1 => Ok(Ordering::Greater),
            _ => Err(Error::ConversionError)
        }
    }

    pub fn flip_sign(&mut self) -> Result<()> {
        call_botan! { botan_mp_flip_sign(self.obj) };
        Ok(())
    }

    pub fn add(&self, other: &MPI) -> Result<MPI> {
        let r = MPI::new()?;
        call_botan! { botan_mp_add(r.obj, self.obj, other.obj) };
        Ok(r)
    }

    pub fn add_assign(&mut self, other: &MPI) -> Result<()> {
        call_botan! { botan_mp_add(self.obj, self.obj, other.obj) };
        Ok(())
    }

    pub fn sub(&self, other: &MPI) -> Result<MPI> {
        let r = MPI::new()?;
        call_botan! { botan_mp_sub(r.obj, self.obj, other.obj) };
        Ok(r)
    }

    pub fn sub_assign(&mut self, other: &MPI) -> Result<()> {
        call_botan! { botan_mp_sub(self.obj, self.obj, other.obj) };
        Ok(())
    }

    pub fn mul(&self, other: &MPI) -> Result<MPI> {
        let r = MPI::new()?;
        call_botan! { botan_mp_mul(r.obj, self.obj, other.obj) };
        Ok(r)
    }

    pub fn mul_assign(&mut self, other: &MPI) -> Result<()> {
        call_botan! { botan_mp_mul(self.obj, self.obj, other.obj) };
        Ok(())
    }

    pub fn shl(&self, shift: usize) -> Result<MPI> {
        let r = MPI::new()?;
        call_botan! { botan_mp_lshift(r.obj, self.obj, shift) };
        Ok(r)
    }

    pub fn shl_assign(&mut self, shift: usize) -> Result<()> {
        call_botan! { botan_mp_lshift(self.obj, self.obj, shift) };
        Ok(())
    }

    pub fn shr(&self, shift: usize) -> Result<MPI> {
        let r = MPI::new()?;
        call_botan! { botan_mp_rshift(r.obj, self.obj, shift) };
        Ok(r)
    }

    pub fn shr_assign(&mut self, shift: usize) -> Result<()> {
        call_botan! { botan_mp_rshift(self.obj, self.obj, shift) };
        Ok(())
    }

    pub fn divrem(&self, z: &MPI) -> Result<(MPI, MPI)> {
        let q = MPI::new()?;
        let r = MPI::new()?;

        call_botan! { botan_mp_div(q.obj, r.obj, self.obj, z.obj) };

        Ok((q,r))
    }

    pub fn swap(&mut self, other: &mut MPI) -> Result<()> {
        call_botan! { botan_mp_swap(self.obj, other.obj) };
        Ok(())
    }

    pub fn is_prime(&self, rng: &RandomNumberGenerator, test_prob: usize) -> Result<bool> {
        let rc = unsafe { botan_mp_is_prime(self.obj, rng.handle(), test_prob) };
        match rc {
            0 => Ok(false),
            1 => Ok(true),
            e => Err(Error::from(e))
        }
    }

}

pub fn gcd(x: &MPI, y: &MPI) -> Result<MPI> {
    let r = MPI::new()?;
    call_botan! { botan_mp_gcd(r.obj, x.obj, y.obj) };
    Ok(r)
}

pub fn modular_inverse(x: &MPI, m: &MPI) -> Result<MPI> {
    let r = MPI::new()?;
    call_botan! { botan_mp_mod_inverse(r.obj, x.obj, m.obj) };
    Ok(r)
}

pub fn powmod(x: &MPI, e: &MPI, m: &MPI) -> Result<MPI> {
    let r = MPI::new()?;
    call_botan! { botan_mp_powmod(r.obj, x.obj, e.obj, m.obj) };
    Ok(r)
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

// TODO proper arithmetic operators
