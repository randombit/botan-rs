use cty::{c_char, c_int};

use rng::botan_rng_t;

pub enum botan_mp_struct {}
pub type botan_mp_t = *mut botan_mp_struct;

extern "C" {

    pub fn botan_mp_init(mp: *mut botan_mp_t) -> c_int;
    pub fn botan_mp_destroy(mp: botan_mp_t) -> c_int;
    pub fn botan_mp_to_hex(mp: botan_mp_t, out: *mut c_char) -> c_int;
    pub fn botan_mp_to_str(
        mp: botan_mp_t,
        base: u8,
        out: *mut c_char,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_mp_clear(mp: botan_mp_t) -> c_int;
    pub fn botan_mp_set_from_int(mp: botan_mp_t, initial_value: c_int) -> c_int;
    pub fn botan_mp_set_from_mp(dest: botan_mp_t, source: botan_mp_t) -> c_int;
    pub fn botan_mp_set_from_str(dest: botan_mp_t, str: *const c_char) -> c_int;

    pub fn botan_mp_set_from_radix_str(dest: botan_mp_t, str: *const c_char, radix: usize)
        -> c_int;
    pub fn botan_mp_num_bits(n: botan_mp_t, bits: *mut usize) -> c_int;
    pub fn botan_mp_num_bytes(n: botan_mp_t, bytes: *mut usize) -> c_int;
    pub fn botan_mp_to_bin(mp: botan_mp_t, vec: *mut u8) -> c_int;
    pub fn botan_mp_from_bin(mp: botan_mp_t, vec: *const u8, vec_len: usize) -> c_int;
    pub fn botan_mp_to_uint32(mp: botan_mp_t, val: *mut u32) -> c_int;
    pub fn botan_mp_is_positive(mp: botan_mp_t) -> c_int;
    pub fn botan_mp_is_negative(mp: botan_mp_t) -> c_int;
    pub fn botan_mp_flip_sign(mp: botan_mp_t) -> c_int;
    pub fn botan_mp_is_zero(mp: botan_mp_t) -> c_int;
    pub fn botan_mp_is_odd(mp: botan_mp_t) -> c_int;
    pub fn botan_mp_is_even(mp: botan_mp_t) -> c_int;
    pub fn botan_mp_add(result: botan_mp_t, x: botan_mp_t, y: botan_mp_t) -> c_int;
    pub fn botan_mp_sub(result: botan_mp_t, x: botan_mp_t, y: botan_mp_t) -> c_int;
    pub fn botan_mp_add_u32(result: botan_mp_t, x: botan_mp_t, y: u32) -> c_int;
    pub fn botan_mp_sub_u32(result: botan_mp_t, x: botan_mp_t, y: u32) -> c_int;
    pub fn botan_mp_mul(result: botan_mp_t, x: botan_mp_t, y: botan_mp_t) -> c_int;
    pub fn botan_mp_div(
        quotient: botan_mp_t,
        remainder: botan_mp_t,
        x: botan_mp_t,
        y: botan_mp_t,
    ) -> c_int;
    pub fn botan_mp_mod_mul(
        result: botan_mp_t,
        x: botan_mp_t,
        y: botan_mp_t,
        mod_: botan_mp_t,
    ) -> c_int;
    pub fn botan_mp_equal(x: botan_mp_t, y: botan_mp_t) -> c_int;
    pub fn botan_mp_cmp(result: *mut c_int, x: botan_mp_t, y: botan_mp_t) -> c_int;
    pub fn botan_mp_swap(x: botan_mp_t, y: botan_mp_t) -> c_int;
    pub fn botan_mp_powmod(
        out: botan_mp_t,
        base: botan_mp_t,
        exponent: botan_mp_t,
        modulus: botan_mp_t,
    ) -> c_int;
    pub fn botan_mp_lshift(out: botan_mp_t, in_: botan_mp_t, shift: usize) -> c_int;
    pub fn botan_mp_rshift(out: botan_mp_t, in_: botan_mp_t, shift: usize) -> c_int;
    pub fn botan_mp_mod_inverse(out: botan_mp_t, in_: botan_mp_t, modulus: botan_mp_t) -> c_int;
    pub fn botan_mp_rand_bits(rand_out: botan_mp_t, rng: botan_rng_t, bits: usize) -> c_int;
    pub fn botan_mp_rand_range(
        rand_out: botan_mp_t,
        rng: botan_rng_t,
        lower_bound: botan_mp_t,
        upper_bound: botan_mp_t,
    ) -> c_int;
    pub fn botan_mp_gcd(out: botan_mp_t, x: botan_mp_t, y: botan_mp_t) -> c_int;
    pub fn botan_mp_is_prime(n: botan_mp_t, rng: botan_rng_t, test_prob: usize) -> c_int;
    pub fn botan_mp_get_bit(n: botan_mp_t, bit: usize) -> c_int;
    pub fn botan_mp_set_bit(n: botan_mp_t, bit: usize) -> c_int;
    pub fn botan_mp_clear_bit(n: botan_mp_t, bit: usize) -> c_int;

}
