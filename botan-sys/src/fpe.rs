use crate::ffi_types::c_int;

use crate::mp::botan_mp_t;

pub enum botan_fpe_struct {}
pub type botan_fpe_t = *mut botan_fpe_struct;

extern "C" {

    pub fn botan_fpe_fe1_init(
        fpe: *mut botan_fpe_t,
        n: botan_mp_t,
        key: *const u8,
        key_len: usize,
        rounds: usize,
        flags: u32,
    ) -> c_int;

    pub fn botan_fpe_destroy(fpe: botan_fpe_t) -> c_int;

    pub fn botan_fpe_encrypt(
        fpe: botan_fpe_t,
        x: botan_mp_t,
        tweak: *const u8,
        tweak_len: usize,
    ) -> c_int;

    pub fn botan_fpe_decrypt(
        fpe: botan_fpe_t,
        x: botan_mp_t,
        tweak: *const u8,
        tweak_len: usize,
    ) -> c_int;

}
