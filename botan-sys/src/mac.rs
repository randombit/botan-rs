use core::ffi::{c_char, c_int};

pub enum botan_mac_struct {}
pub type botan_mac_t = *mut botan_mac_struct;

extern "C" {

    pub fn botan_mac_init(mac: *mut botan_mac_t, mac_name: *const c_char, flags: u32) -> c_int;

    pub fn botan_mac_output_length(mac: botan_mac_t, output_length: *mut usize) -> c_int;

    pub fn botan_mac_set_key(mac: botan_mac_t, key: *const u8, key_len: usize) -> c_int;

    #[cfg(feature = "botan3")]
    pub fn botan_mac_set_nonce(mac: botan_mac_t, nonce: *const u8, nonce_len: usize) -> c_int;

    pub fn botan_mac_name(mac: botan_mac_t, name: *mut c_char, name_len: *mut usize) -> c_int;

    pub fn botan_mac_get_keyspec(
        mac: botan_mac_t,
        min_keylen: *mut usize,
        max_keylen: *mut usize,
        mod_keylen: *mut usize,
    ) -> c_int;

    pub fn botan_mac_update(mac: botan_mac_t, buf: *const u8, len: usize) -> c_int;
    pub fn botan_mac_final(mac: botan_mac_t, out: *mut u8) -> c_int;
    pub fn botan_mac_clear(mac: botan_mac_t) -> c_int;
    pub fn botan_mac_destroy(mac: botan_mac_t) -> c_int;

}
