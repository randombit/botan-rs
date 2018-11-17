use libc::{c_int, c_char};

use mp::botan_mp_t;
use rng::botan_rng_t;

pub enum botan_pubkey_struct {}
pub type botan_pubkey_t = *mut botan_pubkey_struct;

pub enum botan_privkey_struct {}
pub type botan_privkey_t = *mut botan_privkey_struct;

extern "C" {
    pub fn botan_privkey_create(
        key: *mut botan_privkey_t,
        algo_name: *const c_char,
        algo_params: *const c_char,
        rng: botan_rng_t,
    ) -> c_int;
    pub fn botan_privkey_check_key(
        key: botan_privkey_t,
        rng: botan_rng_t,
        flags: u32,
    ) -> c_int;
    pub fn botan_privkey_create_rsa(
        key: *mut botan_privkey_t,
        rng: botan_rng_t,
        n_bits: usize,
    ) -> c_int;
    pub fn botan_privkey_create_ecdsa(
        key: *mut botan_privkey_t,
        rng: botan_rng_t,
        params: *const c_char,
    ) -> c_int;
    pub fn botan_privkey_create_ecdh(
        key: *mut botan_privkey_t,
        rng: botan_rng_t,
        params: *const c_char,
    ) -> c_int;
    pub fn botan_privkey_create_mceliece(
        key: *mut botan_privkey_t,
        rng: botan_rng_t,
        n: usize,
        t: usize,
    ) -> c_int;
    pub fn botan_privkey_create_dh(
        key: *mut botan_privkey_t,
        rng: botan_rng_t,
        param: *const c_char,
    ) -> c_int;
    pub fn botan_privkey_create_dsa(
        key: *mut botan_privkey_t,
        rng: botan_rng_t,
        pbits: usize,
        qbits: usize,
    ) -> c_int;
    pub fn botan_privkey_create_elgamal(
        key: *mut botan_privkey_t,
        rng: botan_rng_t,
        pbits: usize,
        qbits: usize,
    ) -> c_int;
    pub fn botan_privkey_load(
        key: *mut botan_privkey_t,
        rng: botan_rng_t,
        bits: *const u8,
        len: usize,
        password: *const c_char,
    ) -> c_int;
    pub fn botan_privkey_destroy(key: botan_privkey_t) -> c_int;
    pub fn botan_privkey_export(
        key: botan_privkey_t,
        out: *mut u8,
        out_len: *mut usize,
        flags: u32,
    ) -> c_int;
    pub fn botan_privkey_export_encrypted(
        key: botan_privkey_t,
        out: *mut u8,
        out_len: *mut usize,
        rng: botan_rng_t,
        passphrase: *const c_char,
        encryption_algo: *const c_char,
        flags: u32,
    ) -> c_int;
    pub fn botan_privkey_export_encrypted_pbkdf_msec(
        key: botan_privkey_t,
        out: *mut u8,
        out_len: *mut usize,
        rng: botan_rng_t,
        passphrase: *const c_char,
        pbkdf_msec_runtime: u32,
        pbkdf_iterations_out: *mut usize,
        cipher_algo: *const c_char,
        pbkdf_algo: *const c_char,
        flags: u32,
    ) -> c_int;
    pub fn botan_privkey_export_encrypted_pbkdf_iter(
        key: botan_privkey_t,
        out: *mut u8,
        out_len: *mut usize,
        rng: botan_rng_t,
        passphrase: *const c_char,
        pbkdf_iterations: usize,
        cipher_algo: *const c_char,
        pbkdf_algo: *const c_char,
        flags: u32,
    ) -> c_int;

    pub fn botan_pubkey_load(
        key: *mut botan_pubkey_t,
        bits: *const u8,
        len: usize,
    ) -> c_int;
    pub fn botan_privkey_export_pubkey(
        out: *mut botan_pubkey_t,
        in_: botan_privkey_t,
    ) -> c_int;
    pub fn botan_pubkey_export(
        key: botan_pubkey_t,
        out: *mut u8,
        out_len: *mut usize,
        flags: u32,
    ) -> c_int;
    pub fn botan_privkey_algo_name(
        key: botan_privkey_t,
        out: *mut c_char,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_pubkey_algo_name(
        key: botan_pubkey_t,
        out: *mut c_char,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_pubkey_check_key(
        key: botan_pubkey_t,
        rng: botan_rng_t,
        flags: u32,
    ) -> c_int;
    pub fn botan_pubkey_estimated_strength(
        key: botan_pubkey_t,
        estimate: *mut usize,
    ) -> c_int;
    pub fn botan_pubkey_fingerprint(
        key: botan_pubkey_t,
        hash: *const c_char,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_pubkey_destroy(key: botan_pubkey_t) -> c_int;
    pub fn botan_pubkey_get_field(
        output: botan_mp_t,
        key: botan_pubkey_t,
        field_name: *const c_char,
    ) -> c_int;
    pub fn botan_privkey_get_field(
        output: botan_mp_t,
        key: botan_privkey_t,
        field_name: *const c_char,
    ) -> c_int;
    pub fn botan_privkey_load_rsa(
        key: *mut botan_privkey_t,
        p: botan_mp_t,
        q: botan_mp_t,
        e: botan_mp_t,
    ) -> c_int;
    pub fn botan_privkey_load_rsa_pkcs1(
        key: *mut botan_privkey_t,
        bits: *const u8,
        len: usize) -> c_int;
    pub fn botan_privkey_rsa_get_p(
        p: botan_mp_t,
        rsa_key: botan_privkey_t,
    ) -> c_int;
    pub fn botan_privkey_rsa_get_q(
        q: botan_mp_t,
        rsa_key: botan_privkey_t,
    ) -> c_int;
    pub fn botan_privkey_rsa_get_d(
        d: botan_mp_t,
        rsa_key: botan_privkey_t,
    ) -> c_int;
    pub fn botan_privkey_rsa_get_n(
        n: botan_mp_t,
        rsa_key: botan_privkey_t,
    ) -> c_int;
    pub fn botan_privkey_rsa_get_e(
        e: botan_mp_t,
        rsa_key: botan_privkey_t,
    ) -> c_int;
    pub fn botan_pubkey_load_rsa(
        key: *mut botan_pubkey_t,
        n: botan_mp_t,
        e: botan_mp_t,
    ) -> c_int;
    pub fn botan_pubkey_rsa_get_e(e: botan_mp_t, rsa_key: botan_pubkey_t) -> c_int;
    pub fn botan_pubkey_rsa_get_n(n: botan_mp_t, rsa_key: botan_pubkey_t) -> c_int;
    pub fn botan_privkey_load_dsa(
        key: *mut botan_privkey_t,
        p: botan_mp_t,
        q: botan_mp_t,
        g: botan_mp_t,
        x: botan_mp_t,
    ) -> c_int;
    pub fn botan_pubkey_load_dsa(
        key: *mut botan_pubkey_t,
        p: botan_mp_t,
        q: botan_mp_t,
        g: botan_mp_t,
        y: botan_mp_t,
    ) -> c_int;
    pub fn botan_privkey_dsa_get_x(n: botan_mp_t, key: botan_privkey_t) -> c_int;
    pub fn botan_pubkey_dsa_get_p(p: botan_mp_t, key: botan_pubkey_t) -> c_int;
    pub fn botan_pubkey_dsa_get_q(q: botan_mp_t, key: botan_pubkey_t) -> c_int;
    pub fn botan_pubkey_dsa_get_g(d: botan_mp_t, key: botan_pubkey_t) -> c_int;
    pub fn botan_pubkey_dsa_get_y(y: botan_mp_t, key: botan_pubkey_t) -> c_int;
    pub fn botan_privkey_load_dh(
        key: *mut botan_privkey_t,
        p: botan_mp_t,
        g: botan_mp_t,
        x: botan_mp_t,
    ) -> c_int;
    pub fn botan_pubkey_load_dh(
        key: *mut botan_pubkey_t,
        p: botan_mp_t,
        g: botan_mp_t,
        y: botan_mp_t,
    ) -> c_int;
    pub fn botan_pubkey_load_elgamal(
        key: *mut botan_pubkey_t,
        p: botan_mp_t,
        g: botan_mp_t,
        y: botan_mp_t,
    ) -> c_int;
    pub fn botan_privkey_load_elgamal(
        key: *mut botan_privkey_t,
        p: botan_mp_t,
        g: botan_mp_t,
        x: botan_mp_t,
    ) -> c_int;
    pub fn botan_privkey_load_ed25519(
        key: *mut botan_privkey_t,
        privkey: *const u8,
    ) -> c_int;
    pub fn botan_pubkey_load_ed25519(
        key: *mut botan_pubkey_t,
        pubkey: *const u8,
    ) -> c_int;
    pub fn botan_privkey_ed25519_get_privkey(
        key: botan_privkey_t,
        output: *mut u8,
    ) -> c_int;
    pub fn botan_pubkey_ed25519_get_pubkey(
        key: botan_pubkey_t,
        pubkey: *mut u8,
    ) -> c_int;

    pub fn botan_privkey_load_x25519(
        key: *mut botan_privkey_t,
        privkey: *const u8,
    ) -> c_int;
    pub fn botan_pubkey_load_x25519(
        key: *mut botan_pubkey_t,
        pubkey: *const u8,
    ) -> c_int;
    pub fn botan_privkey_x25519_get_privkey(
        key: botan_privkey_t,
        output: *mut u8,
    ) -> c_int;
    pub fn botan_pubkey_x25519_get_pubkey(
        key: botan_pubkey_t,
        pubkey: *mut u8,
    ) -> c_int;

    pub fn botan_privkey_load_ecdsa(
        key: *mut botan_privkey_t,
        scalar: botan_mp_t,
        curve_name: *const c_char,
    ) -> c_int;
    pub fn botan_pubkey_load_ecdsa(
        key: *mut botan_pubkey_t,
        public_x: botan_mp_t,
        public_y: botan_mp_t,
        curve_name: *const c_char,
    ) -> c_int;
    pub fn botan_pubkey_load_ecdh(
        key: *mut botan_pubkey_t,
        public_x: botan_mp_t,
        public_y: botan_mp_t,
        curve_name: *const c_char,
    ) -> c_int;
    pub fn botan_privkey_load_ecdh(
        key: *mut botan_privkey_t,
        scalar: botan_mp_t,
        curve_name: *const c_char,
    ) -> c_int;
    pub fn botan_pubkey_load_sm2(
        key: *mut botan_pubkey_t,
        public_x: botan_mp_t,
        public_y: botan_mp_t,
        curve_name: *const c_char,
    ) -> c_int;
    pub fn botan_privkey_load_sm2(
        key: *mut botan_privkey_t,
        scalar: botan_mp_t,
        curve_name: *const c_char,
    ) -> c_int;
    pub fn botan_pubkey_load_sm2_enc(
        key: *mut botan_pubkey_t,
        public_x: botan_mp_t,
        public_y: botan_mp_t,
        curve_name: *const c_char,
    ) -> c_int;
    pub fn botan_privkey_load_sm2_enc(
        key: *mut botan_privkey_t,
        scalar: botan_mp_t,
        curve_name: *const c_char,
    ) -> c_int;
    pub fn botan_pubkey_sm2_compute_za(
        out: *mut u8,
        out_len: *mut usize,
        ident: *const c_char,
        hash_algo: *const c_char,
        key: botan_pubkey_t,
    ) -> c_int;
}
