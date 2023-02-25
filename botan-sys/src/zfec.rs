extern "C" {

    #[cfg(feature = "botan3")]
    pub fn botan_zfec_encode(
        k: usize,
        n: usize,
        input: *const u8,
        input_len: usize,
        outputs: *mut *mut u8,
    ) -> core::ffi::c_int;

    #[cfg(feature = "botan3")]
    pub fn botan_zfec_decode(
        k: usize,
        n: usize,
        indexes: *const usize,
        shares: *const *const u8,
        share_size: usize,
        outputs: *mut *mut u8,
    ) -> core::ffi::c_int;
}
