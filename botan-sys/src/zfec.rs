extern "C" {

    #[cfg(botan_ffi_20230403)]
    pub fn botan_zfec_encode(
        k: usize,
        n: usize,
        input: *const u8,
        input_len: usize,
        outputs: *mut *mut u8,
    ) -> crate::ffi_types::c_int;

    #[cfg(botan_ffi_20230403)]
    pub fn botan_zfec_decode(
        k: usize,
        n: usize,
        indexes: *const usize,
        shares: *const *const u8,
        share_size: usize,
        outputs: *mut *mut u8,
    ) -> crate::ffi_types::c_int;
}
