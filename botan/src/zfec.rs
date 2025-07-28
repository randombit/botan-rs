use crate::utils::*;
use botan_sys::*;

/// Forward Error Correction Encoding
///
/// This requires `botan_ffi_20230403`, otherwise a not implemented error is returned
pub fn zfec_encode(k: usize, n: usize, input: &[u8]) -> Result<Vec<Vec<u8>>> {
    crate::ffi_version_guard!("zfec_encode", botan_ffi_20230403, [k, n, input], {
        let share_size = input.len() / k;

        let mut outputs = Vec::with_capacity(n);
        let mut output_ptrs = Vec::with_capacity(n);

        for _ in 0..n {
            let mut share = vec![0u8; share_size];
            output_ptrs.push(share.as_mut_ptr());
            outputs.push(share);
        }

        botan_call!(
            botan_zfec_encode,
            k,
            n,
            input.as_ptr(),
            input.len(),
            output_ptrs.as_mut_ptr()
        )?;

        Ok(outputs)
    })
}

/// Forward Error Correction Decoding
pub fn zfec_decode(
    k: usize,
    n: usize,
    shares: &[(usize, &[u8])],
    share_size: usize,
) -> Result<Vec<u8>> {
    crate::ffi_version_guard!(
        "zfec_decode",
        botan_ffi_20230403,
        [k, n, shares, share_size],
        {
            let mut share_ptrs = Vec::with_capacity(shares.len());
            let mut indexes = Vec::with_capacity(shares.len());
            for (share_index, share_slice) in shares {
                indexes.push(*share_index);
                share_ptrs.push(share_slice.as_ptr());
                if share_slice.len() != share_size {
                    return Err(Error::with_message(
                        ErrorType::InvalidInput,
                        "ZFEC decoding requires all shares be the same length".to_string(),
                    ));
                }
            }

            let mut output_buf = vec![0u8; k * share_size];
            let output_buf_ptr: *mut u8 = output_buf.as_mut_ptr();

            let mut output_ptrs = Vec::with_capacity(k);

            for i in 0..k {
                output_ptrs.push(unsafe { output_buf_ptr.add(i * share_size) });
            }

            botan_call!(
                botan_zfec_decode,
                k,
                n,
                indexes.as_ptr(),
                share_ptrs.as_ptr(),
                share_size,
                output_ptrs.as_mut_ptr()
            )?;

            Ok(output_buf)
        }
    )
}
