use crate::utils::*;
use botan_sys::*;

/// Botan's ZFEC implementation requires `1 <= k <= n < 256`
const ZFEC_SHARE_LIMIT: usize = 256;

fn check_zfec_params(k: usize, n: usize) -> Result<()> {
    if k == 0 || k > n || n >= ZFEC_SHARE_LIMIT {
        return Err(Error::bad_parameter("Invalid ZFEC parameters"));
    }
    Ok(())
}

/// Forward Error Correction Encoding
///
/// Splits `input` into `k` shares and produces `n` shares in total, any `k`
/// of which suffice to recover `input` with [`zfec_decode`]. The parameters
/// must satisfy `1 <= k <= n < 256`, and the length of `input` must be a
/// multiple of `k`.
///
/// This requires Botan 3.0 or later; with older versions an error of type
/// [`ErrorType::NotImplemented`](crate::ErrorType::NotImplemented) is returned
pub fn zfec_encode(k: usize, n: usize, input: &[u8]) -> Result<Vec<Vec<u8>>> {
    check_zfec_params(k, n)?;

    if input.len() % k != 0 {
        return Err(Error::bad_parameter(
            "ZFEC encoding requires the input length be a multiple of k",
        ));
    }

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
}

/// Forward Error Correction Decoding
///
/// Recovers the original input from `k` of the `n` shares produced by
/// [`zfec_encode`] with the same `k` and `n`. `shares` must contain exactly
/// `k` entries, each pairing a share's index (its position in the output of
/// [`zfec_encode`], so less than `n`) with its contents. The indexes must be
/// distinct and every share must be `share_size` bytes long.
///
/// This requires Botan 3.0 or later; with older versions an error of type
/// [`ErrorType::NotImplemented`](crate::ErrorType::NotImplemented) is returned
pub fn zfec_decode(
    k: usize,
    n: usize,
    shares: &[(usize, &[u8])],
    share_size: usize,
) -> Result<Vec<u8>> {
    check_zfec_params(k, n)?;

    // botan_zfec_decode reads exactly k indexes and k share pointers
    if shares.len() != k {
        return Err(Error::bad_parameter(
            "ZFEC decoding requires exactly k shares",
        ));
    }

    let output_len = k
        .checked_mul(share_size)
        .ok_or_else(|| Error::bad_parameter("ZFEC share size is too large"))?;

    let mut seen = [false; ZFEC_SHARE_LIMIT];
    let mut share_ptrs = Vec::with_capacity(k);
    let mut indexes = Vec::with_capacity(k);
    for (share_index, share_slice) in shares {
        if *share_index >= n {
            return Err(Error::with_message(
                ErrorType::InvalidInput,
                "ZFEC share index must be less than n".to_string(),
            ));
        }
        if seen[*share_index] {
            return Err(Error::with_message(
                ErrorType::InvalidInput,
                "ZFEC decoding requires all share indexes be distinct".to_string(),
            ));
        }
        seen[*share_index] = true;

        if share_slice.len() != share_size {
            return Err(Error::with_message(
                ErrorType::InvalidInput,
                "ZFEC decoding requires all shares be the same length".to_string(),
            ));
        }

        indexes.push(*share_index);
        share_ptrs.push(share_slice.as_ptr());
    }

    let mut output_buf = vec![0u8; output_len];
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
