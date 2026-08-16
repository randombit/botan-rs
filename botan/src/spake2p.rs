use crate::utils::*;
use botan_sys::*;

use crate::{EcGroup, RandomNumberGenerator};

#[derive(Eq, PartialEq, Debug, Copy, Clone)]
/// A SPAKE2+ ciphersuite from RFC 9383
pub enum Spake2pCiphersuite {
    /// P-256 with SHA-256
    P256Sha256,
    /// P-256 with SHA-512
    P256Sha512,
    /// P-384 with SHA-256
    P384Sha256,
    /// P-384 with SHA-512
    P384Sha512,
    /// P-521 with SHA-512
    P521Sha512,
}

impl Spake2pCiphersuite {
    fn name(self) -> &'static str {
        match self {
            Self::P256Sha256 => "P256-SHA256",
            Self::P256Sha512 => "P256-SHA512",
            Self::P384Sha256 => "P384-SHA256",
            Self::P384Sha512 => "P384-SHA512",
            Self::P521Sha512 => "P521-SHA512",
        }
    }
}

#[derive(Debug)]
/// SPAKE2+ system parameters
///
/// SPAKE2+ (RFC 9383) is a password authenticated key exchange; a
/// prover ("client") and a verifier ("server") each derive a shared
/// secret which is the same on both sides only if both sides know the
/// same password. The verifier does not store the password itself but
/// instead a registration record, which does not allow impersonating
/// the prover, but does allow offline password guessing attacks.
///
/// Both sides must use the same system parameters, identities, and
/// context string.
pub struct Spake2pParams {
    obj: botan_spake2p_params_t,
}

unsafe impl Sync for Spake2pParams {}
unsafe impl Send for Spake2pParams {}

botan_impl_drop!(Spake2pParams, botan_spake2p_params_destroy);

impl Spake2pParams {
    /// Create SPAKE2+ system parameters from an RFC 9383 ciphersuite
    pub fn new(ciphersuite: Spake2pCiphersuite) -> Result<Self> {
        let ciphersuite = make_cstr(ciphersuite.name())?;
        let obj = botan_init!(botan_spake2p_params_init, ciphersuite.as_ptr())?;
        Ok(Self { obj })
    }

    /// Create custom SPAKE2+ system parameters for an arbitrary group
    ///
    /// The M/N group elements are derived from the seed using hash to
    /// curve; this fails if the group does not support hash to curve.
    /// Both peers must use the same group, seed, and hash.
    ///
    /// If the seed includes the identities of the participants, this
    /// additionally makes the scheme "quantum annoying", in that an
    /// attacker with a discrete logarithm oracle must compute a new
    /// discrete log for each (prover, verifier) pair they wish to attack.
    pub fn new_custom(group: &EcGroup, seed: &[u8], hash_fn: &str) -> Result<Self> {
        let hash_fn = make_cstr(hash_fn)?;
        let obj = botan_init!(
            botan_spake2p_params_init_custom,
            group.handle(),
            seed.as_ptr(),
            seed.len(),
            hash_fn.as_ptr()
        )?;
        Ok(Self { obj })
    }

    /// Return the size in bytes of a SPAKE2+ key share (shareP or shareV)
    pub fn share_size(&self) -> Result<usize> {
        botan_usize!(botan_spake2p_params_share_size, self.obj)
    }

    /// Return the size in bytes of a SPAKE2+ key confirmation message
    /// (confirmP or confirmV)
    pub fn confirmation_size(&self) -> Result<usize> {
        botan_usize!(botan_spake2p_params_confirmation_size, self.obj)
    }

    /// Derive a SPAKE2+ prover secret (w0 and w1) from a password, using Argon2id
    ///
    /// The returned secret is password equivalent and must be protected
    /// accordingly. It is used with [`Spake2pParams::registration_record`]
    /// and [`Spake2pProver::new`].
    pub fn derive_secret(
        &self,
        password: &str,
        prover_id: &[u8],
        verifier_id: &[u8],
        salt: &[u8],
    ) -> Result<Vec<u8>> {
        let password = make_cstr(password)?;
        call_botan_ffi_viewing_vec_u8(&|ctx, cb| unsafe {
            botan_spake2p_derive_secret(
                self.obj,
                password.as_ptr(),
                prover_id.as_ptr(),
                prover_id.len(),
                verifier_id.as_ptr(),
                verifier_id.len(),
                salt.as_ptr(),
                salt.len(),
                ctx,
                cb,
            )
        })
    }

    /// Compute a SPAKE2+ registration record (w0 and L) from a prover secret
    ///
    /// The registration record is provided to the verifier during
    /// registration. While it does not allow directly impersonating the
    /// prover, it does allow offline password guessing attacks, so it
    /// should be protected.
    pub fn registration_record(
        &self,
        rng: &mut RandomNumberGenerator,
        secret: &[u8],
    ) -> Result<Vec<u8>> {
        let rng = rng.handle();
        call_botan_ffi_viewing_vec_u8(&|ctx, cb| unsafe {
            botan_spake2p_registration_record(self.obj, rng, secret.as_ptr(), secret.len(), ctx, cb)
        })
    }
}

#[derive(Debug)]
/// SPAKE2+ prover
///
/// The prover ("client") side of a SPAKE2+ exchange. The exchange
/// proceeds as follows:
///
/// 1. The prover calls [`Spake2pProver::generate_message`] and sends
///    the key share to the verifier.
/// 2. The verifier calls [`Spake2pVerifier::process_message`] and sends
///    the response to the prover.
/// 3. The prover calls [`Spake2pProver::process_message`] and sends the
///    key confirmation to the verifier.
/// 4. The verifier calls [`Spake2pVerifier::verify_confirmation`].
/// 5. Both sides extract the shared secret.
pub struct Spake2pProver {
    obj: botan_spake2p_prover_t,
}

unsafe impl Sync for Spake2pProver {}
unsafe impl Send for Spake2pProver {}

botan_impl_drop!(Spake2pProver, botan_spake2p_prover_destroy);

impl Spake2pProver {
    /// Initialize a SPAKE2+ prover
    ///
    /// The secret is the prover secret from
    /// [`Spake2pParams::derive_secret`]. The identities and context must
    /// be agreed upon by both parties; the identities must additionally
    /// match the values used when deriving the prover secret.
    pub fn new(
        params: &Spake2pParams,
        secret: &[u8],
        prover_id: &[u8],
        verifier_id: &[u8],
        context: &[u8],
    ) -> Result<Self> {
        let obj = botan_init!(
            botan_spake2p_prover_init,
            params.obj,
            secret.as_ptr(),
            secret.len(),
            prover_id.as_ptr(),
            prover_id.len(),
            verifier_id.as_ptr(),
            verifier_id.len(),
            context.as_ptr(),
            context.len()
        )?;
        Ok(Self { obj })
    }

    /// Generate the prover's key share (shareP), which is sent to the verifier
    ///
    /// This can be called only once per prover object.
    pub fn generate_message(&mut self, rng: &mut RandomNumberGenerator) -> Result<Vec<u8>> {
        let rng = rng.handle();
        call_botan_ffi_viewing_vec_u8(&|ctx, cb| unsafe {
            botan_spake2p_prover_generate_message(self.obj, rng, ctx, cb)
        })
    }

    /// Consume the verifier's response and produce the prover's key confirmation
    ///
    /// The peer message is the verifier's response (shareV followed by
    /// confirmV); the returned key confirmation (confirmP) is sent to
    /// the verifier.
    ///
    /// Fails with `ErrorType::BadAuthCode` if the verifier's key
    /// confirmation is wrong, typically meaning the passwords do not
    /// match.
    pub fn process_message(
        &mut self,
        rng: &mut RandomNumberGenerator,
        peer_message: &[u8],
    ) -> Result<Vec<u8>> {
        let rng = rng.handle();
        call_botan_ffi_viewing_vec_u8(&|ctx, cb| unsafe {
            botan_spake2p_prover_process_message(
                self.obj,
                rng,
                peer_message.as_ptr(),
                peer_message.len(),
                ctx,
                cb,
            )
        })
    }

    /// Return the prover's shared secret (K_shared)
    ///
    /// This may be called only after [`Spake2pProver::process_message`]
    /// has succeeded.
    pub fn shared_secret(&self) -> Result<Vec<u8>> {
        call_botan_ffi_viewing_vec_u8(&|ctx, cb| unsafe {
            botan_spake2p_prover_shared_secret(self.obj, ctx, cb)
        })
    }
}

#[derive(Debug)]
/// SPAKE2+ verifier
///
/// The verifier ("server") side of a SPAKE2+ exchange; see
/// [`Spake2pProver`] for an outline of the exchange.
pub struct Spake2pVerifier {
    obj: botan_spake2p_verifier_t,
}

unsafe impl Sync for Spake2pVerifier {}
unsafe impl Send for Spake2pVerifier {}

botan_impl_drop!(Spake2pVerifier, botan_spake2p_verifier_destroy);

impl Spake2pVerifier {
    /// Initialize a SPAKE2+ verifier
    ///
    /// The record is the registration record from
    /// [`Spake2pParams::registration_record`]. The identities and
    /// context must be agreed upon by both parties; the identities must
    /// additionally match the values used when deriving the prover
    /// secret.
    pub fn new(
        params: &Spake2pParams,
        record: &[u8],
        prover_id: &[u8],
        verifier_id: &[u8],
        context: &[u8],
    ) -> Result<Self> {
        let obj = botan_init!(
            botan_spake2p_verifier_init,
            params.obj,
            record.as_ptr(),
            record.len(),
            prover_id.as_ptr(),
            prover_id.len(),
            verifier_id.as_ptr(),
            verifier_id.len(),
            context.as_ptr(),
            context.len()
        )?;
        Ok(Self { obj })
    }

    /// Consume the prover's key share and produce the verifier's response
    ///
    /// The peer message is the prover's key share (shareP); the returned
    /// response (shareV followed by confirmV) is sent to the prover.
    ///
    /// This can be called only once per verifier object.
    pub fn process_message(
        &mut self,
        rng: &mut RandomNumberGenerator,
        peer_message: &[u8],
    ) -> Result<Vec<u8>> {
        let rng = rng.handle();
        call_botan_ffi_viewing_vec_u8(&|ctx, cb| unsafe {
            botan_spake2p_verifier_process_message(
                self.obj,
                rng,
                peer_message.as_ptr(),
                peer_message.len(),
                ctx,
                cb,
            )
        })
    }

    /// Check the prover's key confirmation (confirmP)
    ///
    /// Fails with `ErrorType::BadAuthCode` if the confirmation is wrong,
    /// meaning the prover does not know the password.
    pub fn verify_confirmation(&mut self, confirmation: &[u8]) -> Result<()> {
        botan_call!(
            botan_spake2p_verifier_verify_confirmation,
            self.obj,
            confirmation.as_ptr(),
            confirmation.len()
        )
    }

    /// Skip checking the prover's key confirmation (confirmP)
    ///
    /// This can be called after [`Spake2pVerifier::process_message`], in
    /// place of [`Spake2pVerifier::verify_confirmation`], to allow
    /// extracting the shared secret without having checked the prover's
    /// key confirmation.
    ///
    /// # Warning
    ///
    /// After calling this, nothing is known about the peer; only a
    /// prover which knows the password can compute the same shared
    /// secret, but no evidence of this has been received. It is intended
    /// solely for protocols which embed SPAKE2+ and perform the prover's
    /// key confirmation themselves. Anywhere else, use
    /// [`Spake2pVerifier::verify_confirmation`].
    pub fn skip_confirmation(&mut self) -> Result<()> {
        botan_call!(botan_spake2p_verifier_skip_confirmation, self.obj)
    }

    /// Return the verifier's shared secret (K_shared)
    ///
    /// This may be called only after
    /// [`Spake2pVerifier::verify_confirmation`] has succeeded, or after
    /// [`Spake2pVerifier::skip_confirmation`].
    pub fn shared_secret(&self) -> Result<Vec<u8>> {
        call_botan_ffi_viewing_vec_u8(&|ctx, cb| unsafe {
            botan_spake2p_verifier_shared_secret(self.obj, ctx, cb)
        })
    }
}
