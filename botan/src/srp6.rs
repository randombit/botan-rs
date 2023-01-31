//! SRP-6a (RFC 5054 compatatible)
//!
//! This module contains the [`ServerSession`] type and the client side functions.
//!
//! # Examples
//!
//! ```
//! use botan::RandomNumberGenerator;
//! use botan::{ServerSession, generate_srp6_verifier, srp6_client_agree};
//!
//! let mut rng = RandomNumberGenerator::new_system().expect("Failed to create a random number generator");
//! let mut server = ServerSession::new().expect("Failed to create a SRP6 server session");
//! let salt = rng.read(24).expect("Failed to generate salt");
//! let verifier = generate_srp6_verifier("alice", "password123", &salt, "modp/srp/1024", "SHA-512").expect("Failed to generate SRP6 verifier");
//! let b_pub = server.step1(&verifier, "modp/srp/1024", "SHA-512", &rng).expect("Failed to calculate server B value");
//! let (a_pub, client_key) = srp6_client_agree("alice", "password123", "modp/srp/1024", "SHA-512", &salt, &b_pub, &rng).expect("Failed to generate client key");
//! let server_key = server.step2(&a_pub).expect("Failed to generate server key");
//! assert_eq!(client_key, server_key);
//! ```

use crate::{utils::*, RandomNumberGenerator};
use botan_sys::*;

/// An SRP-6 server session
#[derive(Debug)]
pub struct ServerSession {
    obj: botan_srp6_server_session_t,
}

botan_impl_drop!(ServerSession, botan_srp6_server_session_destroy);

impl ServerSession {
    /// Returns a new server session object.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorType::OutOfMemory`] if memory is exhausted
    pub fn new() -> Result<Self> {
        Ok(Self {
            obj: botan_init!(botan_srp6_server_session_init)?,
        })
    }

    /// Server side step 1. Returns SRP-6 B value.
    ///
    /// # Arguments
    ///
    /// `verifier`: the verification value saved from client registration
    /// `group_id`: the SRP group id
    /// `hash_id`: the SRP hash in use
    /// `rng`: a random number generator
    ///
    /// # Errors
    ///
    /// Returns [`ErrorType::BadParameter`] if SRP group/hash id is invalid.
    pub fn step1(
        &mut self,
        verifier: &[u8],
        group_id: &str,
        hash_id: &str,
        rng: &RandomNumberGenerator,
    ) -> Result<Vec<u8>> {
        let group_id = make_cstr(group_id)?;
        let hash_id = make_cstr(hash_id)?;
        call_botan_ffi_returning_vec_u8(128, &|b_pub, b_pub_len| unsafe {
            botan_srp6_server_session_step1(
                self.obj,
                verifier.as_ptr(),
                verifier.len(),
                group_id.as_ptr(),
                hash_id.as_ptr(),
                rng.handle(),
                b_pub,
                b_pub_len,
            )
        })
    }

    /// Server side step 2. Returns shared symmetric key.
    ///
    /// # Arguments
    ///
    /// `a_pub`: the client's value
    ///
    /// # Errors
    ///
    /// Returns [`ErrorType::BadParameter`] if the A value is invalid.
    pub fn step2(&self, a_pub: &[u8]) -> Result<Vec<u8>> {
        call_botan_ffi_returning_vec_u8(128, &|key, key_len| unsafe {
            botan_srp6_server_session_step2(self.obj, a_pub.as_ptr(), a_pub.len(), key, key_len)
        })
    }
}

/// Returns a new SRP-6 verifier.
///
/// `identifier`: a username or other client identifier
/// `password`: the secret used to authenticate user
/// `salt`: a randomly chosen value, at least 128 bits long
/// `group_id`: the SRP group id
/// `hash_id`: the SRP hash in use
///
/// # Error
///
/// Returns [`ErrorType::BadParameter`] if SRP group/hash id is invalid.
/// Returns [`ErrorType::BadParameter`] if salt is too short.
pub fn generate_srp6_verifier(
    identifier: &str,
    password: &str,
    salt: &[u8],
    group_id: &str,
    hash_id: &str,
) -> Result<Vec<u8>> {
    if salt.len() * 8 < 128 {
        return Err(Error::with_message(
            ErrorType::BadParameter,
            "Salt is too short".to_string(),
        ));
    }

    let identifier = make_cstr(identifier)?;
    let password = make_cstr(password)?;
    let group_id = make_cstr(group_id)?;
    let hash_id = make_cstr(hash_id)?;

    call_botan_ffi_returning_vec_u8(128, &|verifier, verifier_len| unsafe {
        botan_generate_srp6_verifier(
            identifier.as_ptr(),
            password.as_ptr(),
            salt.as_ptr(),
            salt.len(),
            group_id.as_ptr(),
            hash_id.as_ptr(),
            verifier,
            verifier_len,
        )
    })
}

/// SRP6a Client side. Returns the client public key and the shared secret key.
///
/// `username`: the username we are attempting login for
/// `password`: the password we are attempting to use
/// `salt`: the salt value sent by the server
/// `group_id`: specifies the shared SRP group
/// `hash_id`: specifies a secure hash function
/// `b_pub`: is the server's public value
/// `rng`: rng is a random number generator
///
/// # Error
///
/// Returns [`ErrorType::BadParameter`] if SRP group/hash id is invalid.
/// Returns [`ErrorType::BadParameter`] if the B value is invalid.
pub fn srp6_client_agree(
    username: &str,
    password: &str,
    group_id: &str,
    hash_id: &str,
    salt: &[u8],
    b_pub: &[u8],
    rng: &RandomNumberGenerator,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let username = make_cstr(username)?;
    let password = make_cstr(password)?;
    let group_id = make_cstr(group_id)?;
    let hash_id = make_cstr(hash_id)?;

    call_botan_ffi_returning_vec_u8_pair(128, 128, &|a, a_len, key, key_len| unsafe {
        botan_srp6_client_agree(
            username.as_ptr(),
            password.as_ptr(),
            group_id.as_ptr(),
            hash_id.as_ptr(),
            salt.as_ptr(),
            salt.len(),
            b_pub.as_ptr(),
            b_pub.len(),
            rng.handle(),
            a,
            a_len,
            key,
            key_len,
        )
    })
}
