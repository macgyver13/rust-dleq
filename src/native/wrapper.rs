// SPDX-License-Identifier: CC0-1.0

//! Safe Rust wrapper over libsecp256k1 FFI for DLEQ operations.
//!
//! This module provides safe wrappers around the native libsecp256k1 DLEQ
//! implementation, calling the C library functions directly via FFI.

use super::ffi;
use crate::types::{DleqError, DleqProof};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

/// Generate DLEQ proof using native libsecp256k1.
///
/// This function calls the C implementation directly, delegating all
/// cryptographic operations to the native library.
///
/// # Arguments
/// * `_secp` - maintain for compatibility; not used in native implementation
/// * `a` - Secret key (scalar a)
/// * `b` - Public key B (base point)
/// * `aux_rand` - 32 bytes of auxiliary randomness
/// * `m` - Optional 32-byte message
///
/// # Returns
/// * `Ok(DleqProof)` - 64-byte proof (e || s)
/// * `Err(DleqError)` - If proof generation fails
pub fn generate_dleq_proof<C: secp256k1::Signing + secp256k1::Verification>(
    _secp: &Secp256k1<C>,
    a: &SecretKey,
    b: &PublicKey,
    aux_rand: &[u8; 32],
    m: Option<&[u8; 32]>,
) -> Result<DleqProof, DleqError> {
    unsafe {
        // Create a context for the native library
        let ctx = ffi::secp256k1_context_create(
            ffi::SECP256K1_CONTEXT_SIGN | ffi::SECP256K1_CONTEXT_VERIFY,
        );
        if ctx.is_null() {
            return Err(DleqError::TweakFailed);
        }

        // Ensure context is destroyed on exit
        let _ctx_guard = ContextGuard(ctx);

        // Convert rust-secp256k1 public keys to FFI format
        let ffi_pubkey_b = pubkey_to_ffi(ctx, b)?;

        // Prepare proof structure
        let mut proof = ffi::secp256k1_dleq_proof { data: [0u8; 64] };

        // Call native DLEQ proof generation
        let result = ffi::secp256k1_dleq_prove(
            ctx,
            &mut proof,
            a.as_ref().as_ptr(),
            &ffi_pubkey_b,
            aux_rand.as_ptr(),
            m.map(|msg| msg.as_ptr()).unwrap_or(core::ptr::null()),
        );

        if result != 1 {
            return Err(DleqError::InvalidNonce);
        }

        // Convert FFI proof to DleqProof
        Ok(DleqProof(proof.data))
    }
}

/// Verify DLEQ proof using native libsecp256k1.
///
/// This function calls the C implementation directly.
///
/// # Arguments
/// * `_secp` - maintain for compatibility; not used in native implementation
/// * `a` - Public key A = a*G
/// * `b` - Public key B (base point)
/// * `c` - Public key C = a*B
/// * `proof` - 64-byte DLEQ proof
/// * `m` - Optional 32-byte message
///
/// # Returns
/// * `Ok(true)` - Proof is valid
/// * `Ok(false)` - Proof is invalid
/// * `Err(DleqError)` - If verification operation fails
pub fn verify_dleq_proof<C: secp256k1::Verification + secp256k1::Signing>(
    _secp: &Secp256k1<C>,
    a: &PublicKey,
    b: &PublicKey,
    c: &PublicKey,
    proof: &DleqProof,
    m: Option<&[u8; 32]>,
) -> Result<bool, DleqError> {
    unsafe {
        // Create a context for the native library
        let ctx = ffi::secp256k1_context_create(ffi::SECP256K1_CONTEXT_VERIFY);
        if ctx.is_null() {
            return Err(DleqError::InvalidProof);
        }

        // Ensure context is destroyed on exit
        let _ctx_guard = ContextGuard(ctx);

        // Convert rust-secp256k1 public keys to FFI format
        let ffi_pubkey_a = pubkey_to_ffi(ctx, a)?;
        let ffi_pubkey_b = pubkey_to_ffi(ctx, b)?;
        let ffi_pubkey_c = pubkey_to_ffi(ctx, c)?;

        // Parse proof into FFI format
        let ffi_proof = ffi::secp256k1_dleq_proof { data: proof.0 };

        // Call native DLEQ proof verification
        let result = ffi::secp256k1_dleq_verify(
            ctx,
            &ffi_proof,
            &ffi_pubkey_a,
            &ffi_pubkey_b,
            &ffi_pubkey_c,
            m.map(|msg| msg.as_ptr()).unwrap_or(core::ptr::null()),
        );

        Ok(result == 1)
    }
}

/// Convert a rust-secp256k1 PublicKey to FFI format.
///
/// # Safety
/// The ctx pointer must be valid and non-null.
unsafe fn pubkey_to_ffi(
    ctx: *const ffi::secp256k1_context,
    pubkey: &PublicKey,
) -> Result<ffi::secp256k1_pubkey, DleqError> {
    let mut ffi_pubkey = ffi::secp256k1_pubkey { data: [0u8; 64] };

    // Serialize the public key to compressed format
    let serialized = pubkey.serialize();

    // Parse into FFI format
    let result =
        ffi::secp256k1_ec_pubkey_parse(ctx, &mut ffi_pubkey, serialized.as_ptr(), serialized.len());

    if result != 1 {
        return Err(DleqError::InvalidProof);
    }

    Ok(ffi_pubkey)
}

/// RAII guard for secp256k1_context to ensure cleanup.
struct ContextGuard(*mut ffi::secp256k1_context);

impl Drop for ContextGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_null() {
                ffi::secp256k1_context_destroy(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;

    #[test]
    fn test_ffi_roundtrip() {
        let secp = Secp256k1::new();
        let secret = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let b = PublicKey::from_secret_key(&secp, &secret);
        let aux_rand = [0u8; 32];

        let proof = generate_dleq_proof(&secp, &secret, &b, &aux_rand, None)
            .expect("proof generation should succeed");

        let a = PublicKey::from_secret_key(&secp, &secret);
        let scalar: secp256k1::Scalar = secret.into();
        let c = b.mul_tweak(&secp, &scalar).expect("tweak should succeed");

        let valid = verify_dleq_proof(&secp, &a, &b, &c, &proof, None)
            .expect("verification should succeed");

        assert!(valid, "proof should be valid");
    }

    #[test]
    fn test_ffi_with_message() {
        let secp = Secp256k1::new();
        let secret = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let b = PublicKey::from_secret_key(&secp, &secret);
        let aux_rand = [1u8; 32];
        let message = [42u8; 32];

        let proof = generate_dleq_proof(&secp, &secret, &b, &aux_rand, Some(&message))
            .expect("proof generation should succeed");

        let a = PublicKey::from_secret_key(&secp, &secret);
        let scalar: secp256k1::Scalar = secret.into();
        let c = b.mul_tweak(&secp, &scalar).expect("tweak should succeed");

        let valid = verify_dleq_proof(&secp, &a, &b, &c, &proof, Some(&message))
            .expect("verification should succeed");

        assert!(valid, "proof with message should be valid");
    }

    #[test]
    fn test_ffi_invalid_proof() {
        let secp = Secp256k1::new();
        let secret = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let b = PublicKey::from_secret_key(&secp, &secret);

        let a = PublicKey::from_secret_key(&secp, &secret);
        let scalar: secp256k1::Scalar = secret.into();
        let c = b.mul_tweak(&secp, &scalar).expect("tweak should succeed");

        // Create invalid proof
        let invalid_proof = DleqProof([0u8; 64]);

        let valid = verify_dleq_proof(&secp, &a, &b, &c, &invalid_proof, None)
            .expect("verification should succeed");

        assert!(!valid, "invalid proof should not verify");
    }
}
