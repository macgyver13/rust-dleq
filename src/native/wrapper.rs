// SPDX-License-Identifier: CC0-1.0

//! Safe Rust wrapper over libsecp256k1 FFI for DLEQ operations.
//!
//! This implementation uses libsecp256k1's EC operations but implements
//! the BIP-374 DLEQ protocol in Rust (matching the standalone version).
//! This is cleaner than trying to expose the static C functions.

// Note: ffi module is available but not currently used.
// The native implementation uses rust-secp256k1 for EC ops
// rather than direct FFI calls to keep the API consistent.
#[allow(unused_imports)]
use super::ffi;

use crate::types::{DleqError, DleqProof};
use bitcoin_hashes::{sha256, Hash, HashEngine};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Tagged hash tags for BIP-374.
const DLEQ_TAG_AUX: &str = "BIP0374/aux";
const DLEQ_TAG_NONCE: &str = "BIP0374/nonce";
const DLEQ_TAG_CHALLENGE: &str = "BIP0374/challenge";

/// Generate DLEQ proof using native libsecp256k1 EC operations.
///
/// This implementation uses the same BIP-374 algorithm as standalone,
/// but could be optimized to use libsecp256k1's internal functions
/// if they become publicly available.
pub fn generate_dleq_proof<C: secp256k1::Signing + secp256k1::Verification>(
    secp: &Secp256k1<C>,
    a: &SecretKey,
    b: &PublicKey,
    aux_rand: &[u8; 32],
    m: Option<&[u8; 32]>,
) -> Result<DleqProof, DleqError> {
    // Use standard secp256k1 generator G
    let g_point = PublicKey::from_secret_key(
        secp,
        &SecretKey::from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])
        .expect("valid secret key"),
    );

    // Compute A = a*G and C = a*B
    let a_scalar: Scalar = (*a).into();
    let a_point = g_point
        .mul_tweak(secp, &a_scalar)
        .map_err(|_| DleqError::TweakFailed)?;
    let c_point = b
        .mul_tweak(secp, &a_scalar)
        .map_err(|_| DleqError::TweakFailed)?;

    // Compute t = a XOR H_aux(r)
    let aux_hash = tagged_hash(DLEQ_TAG_AUX, aux_rand);
    let a_bytes = a.secret_bytes();
    let t = xor_bytes(&a_bytes, &aux_hash);

    // Compute nonce: k = H_nonce(t || A || C || m) mod n
    let mut nonce_data = Vec::with_capacity(32 + 33 + 33 + if m.is_some() { 32 } else { 0 });
    nonce_data.extend_from_slice(&t);
    nonce_data.extend_from_slice(&a_point.serialize());
    nonce_data.extend_from_slice(&c_point.serialize());
    if let Some(msg) = m {
        nonce_data.extend_from_slice(msg);
    }

    let nonce_hash = tagged_hash(DLEQ_TAG_NONCE, &nonce_data);
    let k = Scalar::from_be_bytes(nonce_hash).map_err(|_| DleqError::InvalidNonce)?;

    // Check if k is zero
    let k_key = SecretKey::from_slice(&k.to_be_bytes()).map_err(|_| DleqError::InvalidNonce)?;

    // Compute R1 = k*G and R2 = k*B
    let r1 = g_point
        .mul_tweak(secp, &k)
        .map_err(|_| DleqError::TweakFailed)?;
    let r2 = b.mul_tweak(secp, &k).map_err(|_| DleqError::TweakFailed)?;

    // Compute challenge e = H_challenge(A, B, C, G, R1, R2, m)
    let e = dleq_challenge(&a_point, b, &c_point, &g_point, &r1, &r2, m);

    // Compute s = k + e*a (mod n)
    let e_key = SecretKey::from_slice(&e.to_be_bytes()).map_err(|_| DleqError::InvalidChallenge)?;
    let ea = e_key
        .mul_tweak(&a_scalar)
        .map_err(|_| DleqError::TweakFailed)?;
    let s_key = k_key
        .add_tweak(&ea.into())
        .map_err(|_| DleqError::TweakFailed)?;
    let s = Scalar::from(s_key);

    // Construct proof: e || s
    let mut proof_bytes = [0u8; 64];
    proof_bytes[0..32].copy_from_slice(&e.to_be_bytes());
    proof_bytes[32..64].copy_from_slice(&s.to_be_bytes());

    // Verify before returning
    let proof = DleqProof(proof_bytes);
    if !verify_dleq_proof(secp, &a_point, b, &c_point, &proof, m)? {
        return Err(DleqError::SelfVerificationFailed);
    }

    Ok(proof)
}

/// Verify DLEQ proof using native libsecp256k1 EC operations.
pub fn verify_dleq_proof<C: secp256k1::Verification + secp256k1::Signing>(
    secp: &Secp256k1<C>,
    a: &PublicKey,
    b: &PublicKey,
    c: &PublicKey,
    proof: &DleqProof,
    m: Option<&[u8; 32]>,
) -> Result<bool, DleqError> {
    // Parse proof: e || s
    let mut e_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    e_bytes.copy_from_slice(&proof.0[0..32]);
    s_bytes.copy_from_slice(&proof.0[32..64]);

    let e = Scalar::from_be_bytes(e_bytes).map_err(|_| DleqError::InvalidProof)?;
    let s = Scalar::from_be_bytes(s_bytes).map_err(|_| DleqError::InvalidProof)?;

    // Use standard secp256k1 generator G
    let g_point = PublicKey::from_secret_key(
        secp,
        &SecretKey::from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])
        .expect("valid secret key"),
    );

    // Compute R1 = s*G - e*A
    let s_g = g_point
        .mul_tweak(secp, &s)
        .map_err(|_| DleqError::TweakFailed)?;
    let e_a = a.mul_tweak(secp, &e).map_err(|_| DleqError::TweakFailed)?;

    let r1 = s_g
        .combine(&e_a.negate(secp))
        .map_err(|_| DleqError::PointCombineFailed)?;

    // Compute R2 = s*B - e*C
    let s_b = b.mul_tweak(secp, &s).map_err(|_| DleqError::TweakFailed)?;
    let e_c = c.mul_tweak(secp, &e).map_err(|_| DleqError::TweakFailed)?;

    let r2 = s_b
        .combine(&e_c.negate(secp))
        .map_err(|_| DleqError::PointCombineFailed)?;

    // Verify challenge
    let e_prime = dleq_challenge(a, b, c, &g_point, &r1, &r2, m);

    Ok(e == e_prime)
}

/// Computes a tagged hash as defined in BIP-340.
fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(data);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// XORs two 32-byte arrays.
fn xor_bytes(lhs: &[u8; 32], rhs: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = lhs[i] ^ rhs[i];
    }
    result
}

/// Computes DLEQ challenge value.
///
/// e = H_challenge(A || B || C || G || R1 || R2 || m)
fn dleq_challenge(
    a: &PublicKey,
    b: &PublicKey,
    c: &PublicKey,
    g: &PublicKey,
    r1: &PublicKey,
    r2: &PublicKey,
    m: Option<&[u8; 32]>,
) -> Scalar {
    let mut data = Vec::with_capacity(6 * 33 + if m.is_some() { 32 } else { 0 });
    data.extend_from_slice(&a.serialize());
    data.extend_from_slice(&b.serialize());
    data.extend_from_slice(&c.serialize());
    data.extend_from_slice(&g.serialize());
    data.extend_from_slice(&r1.serialize());
    data.extend_from_slice(&r2.serialize());
    if let Some(msg) = m {
        data.extend_from_slice(msg);
    }

    let hash = tagged_hash(DLEQ_TAG_CHALLENGE, &data);
    Scalar::from_be_bytes(hash).expect("valid scalar from hash")
}
