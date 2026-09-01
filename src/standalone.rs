// SPDX-License-Identifier: CC0-1.0

//! Standalone DLEQ implementation using rust-secp256k1 for EC operations.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use bitcoin_hashes::{sha256, HashEngine};
use secp256k1::constants::GENERATOR_X;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

use crate::types::{DleqError, DleqProof};

/// Tagged hash tags for BIP-374.
const DLEQ_TAG_AUX: &str = "BIP0374/aux";
const DLEQ_TAG_NONCE: &str = "BIP0374/nonce";
const DLEQ_TAG_CHALLENGE: &str = "BIP0374/challenge";

/// The standard secp256k1 generator G, in compressed form (its y coordinate is even).
fn generator_point() -> PublicKey {
    let mut serialized = [0u8; 33];
    serialized[0] = 0x02;
    serialized[1..].copy_from_slice(&GENERATOR_X);
    PublicKey::from_slice(&serialized).expect("valid generator")
}

/// Generate a DLEQ proof per BIP-374.
///
/// Proves that log_G(A) = log_B(C), i.e., A = a*G and C = a*B for some secret a.
///
/// # Arguments
///
/// * `secp` - Secp256k1 context with signing and verification capabilities
/// * `a` - Secret scalar (private key)
/// * `b` - Public key B (typically a scan key)
/// * `aux_rand` - 32 bytes of randomness for auxiliary randomization
/// * `m` - Optional 32-byte message to include in the proof
///
/// # Returns
///
/// Returns a `DleqProof` containing a 64-byte proof: e (32 bytes) || s (32 bytes)
///
/// # Errors
///
/// Returns `DleqError` if proof generation fails due to:
/// - Invalid nonce generation
/// - Failed elliptic curve operations
/// - Self-verification failure
///
/// # Example
///
/// ```
/// use secp256k1::{Secp256k1, SecretKey, PublicKey};
/// use rust_dleq::generate_dleq_proof;
///
/// let secp = Secp256k1::new();
/// let secret = SecretKey::from_secret_bytes([1u8; 32]).unwrap();
/// let scan_key = PublicKey::from_secret_key(
///     &SecretKey::from_secret_bytes([2u8; 32]).unwrap());
/// let aux_rand = [3u8; 32];
///
/// let proof = generate_dleq_proof(&secp, &secret, &scan_key, &aux_rand, None).unwrap();
/// assert_eq!(proof.as_bytes().len(), 64);
/// ```
pub fn generate_dleq_proof<C: secp256k1::Signing + secp256k1::Verification>(
    secp: &Secp256k1<C>,
    a: &SecretKey,
    b: &PublicKey,
    aux_rand: &[u8; 32],
    m: Option<&[u8; 32]>,
) -> Result<DleqProof, DleqError> {
    let g_point = generator_point();

    // Compute A = a*G and C = a*B
    let a_scalar: Scalar = (*a).into();
    let a_point = PublicKey::from_secret_key(a);
    let c_point = b.mul_tweak(&a_scalar).map_err(|_| DleqError::TweakFailed)?;

    // Compute t = a XOR H_aux(r)
    let aux_hash = tagged_hash(DLEQ_TAG_AUX, aux_rand);
    let a_bytes = a.to_secret_bytes();
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

    // Check if k is zero by trying to convert to SecretKey
    let k_key =
        SecretKey::from_secret_bytes(k.to_be_bytes()).map_err(|_| DleqError::InvalidNonce)?;

    // Compute R1 = k*G and R2 = k*B
    let r1 = PublicKey::from_secret_key(&k_key);
    let r2 = b.mul_tweak(&k).map_err(|_| DleqError::TweakFailed)?;

    // Compute challenge e = H_challenge(A, B, C, G, R1, R2, m)
    let e = dleq_challenge(&a_point, b, &c_point, &g_point, &r1, &r2, m);

    // Compute s = k + e*a (mod n)
    let e_key =
        SecretKey::from_secret_bytes(e.to_be_bytes()).map_err(|_| DleqError::InvalidChallenge)?;
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

    // Verify the proof before returning
    let proof = DleqProof(proof_bytes);
    if !verify_dleq_proof(secp, &a_point, b, &c_point, &proof, m)? {
        return Err(DleqError::SelfVerificationFailed);
    }

    Ok(proof)
}

/// Verify a DLEQ proof per BIP-374.
///
/// Verifies that log_G(A) = log_B(C).
///
/// # Arguments
///
/// * `secp` - Secp256k1 context with verification and signing capabilities
/// * `a` - Public key A = a*G
/// * `b` - Public key B (typically a scan key)
/// * `c` - Public key C = a*B (ECDH share)
/// * `proof` - DLEQ proof to verify
/// * `m` - Optional 32-byte message
///
/// # Returns
///
/// Returns `Ok(true)` if the proof is valid, `Ok(false)` if invalid.
///
/// # Errors
///
/// Returns `DleqError` if verification fails due to malformed proof or
/// failed elliptic curve operations.
///
/// # Example
///
/// ```
/// use secp256k1::{Secp256k1, SecretKey, PublicKey};
/// use rust_dleq::{generate_dleq_proof, verify_dleq_proof};
///
/// let secp = Secp256k1::new();
/// let secret = SecretKey::from_secret_bytes([1u8; 32]).unwrap();
/// let pubkey = PublicKey::from_secret_key(&secret);
/// let scan_key = PublicKey::from_secret_key(
///     &SecretKey::from_secret_bytes([2u8; 32]).unwrap());
/// let ecdh_share = scan_key.mul_tweak(&secret.into()).unwrap();
/// let aux_rand = [3u8; 32];
///
/// let proof = generate_dleq_proof(&secp, &secret, &scan_key, &aux_rand, None).unwrap();
/// assert!(verify_dleq_proof(&secp, &pubkey, &scan_key, &ecdh_share, &proof, None).unwrap());
/// ```
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

    let g_point = generator_point();

    // Compute R1 = s*G - e*A
    let s_key =
        SecretKey::from_secret_bytes(s.to_be_bytes()).map_err(|_| DleqError::TweakFailed)?;
    let s_g = PublicKey::from_secret_key(&s_key);
    let e_a = a.mul_tweak(&e).map_err(|_| DleqError::TweakFailed)?;

    let r1 = s_g
        .combine(&e_a.negate())
        .map_err(|_| DleqError::PointCombineFailed)?;

    // Compute R2 = s*B - e*C
    let s_b = b.mul_tweak(&s).map_err(|_| DleqError::TweakFailed)?;
    let e_c = c.mul_tweak(&e).map_err(|_| DleqError::TweakFailed)?;

    let r2 = s_b
        .combine(&e_c.negate())
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

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;

    #[test]
    fn test_tagged_hash() {
        let data = b"test data";
        let hash = tagged_hash(DLEQ_TAG_AUX, data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_xor_bytes() {
        let a = [0xFFu8; 32];
        let b = [0xAAu8; 32];
        let result = xor_bytes(&a, &b);
        assert_eq!(result, [0x55u8; 32]);
    }

    #[test]
    fn test_dleq_proof_generation_and_verification() {
        let secp = Secp256k1::new();

        // Generate keypair for party A
        let a = SecretKey::from_secret_bytes([1u8; 32]).unwrap();
        let a_pub = PublicKey::from_secret_key(&a);

        // Generate public key for party B
        let b_priv = SecretKey::from_secret_bytes([2u8; 32]).unwrap();
        let b = PublicKey::from_secret_key(&b_priv);

        // Compute shared secret C = a*B
        let c = b.mul_tweak(&a.into()).unwrap();

        // Generate proof
        let rand_aux = [3u8; 32];
        let proof = generate_dleq_proof(&secp, &a, &b, &rand_aux, None).unwrap();

        // Verify proof
        assert_eq!(proof.as_bytes().len(), 64);
        assert!(verify_dleq_proof(&secp, &a_pub, &b, &c, &proof, None).unwrap());
    }

    #[test]
    fn test_dleq_proof_with_message() {
        let secp = Secp256k1::new();

        let a = SecretKey::from_secret_bytes([1u8; 32]).unwrap();
        let a_pub = PublicKey::from_secret_key(&a);
        let b_priv = SecretKey::from_secret_bytes([2u8; 32]).unwrap();
        let b = PublicKey::from_secret_key(&b_priv);
        let c = b.mul_tweak(&a.into()).unwrap();

        let message = [0x42u8; 32];
        let rand_aux = [3u8; 32];

        let proof = generate_dleq_proof(&secp, &a, &b, &rand_aux, Some(&message)).unwrap();

        // Verify with correct message
        assert!(verify_dleq_proof(&secp, &a_pub, &b, &c, &proof, Some(&message)).unwrap());

        // Verify with wrong message should fail
        let wrong_message = [0x43u8; 32];
        assert!(!verify_dleq_proof(&secp, &a_pub, &b, &c, &proof, Some(&wrong_message)).unwrap());
    }

    #[test]
    fn test_dleq_proof_invalid_verification() {
        let secp = Secp256k1::new();

        let a = SecretKey::from_secret_bytes([1u8; 32]).unwrap();
        let a_pub = PublicKey::from_secret_key(&a);
        let b_priv = SecretKey::from_secret_bytes([2u8; 32]).unwrap();
        let b = PublicKey::from_secret_key(&b_priv);

        let rand_aux = [3u8; 32];
        let proof = generate_dleq_proof(&secp, &a, &b, &rand_aux, None).unwrap();

        // Verify with wrong C point should fail
        let wrong_c_priv = SecretKey::from_secret_bytes([99u8; 32]).unwrap();
        let wrong_c = PublicKey::from_secret_key(&wrong_c_priv);
        assert!(!verify_dleq_proof(&secp, &a_pub, &b, &wrong_c, &proof, None).unwrap());
    }

    #[test]
    fn test_dleq_proof_roundtrip() {
        let secp = Secp256k1::new();

        let a = SecretKey::from_secret_bytes([1u8; 32]).unwrap();
        let a_pub = PublicKey::from_secret_key(&a);
        let b_priv = SecretKey::from_secret_bytes([2u8; 32]).unwrap();
        let b = PublicKey::from_secret_key(&b_priv);
        let c = b.mul_tweak(&a.into()).unwrap();

        let rand_aux = [3u8; 32];
        let proof = generate_dleq_proof(&secp, &a, &b, &rand_aux, None).unwrap();

        // Verify the proof verifies correctly
        assert!(verify_dleq_proof(&secp, &a_pub, &b, &c, &proof, None).unwrap());
    }
}
