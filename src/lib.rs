// SPDX-License-Identifier: CC0-1.0

//! # rust-dleq
//!
//! BIP-374 DLEQ (Discrete Log Equality) proof generation and verification.
//!
//! This library provides cryptographic primitives for generating and verifying
//! DLEQ proofs as specified in BIP-374. DLEQ proofs demonstrate that the same
//! discrete logarithm relationship holds across two different bases.
//!
//! ## Example
//!
//! ```
//! use secp256k1::{Secp256k1, SecretKey, PublicKey};
//! use rust_dleq::{generate_dleq_proof, verify_dleq_proof};
//!
//! let secp = Secp256k1::new();
//!
//! // Generate keypair
//! let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
//! let pubkey = PublicKey::from_secret_key(&secp, &secret);
//!
//! // Scan key (recipient's public key)
//! let scan_key = PublicKey::from_secret_key(&secp,
//!     &SecretKey::from_slice(&[2u8; 32]).unwrap());
//!
//! // Compute ECDH share
//! let ecdh_share = scan_key.mul_tweak(&secp, &secret.into()).unwrap();
//!
//! // Generate DLEQ proof
//! let aux_rand = [3u8; 32];
//! let proof = generate_dleq_proof(&secp, &secret, &scan_key, &aux_rand, None).unwrap();
//!
//! // Verify the proof
//! assert!(verify_dleq_proof(&secp, &pubkey, &scan_key, &ecdh_share, &proof, None).unwrap());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(all(not(feature = "std"), feature = "serde"))]
use alloc::format;

use bitcoin_hashes::{sha256, Hash, HashEngine};
use core::fmt;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

/// Tagged hash tags for BIP-374.
const DLEQ_TAG_AUX: &str = "BIP0374/aux";
const DLEQ_TAG_NONCE: &str = "BIP0374/nonce";
const DLEQ_TAG_CHALLENGE: &str = "BIP0374/challenge";

/// A 64-byte DLEQ proof (BIP-374).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DleqProof(pub [u8; 64]);

#[cfg(feature = "serde")]
impl serde::Serialize for DleqProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            use bitcoin_hashes::hex::DisplayHex;
            serializer.serialize_str(&self.0.to_lower_hex_string())
        } else {
            serializer.serialize_bytes(&self.0[..])
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DleqProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            struct HexVisitor;
            impl serde::de::Visitor<'_> for HexVisitor {
                type Value = DleqProof;

                fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                    f.write_str("a 64-byte hex string")
                }

                fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    use bitcoin_hashes::hex::FromHex;
                    let vec = Vec::<u8>::from_hex(s).map_err(E::custom)?;
                    DleqProof::try_from(vec.as_slice()).map_err(|e| {
                        E::custom(format!("expected {} bytes, got {}", e.expected, e.got))
                    })
                }
            }
            deserializer.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;
            impl serde::de::Visitor<'_> for BytesVisitor {
                type Value = DleqProof;

                fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                    f.write_str("64 bytes")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    DleqProof::try_from(v).map_err(|e| {
                        E::custom(format!("expected {} bytes, got {}", e.expected, e.got))
                    })
                }
            }
            deserializer.deserialize_bytes(BytesVisitor)
        }
    }
}

impl DleqProof {
    /// Returns the inner 64-byte array.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl From<[u8; 64]> for DleqProof {
    fn from(bytes: [u8; 64]) -> Self {
        DleqProof(bytes)
    }
}

impl AsRef<[u8]> for DleqProof {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for DleqProof {
    type Error = InvalidLengthError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 64]>::try_from(slice)
            .map(DleqProof)
            .map_err(|_| InvalidLengthError {
                got: slice.len(),
                expected: 64,
            })
    }
}

impl TryFrom<Vec<u8>> for DleqProof {
    type Error = InvalidLengthError;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(v.as_slice())
    }
}

/// Error returned when a byte array has an invalid length for a dleq proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidLengthError {
    /// The length that was provided.
    pub got: usize,
    /// The expected length.
    pub expected: usize,
}

impl fmt::Display for InvalidLengthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "invalid length for BIP-375 type: got {}, expected {}",
            self.got, self.expected
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidLengthError {}

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
/// let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
/// let scan_key = PublicKey::from_secret_key(&secp,
///     &SecretKey::from_slice(&[2u8; 32]).unwrap());
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
    generate_dleq_proof_with_generator(secp, a, None, b, aux_rand, m)
}

/// Generate a DLEQ proof with a custom generator point.
///
/// Proves that log_G(A) = log_B(C), i.e., A = a*G and C = a*B for some secret a.
///
/// # Arguments
///
/// * `secp` - Secp256k1 context with signing and verification capabilities
/// * `a` - Secret scalar (private key)
/// * `g` - Optional custom generator point. If None, uses the standard secp256k1 generator.
/// * `b` - Public key B (typically a scan key)
/// * `aux_rand` - 32 bytes of randomness for auxiliary randomization
/// * `m` - Optional 32-byte message to include in the proof
///
/// # Returns
///
/// Returns a `DleqProof` containing a 64-byte proof: e (32 bytes) || s (32 bytes)
pub fn generate_dleq_proof_with_generator<C: secp256k1::Signing + secp256k1::Verification>(
    secp: &Secp256k1<C>,
    a: &SecretKey,
    g: Option<&PublicKey>,
    b: &PublicKey,
    aux_rand: &[u8; 32],
    m: Option<&[u8; 32]>,
) -> Result<DleqProof, DleqError> {
    // Get generator G (use custom or default)
    let g_point = g.copied().unwrap_or_else(|| {
        PublicKey::from_secret_key(
            secp,
            &SecretKey::from_slice(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1,
            ])
            .expect("valid secret key"),
        )
    });

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

    // Check if k is zero by trying to convert to SecretKey
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

    // Verify the proof before returning
    let proof = DleqProof(proof_bytes);
    if !verify_dleq_proof_with_generator(secp, &a_point, Some(&g_point), b, &c_point, &proof, m)? {
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
/// let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
/// let pubkey = PublicKey::from_secret_key(&secp, &secret);
/// let scan_key = PublicKey::from_secret_key(&secp,
///     &SecretKey::from_slice(&[2u8; 32]).unwrap());
/// let ecdh_share = scan_key.mul_tweak(&secp, &secret.into()).unwrap();
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
    verify_dleq_proof_with_generator(secp, a, None, b, c, proof, m)
}

/// Verify a DLEQ proof with a custom generator point.
///
/// Verifies that log_G(A) = log_B(C).
///
/// # Arguments
///
/// * `secp` - Secp256k1 context with verification and signing capabilities
/// * `a` - Public key A = a*G
/// * `g` - Optional custom generator point. If None, uses the standard secp256k1 generator.
/// * `b` - Public key B (typically a scan key)
/// * `c` - Public key C = a*B (ECDH share)
/// * `proof` - DLEQ proof to verify
/// * `m` - Optional 32-byte message
///
/// # Returns
///
/// Returns `Ok(true)` if the proof is valid, `Ok(false)` if invalid.
pub fn verify_dleq_proof_with_generator<C: secp256k1::Verification + secp256k1::Signing>(
    secp: &Secp256k1<C>,
    a: &PublicKey,
    g: Option<&PublicKey>,
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

    // Get generator G (use custom or default)
    let g_point = g.copied().unwrap_or_else(|| {
        PublicKey::from_secret_key(
            secp,
            &SecretKey::from_slice(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1,
            ])
            .expect("valid secret key"),
        )
    });

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

/// Error when generating or verifying a DLEQ proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DleqError {
    /// Invalid nonce scalar.
    InvalidNonce,
    /// Invalid challenge scalar.
    InvalidChallenge,
    /// Invalid proof bytes.
    InvalidProof,
    /// Tweak operation failed.
    TweakFailed,
    /// Point combination failed.
    PointCombineFailed,
    /// Self-verification of generated proof failed.
    SelfVerificationFailed,
}

impl fmt::Display for DleqError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DleqError::InvalidNonce => write!(f, "invalid nonce scalar"),
            DleqError::InvalidChallenge => write!(f, "invalid challenge scalar"),
            DleqError::InvalidProof => write!(f, "invalid proof bytes"),
            DleqError::TweakFailed => write!(f, "tweak operation failed"),
            DleqError::PointCombineFailed => write!(f, "point combination failed"),
            DleqError::SelfVerificationFailed => write!(f, "self-verification of proof failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DleqError {}

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
        let a = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let a_pub = PublicKey::from_secret_key(&secp, &a);

        // Generate public key for party B
        let b_priv = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let b = PublicKey::from_secret_key(&secp, &b_priv);

        // Compute shared secret C = a*B
        let c = b.mul_tweak(&secp, &a.into()).unwrap();

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

        let a = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let a_pub = PublicKey::from_secret_key(&secp, &a);
        let b_priv = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let b = PublicKey::from_secret_key(&secp, &b_priv);
        let c = b.mul_tweak(&secp, &a.into()).unwrap();

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

        let a = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let a_pub = PublicKey::from_secret_key(&secp, &a);
        let b_priv = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let b = PublicKey::from_secret_key(&secp, &b_priv);

        let rand_aux = [3u8; 32];
        let proof = generate_dleq_proof(&secp, &a, &b, &rand_aux, None).unwrap();

        // Verify with wrong C point should fail
        let wrong_c_priv = SecretKey::from_slice(&[99u8; 32]).unwrap();
        let wrong_c = PublicKey::from_secret_key(&secp, &wrong_c_priv);
        assert!(!verify_dleq_proof(&secp, &a_pub, &b, &wrong_c, &proof, None).unwrap());
    }

    #[test]
    fn test_dleq_proof_roundtrip() {
        let secp = Secp256k1::new();

        let a = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let a_pub = PublicKey::from_secret_key(&secp, &a);
        let b_priv = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let b = PublicKey::from_secret_key(&secp, &b_priv);
        let c = b.mul_tweak(&secp, &a.into()).unwrap();

        let rand_aux = [3u8; 32];
        let proof = generate_dleq_proof(&secp, &a, &b, &rand_aux, None).unwrap();

        // Verify the proof verifies correctly
        assert!(verify_dleq_proof(&secp, &a_pub, &b, &c, &proof, None).unwrap());
    }
}
