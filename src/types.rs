// SPDX-License-Identifier: CC0-1.0

//! Shared types for DLEQ proofs.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use core::fmt;

/// A 64-byte DLEQ proof (BIP-374).
///
/// Format: e (32 bytes) || s (32 bytes)
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
                    DleqProof::try_from(vec.as_slice()).map_err(E::custom)
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
                    DleqProof::try_from(v).map_err(E::custom)
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

/// Error returned when a byte array has an invalid length for a DLEQ proof.
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
            "invalid length for BIP-374 proof: got {}, expected {}",
            self.got, self.expected
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidLengthError {}

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
