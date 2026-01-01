// SPDX-License-Identifier: CC0-1.0

//! # rust-dleq
//!
//! BIP-374 DLEQ (Discrete Log Equality) proof generation and verification.
//!
//! This library provides cryptographic primitives for generating and verifying
//! DLEQ proofs as specified in BIP-374. DLEQ proofs demonstrate that the same
//! discrete logarithm relationship holds across two different bases.
//!
//! ## Features
//!
//! This crate provides two implementations:
//!
//! - **`standalone`** (default): Pure Rust implementation using rust-secp256k1 for EC operations
//! - **`native`**: Uses libsecp256k1 from PR #1651 (requires git submodule)
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

// Shared types (always available)
mod types;
pub use types::{DleqError, DleqProof, InvalidLengthError};

// Feature-gated implementations
#[cfg(all(feature = "standalone", not(feature = "native")))]
mod standalone;
#[cfg(all(feature = "standalone", not(feature = "native")))]
pub use standalone::{generate_dleq_proof, verify_dleq_proof};

#[cfg(all(feature = "native", not(feature = "standalone")))]
mod native;
#[cfg(all(feature = "native", not(feature = "standalone")))]
pub use native::{generate_dleq_proof, verify_dleq_proof};

// Error if both or neither features are enabled
#[cfg(all(feature = "standalone", feature = "native"))]
compile_error!("Cannot enable both 'standalone' and 'native' features. Choose one.");

#[cfg(not(any(feature = "standalone", feature = "native")))]
compile_error!("Must enable either 'standalone' or 'native' feature.");
