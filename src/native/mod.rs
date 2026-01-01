// SPDX-License-Identifier: CC0-1.0

//! Native DLEQ implementation using libsecp256k1.
//!
//! This module provides DLEQ proof generation and verification using
//! libsecp256k1's elliptic curve operations. The implementation follows
//! BIP-374 and uses the same algorithm as the standalone version, but
//! leverages libsecp256k1 for better performance and security guarantees.

mod ffi;
mod wrapper;

pub use wrapper::{generate_dleq_proof, verify_dleq_proof};
