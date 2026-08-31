// SPDX-License-Identifier: CC0-1.0

//! Direct FFI bindings to libsecp256k1 DLEQ functions from PR #1802.
//!
//! These bindings target the internal DLEQ implementation in
//! src/modules/silentpayments/dleq_impl.h

#![allow(non_camel_case_types, non_snake_case, dead_code)]

use std::os::raw::{c_int, c_uchar, c_uint};

/// Opaque secp256k1 context type
#[repr(C)]
pub struct secp256k1_context {
    _private: [u8; 0],
}

/// secp256k1 public key (64 bytes internal representation)
#[repr(C)]
pub struct secp256k1_pubkey {
    pub data: [c_uchar; 64],
}

/// secp256k1 scalar (internal representation)
#[repr(C)]
pub struct secp256k1_scalar {
    pub d: [u32; 8],
}

/// secp256k1 group element (affine coordinates)
#[repr(C)]
pub struct secp256k1_ge {
    pub x: secp256k1_fe,
    pub y: secp256k1_fe,
    pub infinity: c_int,
}

/// secp256k1 field element
#[repr(C)]
pub struct secp256k1_fe {
    pub n: [u32; 10],
}

// Flag type masks
pub const SECP256K1_FLAGS_TYPE_CONTEXT: c_uint = 1 << 0;
pub const SECP256K1_FLAGS_TYPE_COMPRESSION: c_uint = 1 << 1;
pub const SECP256K1_FLAGS_BIT_CONTEXT_VERIFY: c_uint = 1 << 8;
pub const SECP256K1_FLAGS_BIT_CONTEXT_SIGN: c_uint = 1 << 9;
pub const SECP256K1_FLAGS_BIT_COMPRESSION: c_uint = 1 << 8;

// Context flags
pub const SECP256K1_CONTEXT_NONE: c_uint = SECP256K1_FLAGS_TYPE_CONTEXT;
pub const SECP256K1_CONTEXT_SIGN: c_uint =
    SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN;
pub const SECP256K1_CONTEXT_VERIFY: c_uint =
    SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY;

// Public key serialization flags
pub const SECP256K1_EC_COMPRESSED: c_uint =
    SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION;
pub const SECP256K1_EC_UNCOMPRESSED: c_uint = SECP256K1_FLAGS_TYPE_COMPRESSION;

extern "C" {
    // Context management
    pub fn secp256k1_context_create(flags: c_uint) -> *mut secp256k1_context;
    pub fn secp256k1_context_destroy(ctx: *mut secp256k1_context);

    // Public key operations
    pub fn secp256k1_ec_pubkey_parse(
        ctx: *const secp256k1_context,
        pubkey: *mut secp256k1_pubkey,
        input: *const c_uchar,
        inputlen: usize,
    ) -> c_int;
}

/// DLEQ proof structure (64 bytes: e || s)
#[repr(C)]
pub struct secp256k1_dleq_proof {
    pub data: [c_uchar; 64],
}

extern "C" {
    /// Generate a DLEQ proof.
    ///
    /// Returns: 1 on success, 0 on failure
    pub fn secp256k1_dleq_prove(
        ctx: *const secp256k1_context,
        proof: *mut secp256k1_dleq_proof,
        seckey32: *const c_uchar,
        pubkey_B: *const secp256k1_pubkey,
        aux_rand32: *const c_uchar,
        msg: *const c_uchar,
    ) -> c_int;

    /// Verify a DLEQ proof.
    ///
    /// Returns: 1 if valid, 0 if invalid
    pub fn secp256k1_dleq_verify(
        ctx: *const secp256k1_context,
        proof: *const secp256k1_dleq_proof,
        pubkey_A: *const secp256k1_pubkey,
        pubkey_B: *const secp256k1_pubkey,
        pubkey_C: *const secp256k1_pubkey,
        msg: *const c_uchar,
    ) -> c_int;
}
