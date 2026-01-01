// SPDX-License-Identifier: CC0-1.0

//! Direct FFI bindings to libsecp256k1 DLEQ functions from PR #1651.
//!
//! These bindings target the internal DLEQ implementation in
//! src/modules/silentpayments/dleq_impl.h

#![allow(non_camel_case_types, non_snake_case, dead_code)]

use std::os::raw::{c_int, c_uchar, c_uint, c_void};

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

// Context flags
pub const SECP256K1_CONTEXT_NONE: c_uint = 0;
pub const SECP256K1_CONTEXT_SIGN: c_uint = 1 << 0;
pub const SECP256K1_CONTEXT_VERIFY: c_uint = 1 << 1;

// Public key serialization flags
pub const SECP256K1_EC_COMPRESSED: c_uint = 1 << 0;
pub const SECP256K1_EC_UNCOMPRESSED: c_uint = 1 << 1;

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

    pub fn secp256k1_ec_pubkey_serialize(
        ctx: *const secp256k1_context,
        output: *mut c_uchar,
        outputlen: *mut usize,
        pubkey: *const secp256k1_pubkey,
        flags: c_uint,
    ) -> c_int;

    pub fn secp256k1_ec_pubkey_create(
        ctx: *const secp256k1_context,
        pubkey: *mut secp256k1_pubkey,
        seckey: *const c_uchar,
    ) -> c_int;

    // Scalar operations
    pub fn secp256k1_scalar_set_b32(
        r: *mut secp256k1_scalar,
        bin: *const c_uchar,
        overflow: *mut c_int,
    );

    pub fn secp256k1_scalar_get_b32(bin: *mut c_uchar, a: *const secp256k1_scalar);

    // ECDH (needed for a*B computation)
    pub fn secp256k1_ecdh(
        ctx: *const secp256k1_context,
        output: *mut c_uchar,
        pubkey: *const secp256k1_pubkey,
        seckey: *const c_uchar,
        hashfp: *const c_void,
        data: *mut c_void,
    ) -> c_int;
}

// Note: The actual DLEQ functions (secp256k1_dleq_prove, secp256k1_dleq_verify)
// are currently `static` in dleq_impl.h. We'll need to either:
// 1. Create C wrapper functions that expose them
// 2. Make them non-static in our fork
// 3. Duplicate the logic here
//
// For now, we'll implement the DLEQ logic in Rust using the available FFI functions
// above. This matches the standalone implementation but uses libsecp256k1 for EC ops.
