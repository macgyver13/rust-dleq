// SPDX-License-Identifier: CC0-1.0

//! Build script for rust-dleq.
//!
//! When the `native` feature is enabled, this compiles the libsecp256k1
//! library from the git submodule with the DLEQ module enabled.

#[cfg(feature = "native")]
fn build_secp256k1() {
    use std::path::Path;

    let secp_base = Path::new("secp256k1");

    // Check if submodule is initialized
    if !secp_base.join("src/secp256k1.c").exists() {
        panic!("secp256k1 submodule not initialized. Run: git submodule update --init --recursive");
    }

    // Compile secp256k1.c (single-file compilation includes all modules)
    cc::Build::new()
        .file(secp_base.join("src/secp256k1.c"))
        // Enable required modules for Silent Payments (which includes DLEQ)
        .define("ENABLE_MODULE_SILENTPAYMENTS", None)
        .define("ENABLE_MODULE_ECDH", None)
        .define("ENABLE_MODULE_EXTRAKEYS", None) // Required by Silent Payments
        .define("ENABLE_MODULE_SCHNORRSIG", None) // Required for xonly pubkeys
        // Include paths
        .include(secp_base)
        .include(secp_base.join("include"))
        .include(secp_base.join("src"))
        // Optimization and warnings
        .opt_level(3)
        .flag_if_supported("-Wno-unused-function")
        .flag_if_supported("-Wno-unused-parameter")
        // Compile
        .compile("secp256k1");

    // Tell cargo to recompile if the secp256k1 submodule changes
    println!("cargo:rerun-if-changed=secp256k1/src");
    println!("cargo:rerun-if-changed=secp256k1/include");
}

#[cfg(not(feature = "native"))]
fn build_secp256k1() {
    // No-op when native feature is disabled
}

fn main() {
    build_secp256k1();
}
