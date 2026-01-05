// SPDX-License-Identifier: CC0-1.0

//! Build script for rust-dleq.
//!
//! When the `native` feature is enabled, this compiles the libsecp256k1
//! library from the git submodule with the DLEQ module enabled.

#[cfg(feature = "native")]
fn build_secp256k1() {
    use std::env;
    use std::path::{Path, PathBuf};

    // Try multiple secp256k1sources in order of preference
    let secp_base = if let Ok(custom_path) = env::var("SECP256K1_SRC") {
        PathBuf::from(custom_path)
    } else if Path::new("secp256k1/src/secp256k1.c").exists() {
        PathBuf::from("secp256k1")
    } else if Path::new("vendor/secp256k1/src/secp256k1.c").exists() {
        PathBuf::from("vendor/secp256k1")
    } else {
        panic!(
            "secp256k1 source not found. Either:\n\
                1. Run: git submodule update --init --recursive, OR\n\
                2. Set SECP256K1_SRC environment variable, OR\n\
                3. Use the 'standalone' feature instead"
        );
    };

    // Compile secp256k1.c (single-file compilation includes all modules)
    cc::Build::new()
        .file(secp_base.join("src/secp256k1.c"))
        // Enable required modules for Silent Payments (which includes DLEQ)
        .define("ENABLE_MODULE_SILENTPAYMENTS", None)
        .define("ENABLE_MODULE_ECDH", None)
        .define("ENABLE_MODULE_EXTRAKEYS", None) // Required by Silent Payments
        .define("ENABLE_MODULE_SCHNORRSIG", None) // Required for xonly pubkeys
        // Include paths
        .include(&secp_base)
        .include(secp_base.join("include"))
        .include(secp_base.join("src"))
        // Optimization and warnings
        .opt_level(3)
        .flag_if_supported("-Wno-unused-function")
        .flag_if_supported("-Wno-unused-parameter")
        // Compile
        .compile("secp256k1");

    // Tell cargo to recompile if the secp256k1 submodule changes
    println!("cargo:rerun-if-changed={}/src", secp_base.display());
    println!("cargo:rerun-if-changed={}/include", secp_base.display());
}

#[cfg(not(feature = "native"))]
fn build_secp256k1() {
    // No-op when native feature is disabled
}

fn main() {
    build_secp256k1();
}
