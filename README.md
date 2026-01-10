# rust-dleq

BIP-374 DLEQ (Discrete Log Equality) proof implementation for Bitcoin.

## Overview

This library implements [BIP-374](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki) DLEQ proofs, which prove that the same discrete logarithm relationship holds across two different bases without revealing the private key. DLEQ proofs are primarily used in [BIP-352 Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki) to verify correct ECDH computation.

**Implementation Status:** This crate is based on [libsecp256k1 PR #1651](https://github.com/bitcoin-core/secp256k1/pull/1651) and is planned to be upstreamed to [rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1) as this implementation matures.  [Contributions](#contributing) are welcome!

## Features

- **`standalone`** (default): Pure Rust implementation using rust-secp256k1 for EC operations
- **`native`**: Direct FFI to libsecp256k1 (requires secp256k1 git submodule)
- BIP-374 v0.2.0  compliant with test vectors
- Type-safe`DleqProof` wrapper
- `no_std` compatible (requires`alloc`)
- Optional serde support

## Installation

```toml
[dependencies]
rust-dleq = "0.1"
secp256k1 = "0.29"
```

For native implementation (using libsecp256k1 directly):

```toml
[dependencies]
rust-dleq = { version = "0.1", default-features = false, features = ["native"] }
```

**Note:** The `native` feature requires secp256k1 source files. The build script checks:
1. `vendor/secp256k1/` (vendored copy, included in repo)
2. `secp256k1/` (git submodule: `git clone --branch dleq-sp-stratospher https://github.com/macgyver13/secp256k1.git secp256k1`)
3. Custom path via `SECP256K1_SRC` environment variable

## Quick Start with Just

This project uses [`just`](https://github.com/casey/just) for task running:

```bash
# Test with standalone (default, pure Rust)
just test-standalone

# Test with native (libsecp256k1 FFI)
just test-native

# Run all checks and tests for both implementations
just check
just test
just build
```

## Usage

```rust
use rust_dleq::{generate_dleq_proof, verify_dleq_proof, DleqProof};
use secp256k1::{Secp256k1, SecretKey, PublicKey};

let secp = Secp256k1::new();

// Your private key
let secret = SecretKey::from_slice(&[0x01; 32])?;
let pubkey = PublicKey::from_secret_key(&secp, &secret);

// Recipient's scan key
let scan_key = PublicKey::from_secret_key(&secp,
    &SecretKey::from_slice(&[0x02; 32])?);

// Compute ECDH shared secret
let ecdh_share = scan_key.mul_tweak(&secp, &secret.into())?;

// Generate proof with 32 bytes of randomness
let aux_rand = [0x03; 32];
let proof = generate_dleq_proof(&secp, &secret, &scan_key, &aux_rand, None)?;

// Verify the proof
let is_valid = verify_dleq_proof(&secp, &pubkey, &scan_key, &ecdh_share, &proof, None)?;
assert!(is_valid);
```

## API

**Types:**

- `DleqProof` - Type-safe 64-byte proof wrapper with serde support

**Functions:**

- `generate_dleq_proof(secp, secret, point, aux_rand, msg)` - Generate proof
- `verify_dleq_proof(secp, pubkey, point, result, proof, msg)` - Verify proof

**Cargo Features:**

- `standalone` (default) - Pure Rust implementation
- `native` - libsecp256k1 FFI implementation
- `serde` - Serialization support
- `std` (default) - Standard library (disable for`no_std`)

## Testing

```bash
# Using just (recommended)
just test              # Test both implementations
just test-standalone   # Test standalone only
just test-native       # Test native only

# Using cargo directly
cargo test --features standalone
cargo test --no-default-features --features native
```

Test vectors from BIP-374 are in `tests/test_vectors_*.csv`.

## Updating Vendored secp256k1 Files

The `native` feature uses vendored secp256k1 C library files with DLEQ support. To update these files from your local secp256k1 repository:

```bash
# Use default path ($HOME/src/secp256k1)
just update-vendor

# Or specify a custom path
just update-vendor /path/to/secp256k1
```

This command:
- Cleans existing vendored files to avoid bloat
- Copies headers, modules, and precomputed tables (~3.3MB)
- Ensures the vendored copy stays in sync with upstream

**What gets updated:**
- Public API headers (`include/secp256k1*.h`)
- Module implementations (`src/modules/*`)
- Source headers and main file (`src/*.h`, `src/secp256k1.c`)
- Precomputed tables (`src/precomputed_*.c` - 2.5MB)

## Contributing

Contributions are welcome! Please ensure:

```bash
just fmt     # Format code
just lint    # Run clippy on both implementations
just test    # All tests pass
```

## Resources

- [BIP-374: Discrete Log Equality Proofs](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki)
- [BIP-352: Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [libsecp256k1 PR #1651](https://github.com/bitcoin-core/secp256k1/pull/1651)
- [rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1)

## License

CC0-1.0 - Public Domain