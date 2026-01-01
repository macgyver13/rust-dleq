# rust-dleq



BIP-374 DLEQ (Discrete Log Equality) proof implementation for Bitcoin.

## Overview

This library implements [BIP-374](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki) DLEQ proofs, which prove that the same discrete logarithm relationship holds across two different bases without revealing the private key. Currently DLEQ proofs are primarily used in [BIP-352 Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki) to verify correct ECDH computation.

**What is a DLEQ proof?**

A DLEQ proof demonstrates: `log_G(A) = log_B(C)`

Where:

- `G` is the generator point
- `A = a·G` (your public key)
- `B` is another public key (e.g., recipient's scan key)
- `C = a·B` (ECDH shared secret)
- `a` is the private key (never revealed)

## Features

- BIP-374 compliant implementation
- Type-safe`DleqProof` wrapper
- Support for custom generator points
- `no_std` compatible (requires`alloc`)
- Optional serde support
- Minimal dependencies

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rust-dleq = "0.1"
secp256k1 = "0.29"
```

## Quick Start

### Generating a Proof

```rust
use rust_dleq::{generate_dleq_proof, DleqProof};
use secp256k1::{Secp256k1, SecretKey, PublicKey};

let secp = Secp256k1::new();

// Your private key
let secret = SecretKey::from_slice(&[0x01; 32])?;

// Recipient's scan key
let scan_key = PublicKey::from_secret_key(&secp, 
    &SecretKey::from_slice(&[0x02; 32])?);

// Generate proof (with 32 bytes of randomness)
let aux_rand = [0x03; 32];
let proof: DleqProof = generate_dleq_proof(
    &secp, 
    &secret, 
    &scan_key, 
    &aux_rand, 
    None  // Optional message
)?;

// Access proof bytes
let bytes: &[u8; 64] = proof.as_bytes();
```

### Verifying a Proof

```rust
use rust_dleq::{verify_dleq_proof, DleqProof};
use secp256k1::{Secp256k1, PublicKey};

let secp = Secp256k1::new();

// Public values
let pubkey = PublicKey::from_secret_key(&secp, &secret);
let ecdh_share = scan_key.mul_tweak(&secp, &secret.into())?;

// Verify the proof
let is_valid = verify_dleq_proof(
    &secp,
    &pubkey,
    &scan_key,
    &ecdh_share,
    &proof,
    None  // Optional message (must match generation)
)?;

assert!(is_valid);
```

### Custom Generator Points

For non-standard elliptic curve operations:

```rust
use rust_dleq::{generate_dleq_proof_with_generator, verify_dleq_proof_with_generator};

// Use custom generator point
let custom_generator = PublicKey::from_slice(&custom_point_bytes)?;

let proof = generate_dleq_proof_with_generator(
    &secp,
    &secret,
    &scan_key,
    &aux_rand,
    None,
    Some(&custom_generator)  // Custom generator
)?;

let is_valid = verify_dleq_proof_with_generator(
    &secp,
    &pubkey,
    &scan_key,
    &ecdh_share,
    &proof,
    None,
    Some(&custom_generator)  // Must match generation
)?;
```

## API Reference

### Types

- **`DleqProof`** - Type-safe wrapper for 64-byte proofs

  - `as_bytes() -> &[u8; 64]` - Get proof bytes
  - `From<[u8; 64]>` - Create from byte array
  - `TryFrom<&[u8]>` - Parse from slice
  - Optional serde support with`serde` feature
- **`DleqError`** - Error type for proof operations

  - `InvalidNonce`,`InvalidChallenge`,`InvalidProof`
  - `TweakFailed`,`PointCombineFailed`,`SelfVerificationFailed`

### Functions

- **`generate_dleq_proof()`** - Generate standard DLEQ proof
- **`generate_dleq_proof_with_generator()`** - Generate with custom generator
- **`verify_dleq_proof()`** - Verify standard DLEQ proof
- **`verify_dleq_proof_with_generator()`** - Verify with custom generator

## Features

```toml
[dependencies]
rust-dleq = { version = "0.1", features = ["serde"] }
```

- **`std`** (default) - Standard library support
- **`serde`** - Serialize/deserialize`DleqProof` as hex or bytes

## `no_std` Support

For embedded or `no_std` environments:

```toml
[dependencies]
rust-dleq = { version = "0.1", default-features = false }
```

Requires `alloc` for dynamic allocations.

## Technical Details

### Proof Structure

A DLEQ proof consists of 64 bytes: `[s || e]`

- `s` (32 bytes) - Scalar proof component
- `e` (32 bytes) - Challenge hash

### Tagged Hashes

Uses BIP-340 style tagged hashing:

- `BIP0374/aux` - Auxiliary randomness processing
- `BIP0374/nonce` - Nonce generation
- `BIP0374/challenge` - Challenge computation

### Security Notes

- **Randomness**: Always use cryptographically secure random bytes for`aux_rand`
- **Reuse**: Don't reuse the same`aux_rand` for multiple proofs with the same key pair
- **Verification**: Proofs include self-verification to catch implementation errors

## Testing

The library includes comprehensive test vectors from BIP-374:

```bash
# Run all tests
cargo test

# Run with serde support
cargo test --features serde

# Run test vectors
cargo test --test test_vectors
```

Test vectors are located in `tests/test_vectors_*.csv`.

## License

CC0-1.0 - Public Domain

## Resources

- [BIP-374: Discrete Log Equality Proofs](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki)
- [BIP-352: Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1)

## Contributing

Contributions are welcome. Please ensure:

- All tests pass (`cargo test --all-features`)
- Code follows Rust conventions
- Documentation is updated for API changes
