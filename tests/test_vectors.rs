use rust_dleq::{generate_dleq_proof, verify_dleq_proof, DleqProof};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::fmt::Write;
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Helper function to decode hex string to bytes
fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("Invalid hex"))
        .collect()
}

/// Helper function to encode bytes as a lowercase hex string
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{:02x}", byte).expect("writing to a String cannot fail");
    }
    out
}

/// Helper function to convert Vec<u8> to [u8; 32]
fn to_array_32(vec: Vec<u8>) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&vec);
    arr
}

/// Helper function to convert Vec<u8> to [u8; 64]
fn to_array_64(vec: Vec<u8>) -> [u8; 64] {
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&vec);
    arr
}

#[test]
fn test_vectors_generate_proof() {
    let secp = Secp256k1::new();
    let file = File::open("tests/test_vectors_generate_proof.csv")
        .expect("Failed to open test vectors file");
    let reader = BufReader::new(file);

    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;

    for (_line_num, line) in reader.lines().enumerate().skip(1) {
        let line = line.expect("Failed to read line");
        let fields: Vec<&str> = line.split(',').collect();

        if fields.len() < 7 {
            continue;
        }

        let index = fields[0];
        let point_g_hex = fields[1];
        let scalar_a_hex = fields[2];
        let point_b_hex = fields[3];
        let auxrand_r_hex = fields[4];
        let message_hex = fields[5];
        let result_proof_hex = fields[6];
        let comment = fields.get(7).unwrap_or(&"");

        println!("\n[Test {}] {}", index, comment);

        // Skip failure test cases (where result is "INVALID")
        if result_proof_hex == "INVALID" {
            println!("  SKIPPED: Expected failure case");
            skipped += 1;
            continue;
        }

        // Parse inputs
        let point_g_bytes = hex_decode(point_g_hex);
        let scalar_a_bytes = hex_decode(scalar_a_hex);
        let point_b_bytes = hex_decode(point_b_hex);
        let auxrand_r_bytes = hex_decode(auxrand_r_hex);
        let expected_proof_bytes = hex_decode(result_proof_hex);

        // Parse generator point G
        let point_g = match PublicKey::from_slice(&point_g_bytes) {
            Ok(p) => p,
            Err(e) => {
                println!("  FAILED: Could not parse point_g: {}", e);
                failed += 1;
                continue;
            }
        };

        // Check if this is the standard secp256k1 generator
        // We only support standard G now (custom generators removed)
        let standard_g = PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1,
            ])
            .unwrap(),
        );

        if point_g != standard_g {
            println!("  SKIPPED: Custom generator not supported (only standard secp256k1 G)");
            skipped += 1;
            continue;
        }

        // Parse scalar a
        let scalar_a = match SecretKey::from_slice(&scalar_a_bytes) {
            Ok(s) => s,
            Err(e) => {
                println!("  FAILED: Could not parse scalar_a: {}", e);
                failed += 1;
                continue;
            }
        };

        // Parse point B
        let point_b = match PublicKey::from_slice(&point_b_bytes) {
            Ok(p) => p,
            Err(e) => {
                println!("  FAILED: Could not parse point_b: {}", e);
                failed += 1;
                continue;
            }
        };

        // Parse auxrand
        let auxrand_r = to_array_32(auxrand_r_bytes);

        // Parse optional message
        let message = if message_hex.is_empty() {
            None
        } else {
            Some(to_array_32(hex_decode(message_hex)))
        };

        // Generate proof with standard generator
        match generate_dleq_proof(&secp, &scalar_a, &point_b, &auxrand_r, message.as_ref()) {
            Ok(proof) => {
                let expected_proof = to_array_64(expected_proof_bytes);
                if proof.as_bytes() == &expected_proof {
                    println!("  PASSED: Proof matches expected value");
                    passed += 1;
                } else {
                    println!("  FAILED: Proof mismatch");
                    println!("    Expected: {}", hex_encode(&expected_proof));
                    println!("    Got:      {}", hex_encode(proof.as_bytes()));
                    failed += 1;
                }
            }
            Err(e) => {
                println!("  FAILED: Could not generate proof: {}", e);
                failed += 1;
            }
        }
    }

    println!("\n=== Generate Proof Test Summary ===");
    println!("Passed:  {}", passed);
    println!("Failed:  {}", failed);
    println!("Skipped: {}", skipped);
    println!("Total:   {}", passed + failed + skipped);

    assert_eq!(failed, 0, "Some test vectors failed!");
}

#[test]
fn test_vectors_verify_proof() {
    let secp = Secp256k1::new();
    let file = File::open("tests/test_vectors_verify_proof.csv")
        .expect("Failed to open test vectors file");
    let reader = BufReader::new(file);

    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;

    for (_line_num, line) in reader.lines().enumerate().skip(1) {
        let line = line.expect("Failed to read line");
        let fields: Vec<&str> = line.split(',').collect();

        if fields.len() < 8 {
            continue;
        }

        let index = fields[0];
        let point_g_hex = fields[1];
        let point_a_hex = fields[2];
        let point_b_hex = fields[3];
        let point_c_hex = fields[4];
        let proof_hex = fields[5];
        let message_hex = fields[6];
        let result_success = fields[7];
        let comment = fields.get(8).unwrap_or(&"");

        println!("\n[Test {}] {}", index, comment);

        // Parse expected result
        let expected_success = result_success.trim().to_uppercase() == "TRUE";

        // Parse inputs
        let point_g_bytes = hex_decode(point_g_hex);
        let point_a_bytes = hex_decode(point_a_hex);
        let point_b_bytes = hex_decode(point_b_hex);
        let point_c_bytes = hex_decode(point_c_hex);
        let proof_bytes = hex_decode(proof_hex);

        // Parse generator point G
        let point_g = match PublicKey::from_slice(&point_g_bytes) {
            Ok(p) => p,
            Err(e) => {
                println!("  FAILED: Could not parse point_g: {}", e);
                failed += 1;
                continue;
            }
        };

        // Check if this is the standard secp256k1 generator
        // We only support standard G now (custom generators removed)
        let standard_g = PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1,
            ])
            .unwrap(),
        );

        if point_g != standard_g {
            println!("  SKIPPED: Custom generator not supported (only standard secp256k1 G)");
            skipped += 1;
            continue;
        }

        // Parse points
        let point_a = match PublicKey::from_slice(&point_a_bytes) {
            Ok(p) => p,
            Err(e) => {
                println!("  FAILED: Could not parse point_a: {}", e);
                failed += 1;
                continue;
            }
        };

        let point_b = match PublicKey::from_slice(&point_b_bytes) {
            Ok(p) => p,
            Err(e) => {
                println!("  FAILED: Could not parse point_b: {}", e);
                failed += 1;
                continue;
            }
        };

        let point_c = match PublicKey::from_slice(&point_c_bytes) {
            Ok(p) => p,
            Err(e) => {
                println!("  FAILED: Could not parse point_c: {}", e);
                failed += 1;
                continue;
            }
        };

        // Parse proof
        if proof_bytes.len() != 64 {
            println!("  FAILED: Invalid proof length: {}", proof_bytes.len());
            failed += 1;
            continue;
        }
        let proof = DleqProof::try_from(proof_bytes.as_slice()).unwrap();

        // Parse optional message
        let message = if message_hex.is_empty() {
            None
        } else {
            Some(to_array_32(hex_decode(message_hex)))
        };

        // Verify proof with standard generator
        match verify_dleq_proof(
            &secp,
            &point_a,
            &point_b,
            &point_c,
            &proof,
            message.as_ref(),
        ) {
            Ok(is_valid) => {
                if is_valid == expected_success {
                    println!(
                        "  PASSED: Verification result matches expected ({})",
                        expected_success
                    );
                    passed += 1;
                } else {
                    println!("  FAILED: Expected {}, got {}", expected_success, is_valid);
                    failed += 1;
                }
            }
            Err(e) => {
                println!("  FAILED: Verification error: {}", e);
                failed += 1;
            }
        }
    }

    println!("\n=== Verify Proof Test Summary ===");
    println!("Passed:  {}", passed);
    println!("Failed:  {}", failed);
    println!("Skipped: {}", skipped);
    println!("Total:   {}", passed + failed + skipped);

    assert_eq!(failed, 0, "Some test vectors failed!");
}
