#ifndef SECP256K1_DLEQ_H
#define SECP256K1_DLEQ_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** This module provides an implementation of Discrete Log Equality (DLEQ) proofs,
 *  as specified in BIP-374. A DLEQ proof allows proving knowledge of a discrete
 *  logarithm relationship between two pairs of elliptic curve points without
 *  revealing the secret scalar.
 *
 *  Specifically, given points A, B, C, and the generator G, a DLEQ proof
 *  demonstrates that A = a*G and C = a*B for the same scalar a, without
 *  revealing a.
 *
 *  The proof consists of two 32-byte scalars (s, e) totaling 64 bytes.
 */

/** Opaque data structure for a DLEQ proof.
 *
 *  Serialized as 64 bytes: proof = bytes(32, s) || bytes(32, e)
 */
typedef struct {
    unsigned char data[64];
} secp256k1_dleq_proof;

/** Generate a DLEQ proof.
 *
 *  Proves knowledge of scalar a such that A = a*G and C = a*B without
 *  revealing a. The function computes A and C internally.
 *
 *  Returns: 1 if proof generation succeeded
 *           0 if nonce generation failed (negligible probability) or
 *             if any input is invalid
 *
 *  Args:        ctx: pointer to a context object (not secp256k1_context_static)
 *  Out:       proof: pointer to DLEQ proof structure to be filled
 *  In:     seckey32: pointer to 32-byte secret key (scalar a)
 *          pubkey_B: pointer to public key B (base point)
 *       aux_rand32: pointer to 32-byte auxiliary randomness (can be NULL)
 *              msg: pointer to optional 32-byte message (can be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_dleq_prove(
    const secp256k1_context *ctx,
    secp256k1_dleq_proof *proof,
    const unsigned char *seckey32,
    const secp256k1_pubkey *pubkey_B,
    const unsigned char *aux_rand32,
    const unsigned char *msg
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3)
  SECP256K1_ARG_NONNULL(4);

/** Verify a DLEQ proof.
 *
 *  Verifies that A and C were generated from the same scalar.
 *
 *  Returns: 1 if proof is valid
 *           0 if proof is invalid or any input is invalid
 *
 *  Args:       ctx: pointer to a context object
 *  In:       proof: pointer to DLEQ proof structure
 *         pubkey_A: pointer to public key A
 *         pubkey_B: pointer to public key B (base point)
 *         pubkey_C: pointer to public key C
 *              msg: pointer to optional 32-byte message (can be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_dleq_verify(
    const secp256k1_context *ctx,
    const secp256k1_dleq_proof *proof,
    const secp256k1_pubkey *pubkey_A,
    const secp256k1_pubkey *pubkey_B,
    const secp256k1_pubkey *pubkey_C,
    const unsigned char *msg
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3)
  SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Serialize a DLEQ proof.
 *
 *  Returns: 1 always
 *  Args:    ctx: pointer to a context object
 *  Out:   out64: pointer to 64-byte array to store serialized proof
 *  In:    proof: pointer to proof object
 */
SECP256K1_API int secp256k1_dleq_proof_serialize(
    const secp256k1_context *ctx,
    unsigned char *out64,
    const secp256k1_dleq_proof *proof
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse a DLEQ proof.
 *
 *  Returns: 1 if parsing succeeded
 *           0 if input is invalid
 *  Args:    ctx: pointer to a context object
 *  Out:   proof: pointer to proof object
 *  In:     in64: pointer to 64-byte serialized proof
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_dleq_proof_parse(
    const secp256k1_context *ctx,
    secp256k1_dleq_proof *proof,
    const unsigned char *in64
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_DLEQ_H */
