# ZKTx Per-Transaction Circuit Specification

This document describes the constraints and witness layout for a single `ZKTx` transaction circuit used in a batched aggregator.

## Goals
- Prove a valid account-state transition while keeping sender, receiver, and amount confidential.
- Support Merkle inclusion/exclusion and a verifiable update to the global state root.
- Emit a nullifier to prevent double-spends.

## High-level public inputs
- `state_root_before` (field element)
- `state_root_after` (field element)
- `tx_commitment` (optional aggregate commitment; per-batch used by aggregator)
- `nullifier_commitments_root` (optional per-batch root)

Note: aggregated proof will expose only roots; per-tx details are private witnesses.

## Private witnesses (per-transaction)
- `sk`: secret key (scalar)
- `from_pub_commit`: commitment to sender public key (Poseidon)
- `to_pub_commit`: commitment to receiver public key (Poseidon)
- `balance_commit`: commitment to sender balance (Pedersen/Poseidon)
- `amount_commit`: commitment to amount
- `nonce_commit`: commitment to sender nonce
- `merkle_path`: merkle authentication path for sender leaf
- `recipient_leaf_preimage` (if destination is fresh)
- `ciphertext_payload_preimage` (for constructing commitments used in signature)

## Primitive building blocks
- Hash: Poseidon (preferred) or Pedersen for on-chain friendliness.
- Field: choose same scalar field as target SNARK (e.g., BLS12-381 scalar field for PLONK/Halo2 on that curve).
- Signature check: ZK-friendly signature verification (Schnorr on Jubjub or BLS verify-with-witness). Implement as verification-of-knowledge of `sk` by verifying a signature on committed message or use signature aggregation.

## Constraints (gates)
1. Merkle inclusion: reconstruct leaf hash from leaf preimage, and apply Poseidon hash along `merkle_path` equals `state_root_before`.
2. Signature / key ownership: either verify signature on committed plaintext or prove `pub = G*sk` knowledge (Schnorr/Fiat-Shamir transcript) and that `from_pub_commit` correctly commits `pub`.
3. Balance arithmetic in commitment space: prove that sender balance - amount - fee >= 0. Use range proofs over the committed difference (split into limbs if necessary). Use lookup tables / range-check gadgets to ensure non-negative result.
4. Updated leaves: compute new sender leaf preimage (updated balance, nonce) and compute new leaf commitment.
5. Merkle update: compute updated Merkle root after applying leaf update; aggregator will compose multiple such updates into final `state_root_after` (circuit should yield leaf-updated root as intermediate value).
6. Nullifier emission: compute `nullifier = H(sk, nonce)` or similar; enforce that `nullifier` is included in the batch-level nullifier accumulator / root. Within per-tx circuit, expose `nullifier` as private output used by aggregator-level circuit to check uniqueness.
7. Consistency: ensure ciphertext/AEAD ciphertext authenticity by including MAC commitment inside signature target or requiring ciphertext integrity via separate signature over committed plaintext.

## Performance & arithmetization tips
- Use Poseidon parameters tuned to the chosen field for fewer constraints.
- Represent balances and amounts in constrained bit-length (e.g., 128-bit) and perform range checks via custom lookup tables.
- Reduce costly big-int decomposition by performing arithmetic in field and then using range-checks only when necessary.
- Use aggregation/recursion (Halo/Halo2 or SNARK aggregation) to reduce per-block on-chain verifier cost.

## Aggregator interface notes
- Per-tx circuit should expose the following private outputs: `nullifier`, `old_leaf_commitment`, `new_leaf_commitment`, and `merkle_path_index`.
- Aggregator circuit composes N per-tx proofs by verifying per-tx outputs and re-computing sequential merkle root updates (or by verifying N subproofs via recursion / aggregation proof system).

## Edge cases
- Gas accounting and refunds: include committed fee as part of per-tx witness so aggregator can assert correct fee accounting.
- Contract creation and codehash changes: treat codehash as part of `aux_commitment` in the leaf; circuit must allow codehash updates when tx deploys contract (optional specialized handler).

## Testing & verification checklist
- Unit tests for Poseidon/commitment correctness.
- Circuit-level tests: single tx proof generation + verification against expected root change.
- Aggregator-level tests: 2..N txs aggregated producing same result as sequential application.

## References
- Poseidon hash spec
- Halo2 / PLONK circuit design references
