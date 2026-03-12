---
eip: xxxx
title: ZK-Transactions (ZKTx) — Aggregated On-Chain Verifier Precompile
author: JAnalyticsAI
status: Draft
type: Standards Track
created: 2026-03-12
requires: Consensus hard-fork to add precompile and header fields
---

## Abstract

This EIP specifies protocol-level support for privacy-preserving ZK transactions (`ZKTx`) by requiring a single aggregated zero-knowledge proof per block that attests to the correctness of all included state transitions. It defines the block-header commitments, a verifier precompile API for the aggregated proof, gas guidance, and an activation plan for migration to 100% shielded transactions.

## Motivation

To provide native, protocol-level confidentiality for all Ethereum transactions while keeping L1 verification feasible, ZK proofs must be aggregated per-block and verified by a low-cost on-chain primitive. This EIP standardizes how aggregators publish aggregated proofs and how validators verify them during block validation.

## Specification

Overview:
- Transaction model: clients submit `ZKTx` objects to mempool (encrypted payload + commitments + nullifier). Aggregator collects N `ZKTx` per block, produces `aggregated_proof` and `proof_public_inputs` that publicly commit to `state_root_before` and `state_root_after`.
- Block header additions (new fields): `zk_aggregated_proof` (bytes), `zk_public_inputs` (bytes), `zk_aggregator` (address)

Block header JSON example (illustrative):

{
  "parentHash": "0x...",
  "ommersHash": "0x...",
  "beneficiary": "0x...",
  "stateRoot": "0x<state_root_before>",
  "transactionsRoot": "0x...",
  "receiptsRoot": "0x...",
  "logsBloom": "0x...",
  "difficulty": "0x...",
  "number": "0x...",
  "gasLimit": "0x...",
  "gasUsed": "0x...",
  "timestamp": "0x...",
  "extraData": "0x...",
  "mixHash": "0x...",
  "nonce": "0x...",
  "zk_aggregated_proof": "0x<bytes>",
  "zk_public_inputs": "0x<bytes>",
  "zk_aggregator": "0x...",
  "stateRootAfter": "0x<state_root_after>"
}

Note: `stateRootAfter` duplicates the semantic of `state_root_after` embedded in `zk_public_inputs`. This explicit field is optional but recommended for clarity; implementations may prefer deriving the new root from the public inputs.

Precompile API
- Address: `0x0B` (example; reserved precompile slot via Consensus change)
- Interface (ABI-like):

function verifyAggregatedProof(bytes proof, bytes publicInputs) public view returns (bool);

- Semantics: `proof` is the aggregator's aggregated proof bytes; `publicInputs` is a compact serialization of public inputs (e.g., `state_root_before`, `state_root_after`, nullifier root commitments, optional metadata). The precompile returns `true` if the proof verifies against `publicInputs` under the agreed curve/params, otherwise `false`.

Gas schedule guidance
- Gas for calling the precompile should be priced to reflect verifier cost; suggested regime:
  - `verifyAggregatedProof`: baseGas + perByteGas * proof.length + verifierOpGas
  - Example: baseGas = 50,000; perByteGas = 16; verifierOpGas = implementation-dependent (e.g., 200,000 for PLONK-like KZG pairing checks). Final values determined by consensus discussion and benchmarks.

Consensus rules
- Block proposal: proposer must include `zk_aggregated_proof` and `zk_public_inputs` in header. When validating the header, every full node must call the precompile and require `true` to accept header as valid.
- If `verifyAggregatedProof` returns `false`, the block is invalid and must be rejected.

Migration & activation
- Phase 0 (opt-in): RPC + mempool support for `ZKTx`; aggregators publish proofs off-chain.
- Phase 1 (soft support): clients accept blocks with optional `zk_aggregated_proof` (unverified), validators continue to accept legacy txs.
- Phase 2 (hard fork): change consensus so that all blocks must include a valid `zk_aggregated_proof`; legacy txs no longer accepted.

Trusted setup & parameters
- If the chosen proof system requires trusted-setup (e.g., KZG/Groth16), run a public multi-party computation (MPC) ceremony with wide, audited participation and publish transcripts and verification tools.
- Optionally permit multiple verifier parameter sets (curve + parameters) with on-chain governance to rotate if compromise suspected.

Security considerations
- Aggregator centralization risk: incentivize multiple independent aggregators and allow clients to fallback to alternative aggregators.
- Denial-of-service: limit maximum proof size or gas per block and enforce upper bound on included txs or computation budget.
- Lawful access: do not include backdoors; implement view-keys off-chain for selective disclosure.

Implementers' notes
- Precompile implementors should optimize pairing operations and curve math in native code (client-level) to minimize gas and CPU overhead.
- Provide an EVM-level fallback verifier (slow, expensive) only for testing; mainline relies on precompile.

Appendix: Example precompile call (pseudo-JSON-RPC)

eth_call {
  "to": "0x000000000000000000000000000000000000000B",
  "data": "0x<abi-encoded verifyAggregatedProof(proof, publicInputs)>"
}

Appendix: Example publicInputs layout (binary / TLV suggestion)
- 0x01 | 32 bytes | state_root_before
- 0x02 | 32 bytes | state_root_after
- 0x03 | 32 bytes | nullifier_root
- 0x04 | variable | auxiliary metadata (block number, aggregator id, merkle_commit)

Rationale for precompile vs contract-level
- Precompile (native) verification is required to keep gas low. Implementing full verifier in EVM bytecode is prohibitively expensive for production use.

Backward compatibility
- To support a gradual transition, nodes may accept both legacy and ZK-enabled blocks during the migration window; the hard-fork enforces mandatory inclusion.

Audit & testing recommendations
- Provide reference verifier implementations in client code and in EVM (for unit tests only).
- Run conformance tests, shadow forks, and incentivized testnets prior to activation.

Acknowledgements
- Based on design discussions and ZK literature (PLONK, Groth16, Halo2, STARKs).
