# Aggregator prototype (skeleton)

This folder contains a minimal Rust prototype skeleton for an off-chain aggregator that collects `ZKTx` items and constructs batch proofs.

Notes:
- This is a starter skeleton. To implement an actual prover, add a ZK backend such as `halo2_proofs` or `arkworks` and implement the circuit in `src/circuit.rs`.
- The provided `Cargo.toml` is minimal; add the required cryptography/ZK crates before building.

Quick steps to continue:
1. Add `halo2_proofs` (or chosen backend) to `Cargo.toml`.
2. Implement `src/circuit.rs` with per-tx constraints matching `docs/CIRCUIT_SPEC.md`.
3. Implement `src/aggregator.rs` to read mempool `ZKTx` objects, compute witnesses, and invoke prover.
4. Add benchmark harness to measure prover throughput per CPU/GPU instance.
