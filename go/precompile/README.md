# Geth ZKTx Precompile Prototype

This folder contains a prototype/sketch of a native precompile for Geth that
implements `verifyAggregatedProof(bytes,bytes) -> bool` for the `ZKTx` EIP.

This code is a minimal, non-optimized skeleton intended to be integrated into
the Geth codebase as a starting point. Replace the placeholder verifier logic
with a real SNARK/STARK verifier implementation (bn256 pairings, KZG checks,
or other native verifier machinery) before production use.

Files:
- `zktx_precompile.go` — prototype Go precompile skeleton with gas estimation and Run() placeholder.
- `INTEGRATE.md` — instructions and code snippets for wiring the precompile into Geth.
