# Contracts test helpers

This folder contains two helper contracts used in testing the `ZKTx` precompile design:

- `MockVerifier.sol` — a minimal test-only verifier that returns true for non-empty proofs.
- `VerifierWrapper.sol` — a wrapper that calls the configured verifier address (defaults to precompile slot `0x0B` if constructed with zero address).

Run tests (from repository root):

```bash
npm install
npx hardhat test
```

This will compile the contracts in `contracts/` and run the test in `test/verifier.test.js`.
