Consensus integration — validating ZK aggregated proofs in headers

This directory contains template patches and a shadow-fork test harness to
help integrate the `ZKTx` precompile into a Geth-based consensus/validation
flow. The artifacts are intentionally conservative and include placeholders
you must adapt to the exact Geth codebase and import paths you are using.

Files
- `0002-validate-zktx-in-headers.patch`: illustrative unified diff that
  injects a header-level verification step into the block validation path.
  Edit the import path and function placement to match your Geth tree.
- `shadow_fork_test.sh`: helper script that describes how to run a local
  shadow-fork test that starts a modified node and replays blocks with the
  `ZKTx` precompile available. It relies on you applying the patch and
  building the node.

High-level design
- Use an agreed header extension or Extra data field to carry a compact
  aggregated-proof blob (or pointer to a block-level precommit). The header
  format must be validated for size and structure before cryptographic work
  is attempted.
- On header validation, decode the proof blob and call the native precompile
  (or directly call the verifier code) to verify the aggregated proof. If
  verification fails, the header must be rejected.
- Keep the verification deterministic (no external state), and ensure gas
  limits / CPU cost accounting are considered in the gas schedule when moving
  into production.

Safety notes
- Avoid running heavy crypto during gossip/fast-sync path — favour full
  nodes and validators doing full verification; provide a light-client mode
  that can skip verification if necessary.
- Protect header parsing from malformed inputs and bound the work done by
  any imported proof (byte-length limits, max inputs).

Applying the patch
1. Copy `core/precompiled/zktx` into your geth tree (see apply_pr.sh).
2. Edit `0002-validate-zktx-in-headers.patch` to match exact file names
   and import paths in your geth tree.
3. From the geth repo root run:

```bash
git apply /path/to/0002-validate-zktx-in-headers.patch
```

4. Build the node and run unit tests:

```bash
make geth
go test ./...  # run geth tests; may be slow
```

Shadow-fork testing
- After building the modified node, run `shadow_fork_test.sh` to start a
  test node with the zktx precompile registered and submit a test block
  including a sample aggregated-proof in the header (you will need to
  generate a sample proof and vk using the off-chain prover).
