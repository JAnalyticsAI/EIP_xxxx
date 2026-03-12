Integration notes — wiring the ZKTx precompile into Geth

This document describes how to prototype-wire the `ZKTx` precompile into a
Geth (go-ethereum) checkout for testing. The provided `zktx_precompile.go`
is a simple skeleton; production code must replace the placeholder verifier
with a real native verifier implementation and be audited for performance
and correctness.

1) Place the package into your local go-ethereum tree.

   For example, add the `zktx` package under:
     $GOPATH/src/github.com/ethereum/go-ethereum/core/precompiled/zktx

   or place it under an appropriate path and import it in `core/vm`.

2) Register the precompile in the VM precompile table.

   Edit `core/vm/contracts.go` (or the file where precompiles are registered)
   and add an entry mapping the reserved address `0x0B` to the new precompile.

   Example snippet (illustrative):

```go
import (
    zktx "github.com/yourfork/go-ethereum/core/precompiled/zktx"
    "github.com/ethereum/go-ethereum/common"
)

// in the precompile table init
precompiles[common.HexToAddress("0x000000000000000000000000000000000000000B")] = zktx.New()
```

3) Match the precompile interface

   The skeleton `ZKTxPrecompile` exposes `RequiredGas([]byte) uint64` and
   `Run([]byte) ([]byte, error)` methods. Geth's internal precompile interface
   may differ; adapt method signatures accordingly. In Geth, precompiles are
   often registered as `PrecompiledContract` objects with `RequiredGas` and
   `Run` methods that accept a `vm.Contract` context and gas parameter.

4) Replace placeholder verifier

   - Implement native bn256 pairing checks or KZG polynomial commitment
     verification in optimized Go (or via CGO calling performant C libs).
   - Consider using existing Go libraries for pairing (`github.com/ethereum/go-ethereum/crypto/bn256`) or linking to optimized C implementations.
   - Be careful to validate ABI decoding and reject malformed inputs quickly.

5) Benchmarking & gas tuning

   - Add microbenchmarks for the verifier to measure CPU and memory.
   - Use benchmarks to set the final gas schedule in the EIP (baseGas, perByteGas, verifierOpGas).

6) Testing

   - Use the `VerifierWrapper` / `MockVerifier` contracts in the repo to exercise the precompile via RPC in a testnet node.
   - Run shadow-fork tests and simulate aggregator/validator flows.

7) Security & deployment

   - Audit native verifier code and the MPC transcripts (if KZG/Groth16 used).
   - Coordinate with client teams and community for a consensus activation/hard-fork plan.
