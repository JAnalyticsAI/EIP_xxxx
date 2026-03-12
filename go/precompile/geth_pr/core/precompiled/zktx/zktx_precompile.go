package zktx

import (
    "fmt"
)

// ZKTxPrecompile is a prototype precompile that exposes a single entrypoint:
// verifyAggregatedProof(bytes proof, bytes publicInputs) -> bool
//
// This file is a skeleton containing simple gas estimation and a placeholder
// Run implementation that logs inputs and returns `false` (zero) as the
// verification result. Replace Run() with actual verifier code.
// ZKTxPrecompile is the precompile handler type. It implements a minimal
// `RequiredGas` and `Run` interface compatible with simple precompile
// registration; adapt the signatures to match the Geth version you integrate.
type ZKTxPrecompile struct{}

// New returns a new precompile instance.
// New constructs a new ZKTxPrecompile instance used during precompile
// registration in the VM precompile table.
func New() *ZKTxPrecompile { return &ZKTxPrecompile{} }

// RequiredGas returns a conservative gas estimate for the precompile call
// based on input size. Tune these constants after benchmarking the verifier.
// RequiredGas returns a conservative gas estimate for this prototype.
// Tune these values after benchmarking the native verifier implementation.
func (p *ZKTxPrecompile) RequiredGas(input []byte) uint64 {
    base := uint64(50000)   // base cost for precompile call
    perByte := uint64(16)   // per-byte calldata processing
    return base + perByte*uint64(len(input))
}

// Run is the prototype execution function for the precompile.
// In Geth integration this should match the precompile interface used by the VM.
// For the prototype we accept raw input bytes (ABI-encoded call) and return a
// 32-byte ABI-style boolean (0 / 1) in the returned byte slice.
// Run decodes the prototype ABI and invokes the native verifier. Returns a
// 32-byte ABI-encoded boolean (right-aligned) indicating verification result.
func (p *ZKTxPrecompile) Run(input []byte) ([]byte, error) {
    // Debug log for prototype runs.
    fmt.Printf("[zktx precompile] Run called: input length=%d\n", len(input))

    // Decode the three-part prototype ABI: proof, public inputs, vk.
    proofBlob, publicBlob, vkBlob, err := abiDecodeCall(input)
    if err != nil {
        return nil, err
    }

    // Parse proof and public inputs.
    proof, err := decodeProof(proofBlob)
    if err != nil {
        return nil, err
    }
    publicInputs, err := decodePublicInputs(publicBlob)
    if err != nil {
        return nil, err
    }

    // Parse verifying key and run verification.
    vk, err := decodeVK(vkBlob)
    if err != nil {
        return nil, err
    }
    ok, err := verifyGroth16(vk, proof, publicInputs)
    if err != nil {
        return nil, err
    }

    // Encode boolean result as ABI word and return.
    out := make([]byte, 32)
    if ok {
        out[31] = 1
    }
    return out, nil
}
