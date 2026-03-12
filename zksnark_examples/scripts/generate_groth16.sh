#!/usr/bin/env bash
set -euo pipefail

# This script compiles the example circuit, creates a Groth16 setup, generates a
# proof, and exports the verification key and proof files into zksnark_examples/out/
#
# Requirements (install locally):
# - circom v2 (https://docs.circom.io/getting-started/installation/)
# - snarkjs (npm i -g snarkjs)
# - node >= 14
#
# Run from repository root:
# cd zksnark_examples && ./scripts/generate_groth16.sh

WORKDIR=$(cd "$(dirname "$0")/.." && pwd)
OUT=${WORKDIR}/out
mkdir -p "$OUT"

echo "Compiling circuit..."
circom circuits/simple.circom --r1cs --wasm --sym -o out

echo "Generating witness..."
node out/simple_js/generate_witness.js out/simple.wasm input.json out/witness.wtns

echo "Setting up Powers of Tau (local, insecure for production)"
snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v -e="some random text"

echo "Groth16 setup (zkey)"
snarkjs groth16 setup out/simple.r1cs pot12_0001.ptau out/simple_0000.zkey
snarkjs zkey contribute out/simple_0000.zkey out/simple_final.zkey --name="Contributor" -v -e="more randomness"

echo "Exporting verification key"
snarkjs zkey export verificationkey out/simple_final.zkey out/verification_key.json

echo "Creating proof"
snarkjs groth16 prove out/simple_final.zkey out/witness.wtns out/proof.json out/public.json

echo "Verifying proof (locally)"
snarkjs groth16 verify out/verification_key.json out/public.json out/proof.json

echo "Export Solidity verifier and copy outputs"
snarkjs zkey export solidityverifier out/simple_final.zkey out/Verifier.sol
cp out/proof.json "$OUT/proof.json"
cp out/public.json "$OUT/public.json"
cp out/verification_key.json "$OUT/verification_key.json"

echo "Done. Outputs in zksnark_examples/out/"
