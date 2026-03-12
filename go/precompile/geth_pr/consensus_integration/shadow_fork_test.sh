#!/usr/bin/env bash
set -euo pipefail

# Shadow-fork test harness (instructions)
# This script contains commands and notes to run a shadow-fork test after
# you've applied the precompile and consensus patches to your local geth
# checkout and built a modified `geth` binary.

if [ "$#" -ne 1 ]; then
  echo "usage: $0 /path/to/modified/geth/binary"
  exit 2
fi

GETH_BIN="$1"

echo "1) Start a modified geth node (dev mode) with RPC enabled and the zktx precompile registered."
echo "   Use a separate datadir to avoid corrupting your main node."

DATADIR="/tmp/geth-zktx-shadow"
rm -rf "$DATADIR"
mkdir -p "$DATADIR"

"$GETH_BIN" --dev --http --http.addr 127.0.0.1 --http.port 8545 --datadir "$DATADIR" &
G_PID=$!
echo "started geth (pid=$G_PID)"

echo "2) Wait a few seconds for the node to boot, then use RPC to submit a block/header or run a local miner."
echo "   For an automated flow, you must generate a sample aggregated-proof and embed it into the header Extra field."

echo "3) Use curl or web3 to send transactions and verify the node accepts blocks with valid proofs and rejects invalid ones."

echo "When done, kill the node: kill $G_PID"
