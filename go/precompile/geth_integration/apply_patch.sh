#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 /path/to/go-ethereum-root"
  exit 2
fi

GETH_ROOT="$1"
PATCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH_FILE="$PATCH_DIR/0001-register-zktx-precompile.patch"

if [ ! -f "$PATCH_FILE" ]; then
  echo "patch file not found: $PATCH_FILE"
  exit 2
fi

echo "Applying patch to $GETH_ROOT"
cp "$PATCH_FILE" /tmp/zktx_register.patch
pushd "$GETH_ROOT" > /dev/null
if git apply /tmp/zktx_register.patch; then
  echo "Patch applied. Please review changes, adjust import path if necessary, then run 'go test ./...'"
else
  echo "git apply failed. Open $PATCH_FILE and apply changes manually."
fi
popd > /dev/null
