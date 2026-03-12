#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <your-github-fork-clone-url> <branch-name> [base-branch]"
  echo "example: $0 git@github.com:youruser/go-ethereum.git feature/zktx-precompile main"
  exit 2
fi

FORK_URL="$1"
BRANCH="$2"
BASE_BRANCH="${3:-main}"

TMPDIR=$(mktemp -d)
echo "Cloning fork into $TMPDIR"
git clone "$FORK_URL" "$TMPDIR/repo"
pushd "$TMPDIR/repo" > /dev/null

git checkout -b "$BRANCH" "origin/$BASE_BRANCH"

SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Copying zktx package into repo/core/precompiled/zktx"
mkdir -p core/precompiled/zktx
SRC="$SCRIPTDIR/core/precompiled/zktx"
if [ ! -d "$SRC" ]; then
  echo "source package not found: $SRC"
  exit 2
fi
cp -r "$SRC/"* core/precompiled/zktx/

echo "Adding registration patch"
cp "$SCRIPTDIR/0001-register-zktx-precompile.patch" /tmp/zktx_register.patch
if git apply /tmp/zktx_register.patch; then
  echo "Patch applied"
else
  echo "Patch failed to apply automatically. Please open /tmp/zktx_register.patch and apply manually."
fi

git add core/precompiled/zktx
git commit -m "precompile: add ZKTx precompile package"

echo "Pushing branch to origin"
git push origin "$BRANCH"

echo "Done. Create a PR from $BRANCH against $BASE_BRANCH in your fork."
popd > /dev/null
