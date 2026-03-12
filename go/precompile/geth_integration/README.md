Geth integration patch for ZKTx precompile

This folder contains a suggested patch you can apply to a local go-ethereum
checkout to register the `ZKTx` precompile (prototype) at the reserved
address 0x000...0B.

Contents
- `0001-register-zktx-precompile.patch`: unified diff that adds an import and
  a registration line to the precompile table in `core/vm/contracts.go`.
- `apply_patch.sh`: helper script to apply the patch (adjust paths as needed).

How to use
1. Clone or open your local go-ethereum repository (matching the Geth version
   you plan to patch).
2. Copy the `zktx` package (this repo's `go/precompile` folder) into your
   go-ethereum tree under `core/precompiled/zktx` or another suitable path.
3. Review and edit `0001-register-zktx-precompile.patch` to match the exact
   import path you used in step 2.
4. From the root of your go-ethereum checkout run:

```bash
./go/precompile/geth_integration/apply_patch.sh /path/to/go-ethereum
```

5. Run `go test ./...` in your modified go-ethereum repo and build a node to
   smoke-test the precompile.

Notes
- This patch is intentionally small and conservative: it only registers the
  precompile in the precompile table. You must adapt method signatures and
  plumbing if the Geth version you patch has a different precompile API.
- Always run the full test-suite and benchmarks after integrating native
  cryptographic code.
