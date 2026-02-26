#!/usr/bin/env bash
# Build script for EIP-8141 verifier contracts.
#
# These contracts use custom EVM opcodes (TXPARAMLOAD, APPROVE) via Yul's
# `verbatim` builtin, which is only available in standalone Yul mode
# (not in Solidity inline assembly).
#
# Usage: ./build.sh
# Requires: solc 0.8.24+ (installed via foundry's svm)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/out"
YUL_DIR="${SCRIPT_DIR}/yul"

# Find solc binary
SOLC=""
if command -v solc &>/dev/null; then
    SOLC="solc"
elif [ -f "$HOME/.svm/0.8.24/solc-0.8.24" ]; then
    SOLC="$HOME/.svm/0.8.24/solc-0.8.24"
else
    echo "Error: solc 0.8.24 not found. Install via 'foundryup' or 'svm install 0.8.24'."
    exit 1
fi

echo "Using solc: $SOLC"
$SOLC --version

mkdir -p "$OUT_DIR"

# Compile Yul contracts
for yul_file in "$YUL_DIR"/*.yul; do
    name=$(basename "$yul_file" .yul)
    echo "Compiling $name.yul..."
    $SOLC --strict-assembly --bin "$yul_file" 2>&1 | \
        grep -A1 "Binary representation:" | tail -1 > "$OUT_DIR/${name}.bin"
    echo "  -> $OUT_DIR/${name}.bin"
done

# Also compile the interface with standard solc (no verbatim needed)
echo "Compiling IFrameVerifier.sol..."
$SOLC --abi "${SCRIPT_DIR}/src/IFrameVerifier.sol" -o "$OUT_DIR" --overwrite 2>&1

echo ""
echo "Build complete. Artifacts in $OUT_DIR/"
ls -la "$OUT_DIR/"
