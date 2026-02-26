#!/bin/bash
set -euo pipefail

RPC_URL="${RPC_URL:-http://localhost:8545}"
# Dev account private key (Hardhat/Foundry default #0)
DEPLOYER_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

echo "=== Deploying EIP-8141 Verifier Contracts ==="
echo "RPC: $RPC_URL"
echo ""

# Check if cast is available
if ! command -v cast &> /dev/null; then
    echo "ERROR: cast (foundry) is not installed"
    echo "Install: curl -L https://foundry.paradigm.xyz | bash && foundryup"
    exit 1
fi

# Check connectivity
echo "Checking connection..."
CHAIN_ID=$(cast chain-id --rpc-url "$RPC_URL" 2>/dev/null || echo "")
if [ -z "$CHAIN_ID" ]; then
    echo "ERROR: Cannot connect to $RPC_URL"
    exit 1
fi
echo "Connected to chain ID: $CHAIN_ID"

echo ""
echo "Contracts will be deployed once the verifier bytecodes are compiled."
echo "Run 'cd contracts && ./build.sh' to compile the contracts first."
echo ""
echo "TODO: Deploy ECDSAVerifier, MultisigVerifier, WebAuthnVerifier"
