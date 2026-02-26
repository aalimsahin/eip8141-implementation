#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
RETH_DIR="$ROOT_DIR/reth-eip8141"
DATA_DIR="$SCRIPT_DIR/data"

echo "=== EIP-8141 Devnet ==="
echo "Chain ID: 8141"
echo "RPC: http://localhost:8545"
echo "WS: ws://localhost:8546"
echo ""

# Build the custom reth binary
echo "Building reth-eip8141..."
cd "$RETH_DIR"
cargo build --release -p reth-eip8141 2>&1 | tail -5

RETH_BIN="$RETH_DIR/target/release/reth-eip8141"

if [ ! -f "$RETH_BIN" ]; then
    echo "ERROR: Binary not found at $RETH_BIN"
    exit 1
fi

# Clean previous data if --clean flag is passed
if [ "${1:-}" = "--clean" ]; then
    echo "Cleaning previous data..."
    rm -rf "$DATA_DIR"
fi

mkdir -p "$DATA_DIR"

echo "Starting reth-eip8141 node..."
exec "$RETH_BIN" node \
    --dev \
    --dev.block-time 2s \
    --datadir "$DATA_DIR" \
    --chain "$SCRIPT_DIR/genesis.json" \
    --http \
    --http.addr 0.0.0.0 \
    --http.port 8545 \
    --http.api "eth,net,web3,txpool,debug,trace" \
    --http.corsdomain "*" \
    --ws \
    --ws.addr 0.0.0.0 \
    --ws.port 8546 \
    --ws.api "eth,net,web3,txpool" \
    --log.stdout.filter "info"
