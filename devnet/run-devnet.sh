#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RETH_BIN="${SCRIPT_DIR}/../reth-eip8141/target/release/reth"
DATA_DIR="${SCRIPT_DIR}/data"
GENESIS="${SCRIPT_DIR}/genesis.json"

if [ ! -f "$RETH_BIN" ]; then
    echo "Reth binary not found. Building..."
    cd "${SCRIPT_DIR}/../reth-eip8141"
    cargo build --release --bin reth
    cd "$SCRIPT_DIR"
fi

# Initialize if first run
if [ ! -d "$DATA_DIR" ]; then
    echo "Initializing chain data..."
    "$RETH_BIN" init --chain "$GENESIS" --datadir "$DATA_DIR"
fi

echo "Starting EIP-8141 devnet (chainId: 8141)..."
exec "$RETH_BIN" node \
    --chain "$GENESIS" \
    --datadir "$DATA_DIR" \
    --dev \
    --dev.block-time 2s \
    --http \
    --http.addr 0.0.0.0 \
    --http.port 8545 \
    --http.api "eth,net,web3,debug,txpool" \
    --ws \
    --ws.addr 0.0.0.0 \
    --ws.port 8546 \
    --log.level debug
