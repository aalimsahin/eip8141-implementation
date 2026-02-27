#!/usr/bin/env python3
"""
Anvil EIP-8141 Demo: Send a Type 0x06 Frame Transaction

Demonstrates end-to-end EIP-8141 functionality on the forked Anvil:
1. Deploy a simple APPROVE contract (calls APPROVE opcode)
2. Build a type 0x06 frame transaction (VERIFY + SENDER frames)
3. Send via eth_sendRawTransaction
4. Verify receipt has type 0x06

Requirements:
    pip install web3 rlp

Usage:
    # Start forked anvil first
    ./target/debug/anvil --chain-id 8141

    # Run demo
    python3 devnet/anvil_demo.py
"""

import sys
import rlp
from web3 import Web3

# ─── Constants ──────────────────────────────────────────────────────────────

CHAIN_ID = 8141
RPC_URL = "http://localhost:8545"
TX_TYPE = 0x06

# Frame modes
FRAME_MODE_DEFAULT = 0
FRAME_MODE_VERIFY = 1
FRAME_MODE_SENDER = 2

# ─── Contract Bytecodes ────────────────────────────────────────────────────

# Simple APPROVE bytecode: pushes scope=0, len=0, offset=0, then calls APPROVE (0xAA).
# Stack order for popn!([offset, len, scope]): offset is TOS.
# So push order: scope (bottom), len, offset (top).
#   PUSH1 0x00  (scope = execution approval)
#   PUSH1 0x00  (length = 0)
#   PUSH1 0x00  (offset = 0)
#   APPROVE (0xAA)
APPROVE_RUNTIME = bytes([0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xAA])

# Simple constructor: copy runtime to memory and return it
# PUSH1 <size>   (runtime size)
# DUP1
# PUSH1 <offset> (constructor size = 11 bytes)
# PUSH1 0x00
# CODECOPY
# PUSH1 0x00
# RETURN
APPROVE_RUNTIME_SIZE = len(APPROVE_RUNTIME)
APPROVE_CONSTRUCTOR = bytes([
    0x60, APPROVE_RUNTIME_SIZE,  # PUSH1 runtime_size
    0x80,                         # DUP1
    0x60, 0x0B,                   # PUSH1 11 (constructor size)
    0x60, 0x00,                   # PUSH1 0
    0x39,                         # CODECOPY
    0x60, 0x00,                   # PUSH1 0
    0xF3,                         # RETURN
])
APPROVE_INIT_CODE = APPROVE_CONSTRUCTOR + APPROVE_RUNTIME

# Simple SSTORE bytecode: stores value 42 at slot 0, then STOP.
#   PUSH1 0x2A  (42)
#   PUSH1 0x00  (slot 0)
#   SSTORE
#   STOP
SSTORE_RUNTIME = bytes([0x60, 0x2A, 0x60, 0x00, 0x55, 0x00])
SSTORE_RUNTIME_SIZE = len(SSTORE_RUNTIME)
SSTORE_CONSTRUCTOR = bytes([
    0x60, SSTORE_RUNTIME_SIZE,
    0x80,
    0x60, 0x0B,
    0x60, 0x00,
    0x39,
    0x60, 0x00,
    0xF3,
])
SSTORE_INIT_CODE = SSTORE_CONSTRUCTOR + SSTORE_RUNTIME

# ─── Helpers ────────────────────────────────────────────────────────────────

def encode_frame(mode: int, target: bytes, gas_limit: int, data: bytes) -> list:
    """Encode a single frame as an RLP-compatible list."""
    return [mode, target, gas_limit, data]


def build_tx_rlp(chain_id, nonce, sender, frames, max_priority_fee, max_fee,
                 max_blob_fee, blob_hashes):
    """
    RLP-encode a TxEip8141 matching the Rust Encodable impl:
    rlp([chain_id, nonce, sender, [frames...], max_priority_fee,
         max_fee, max_blob_fee, [blob_hashes...]])
    """
    tx_list = [
        chain_id, nonce, sender, frames,
        max_priority_fee, max_fee, max_blob_fee, blob_hashes,
    ]
    return rlp.encode(tx_list)


# ─── Main Demo ──────────────────────────────────────────────────────────────

def main():
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        print(f"ERROR: Cannot connect to {RPC_URL}")
        print("Make sure anvil is running: ./target/debug/anvil --chain-id 8141")
        sys.exit(1)

    chain_id = w3.eth.chain_id
    print(f"Connected to chain ID {chain_id}")
    print()

    # Use first pre-funded Anvil account as deployer/funder
    accounts = w3.eth.accounts
    if not accounts:
        print("ERROR: No accounts available")
        sys.exit(1)

    funder = accounts[0]
    print(f"Using funder account: {funder}")
    balance = w3.eth.get_balance(funder)
    print(f"  Balance: {w3.from_wei(balance, 'ether')} ETH")
    print()

    # ── Step 1: Deploy APPROVE contract ──────────────────────────────────
    print("Step 1: Deploying APPROVE contract...")

    nonce = w3.eth.get_transaction_count(funder)
    deploy_tx = w3.eth.send_transaction({
        'from': funder,
        'nonce': nonce,
        'gas': 500_000,
        'data': APPROVE_INIT_CODE,
    })
    deploy_receipt = w3.eth.wait_for_transaction_receipt(deploy_tx)
    verifier_addr = deploy_receipt['contractAddress']
    print(f"  APPROVE contract deployed at: {verifier_addr}")
    print(f"  Gas used: {deploy_receipt['gasUsed']}")
    print()

    # ── Step 2: Deploy SSTORE target contract ────────────────────────────
    print("Step 2: Deploying SSTORE target contract...")

    nonce = w3.eth.get_transaction_count(funder)
    deploy_tx2 = w3.eth.send_transaction({
        'from': funder,
        'nonce': nonce,
        'gas': 500_000,
        'data': SSTORE_INIT_CODE,
    })
    deploy_receipt2 = w3.eth.wait_for_transaction_receipt(deploy_tx2)
    target_addr = deploy_receipt2['contractAddress']
    print(f"  SSTORE target deployed at: {target_addr}")
    print(f"  Gas used: {deploy_receipt2['gasUsed']}")
    print()

    # ── Step 3: Fund the frame tx sender ───────────────────────────────
    print("Step 3: Funding frame tx sender account...")

    sender_addr = Web3.to_checksum_address("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    nonce = w3.eth.get_transaction_count(funder)
    fund_tx = w3.eth.send_transaction({
        'from': funder,
        'to': sender_addr,
        'nonce': nonce,
        'value': w3.to_wei(10, 'ether'),
        'gas': 21_000,
    })
    w3.eth.wait_for_transaction_receipt(fund_tx)
    balance = w3.eth.get_balance(sender_addr)
    print(f"  Sender funded with {w3.from_wei(balance, 'ether')} ETH")
    print()

    # ── Step 4: Build frame transaction ──────────────────────────────────
    print("Step 4: Building type 0x06 frame transaction...")

    sender_bytes = bytes.fromhex(sender_addr[2:])
    verifier_bytes = bytes.fromhex(verifier_addr[2:])
    target_bytes = bytes.fromhex(target_addr[2:])

    # Frame 0: VERIFY — calls APPROVE contract (approves the sender)
    verify_frame = encode_frame(FRAME_MODE_VERIFY, verifier_bytes, 100_000, b'')

    # Frame 1: SENDER — calls SSTORE target (writes storage)
    sender_frame = encode_frame(FRAME_MODE_SENDER, target_bytes, 100_000, b'')

    frames = [verify_frame, sender_frame]

    tx_nonce = 0
    max_priority_fee = 1_000_000_000   # 1 gwei
    max_fee = 30_000_000_000           # 30 gwei
    max_blob_fee = 0
    blob_hashes = []

    rlp_encoded = build_tx_rlp(
        chain_id, tx_nonce, sender_bytes, frames,
        max_priority_fee, max_fee, max_blob_fee, blob_hashes
    )
    raw_tx = bytes([TX_TYPE]) + rlp_encoded

    print(f"  Sender: {sender_addr}")
    print(f"  VERIFY frame target: {verifier_addr}")
    print(f"  SENDER frame target: {target_addr}")
    print(f"  Raw tx ({len(raw_tx)} bytes): 0x{raw_tx.hex()[:80]}...")
    print()

    # ── Step 5: Send frame transaction ───────────────────────────────────
    print("Step 5: Sending frame transaction...")

    try:
        tx_hash = w3.eth.send_raw_transaction(raw_tx)
        print(f"  TX hash: 0x{tx_hash.hex()}")

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
        status = "SUCCESS" if receipt['status'] == 1 else "FAILED"
        tx_type = receipt.get('type', 'unknown')
        print(f"  Status: {status}")
        print(f"  Block: {receipt['blockNumber']}")
        print(f"  Gas used: {receipt['gasUsed']}")
        print(f"  Receipt type: {tx_type}")

        if tx_type == TX_TYPE or tx_type == hex(TX_TYPE):
            print()
            print("SUCCESS: Receipt type is 0x06 (EIP-8141 frame transaction)")
        elif receipt['status'] == 1:
            print()
            print(f"Transaction succeeded but receipt type is {tx_type}")
        else:
            print()
            print("Transaction was mined but failed execution")

    except Exception as e:
        print(f"  Transaction error: {e}")
        print()
        print("Check anvil logs for details.")
        sys.exit(1)

    # ── Step 6: Verify state changes ─────────────────────────────────────
    print()
    print("Step 6: Checking storage changes...")
    slot_value = w3.eth.get_storage_at(target_addr, 0)
    value = int.from_bytes(slot_value, 'big')
    if value == 42:
        print(f"  Storage slot 0 = {value} (expected 42)")
        print("  State changes confirmed!")
    else:
        print(f"  Storage slot 0 = {value} (expected 42)")
        print("  Storage was not modified (frame execution may have failed)")

    print()
    print("Demo complete!")


if __name__ == "__main__":
    main()
