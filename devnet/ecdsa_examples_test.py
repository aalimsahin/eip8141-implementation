#!/usr/bin/env python3
"""
ECDSA Example Suite for EIP-8141 (Type 0x06)

This script validates the same EIP-8141 example flows used in passkey tests,
but with classic secp256k1 ECDSA signatures verified via ECRECOVER precompile.

Covered flows:
1. Example 1: Simple transaction (VERIFY + SENDER)
2. Example 1a: Simple ETH transfer via sender smart-account self-call
3. Example 1b: Deployment-style flow in one tx (DEFAULT + VERIFY + SENDER)
4. Example 2: Sponsored-style multi-frame flow (VERIFY/VERIFY/SENDER/SENDER/DEFAULT)

Requirements:
    pip install web3 rlp eth-keys

Usage:
    cd foundry && cargo run -p anvil -- --chain-id 8141
    python3 devnet/ecdsa_examples_test.py
"""

import os
import sys
import rlp
from eth_keys import keys
from web3 import Web3

from erc20_helpers import (
    build_sponsor_policy_verifier_runtime,
    erc20_deploy_data,
    erc20_sponsor_policy_data,
    erc20_transfer_calldata,
    query_erc20_balance,
)


# ─── Constants ──────────────────────────────────────────────────────────────

RPC_URL = "http://localhost:8545"
TX_TYPE = 0x06

FRAME_MODE_DEFAULT = 0
FRAME_MODE_VERIFY = 1
FRAME_MODE_SENDER = 2

MAX_PRIORITY_FEE = 1_000_000_000  # 1 gwei
MAX_FEE = 30_000_000_000          # 30 gwei
MAX_BLOB_FEE = 0
BLOB_HASHES = []


# ─── Helpers ────────────────────────────────────────────────────────────────


def expect(cond: bool, message: str):
    if not cond:
        raise AssertionError(message)


def normalize_receipt_type(raw_type) -> int:
    if raw_type is None:
        return -1
    if isinstance(raw_type, int):
        return raw_type
    if isinstance(raw_type, str):
        return int(raw_type, 16) if raw_type.startswith("0x") else int(raw_type)
    if isinstance(raw_type, (bytes, bytearray)):
        return int.from_bytes(raw_type, "big")
    return int(raw_type)


def mk_init_code(runtime: bytes) -> bytes:
    # Minimal constructor that returns runtime as deployed code.
    expect(len(runtime) <= 0xFF, "runtime too large for PUSH1-sized constructor")
    constructor = bytes([
        0x60, len(runtime),  # PUSH1 runtime_size
        0x80,                # DUP1
        0x60, 0x0B,          # PUSH1 constructor_size
        0x60, 0x00,          # PUSH1 dst
        0x39,                # CODECOPY
        0x60, 0x00,          # PUSH1 dst
        0xF3,                # RETURN
    ])
    return constructor + runtime


def sstore_runtime(value: int) -> bytes:
    expect(0 <= value <= 0xFF, "value must fit in PUSH1")
    # PUSH1 value, PUSH1 0x00, SSTORE, STOP
    return bytes([0x60, value, 0x60, 0x00, 0x55, 0x00])


def sstore_increment_runtime() -> bytes:
    """
    Runtime that increments slot0 by 1 on each call:
      PUSH1 0x00
      SLOAD
      PUSH1 0x01
      ADD
      PUSH1 0x00
      SSTORE
      STOP
    """
    return bytes([0x60, 0x00, 0x54, 0x60, 0x01, 0x01, 0x60, 0x00, 0x55, 0x00])


def build_ecdsa_verifier_runtime(authorized_signer: str, approve_scope: int) -> bytes:
    """
    Runtime verifier logic:
    1) hash = TXPARAMLOAD(0x08, 0)
    2) r,s,v = calldata[0:96] where v is 32-byte value (27 or 28)
    3) STATICCALL ecrecover precompile (0x01)
    4) Compare recovered address with hardcoded authorized_signer
    5) APPROVE(scope, 0, 0)
    """
    expect(approve_scope in (0, 1, 2), "approve scope must be 0/1/2")
    signer_bytes = bytes.fromhex(authorized_signer[2:])
    expect(len(signer_bytes) == 20, "authorized signer must be 20 bytes")
    signer_word = b"\x00" * 12 + signer_bytes

    # Revert jumpdest fixed at 0x5A for this exact layout.
    runtime = (
        bytes([
            0x60, 0x00,
            0x60, 0x08,
            0xB0,
            0x60, 0x00,
            0x52,
            0x60, 0x00,
            0x35,
            0x60, 0x40,
            0x52,
            0x60, 0x20,
            0x35,
            0x60, 0x60,
            0x52,
            0x60, 0x40,
            0x35,
            0x60, 0x20,
            0x52,
            0x60, 0x20,
            0x60, 0xA0,
            0x60, 0x80,
            0x60, 0x00,
            0x60, 0x01,
            0x5A,
            0xFA,
            0x15,
            0x60, 0x5A,
            0x57,
            0x60, 0xA0,
            0x51,
            0x7F,
        ])
        + signer_word
        + bytes([
            0x14,
            0x15,
            0x60, 0x5A,
            0x57,
            0x60, approve_scope,
            0x60, 0x00,
            0x60, 0x00,
            0xAA,
            0x5B,
            0x60, 0x00,
            0x60, 0x00,
            0xFD,
        ])
    )
    expect(len(runtime) == 0x60, f"unexpected ecdsa verifier runtime len: {len(runtime)}")
    return runtime


def deploy_contract(w3, funder: str, init_code: bytes, gas: int = 700_000) -> str:
    nonce = w3.eth.get_transaction_count(funder)
    tx_hash = w3.eth.send_transaction({
        "from": funder,
        "nonce": nonce,
        "gas": gas,
        "data": init_code,
    })
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    expect(int(receipt["status"]) == 1, "deployment failed")
    return Web3.to_checksum_address(receipt["contractAddress"])


def encode_frame(mode: int, target: bytes, gas_limit: int, data: bytes):
    return [mode, target, gas_limit, data]


def build_tx_rlp(chain_id, nonce, sender, frames):
    tx_list = [
        chain_id,
        nonce,
        sender,
        frames,
        MAX_PRIORITY_FEE,
        MAX_FEE,
        MAX_BLOB_FEE,
        BLOB_HASHES,
    ]
    return rlp.encode(tx_list)


def compute_signature_hash(chain_id, nonce, sender, frames):
    modified_frames = []
    for frame in frames:
        mode, target, gas_limit, data = frame
        if mode == FRAME_MODE_VERIFY:
            modified_frames.append([mode, target, gas_limit, b""])
        else:
            modified_frames.append([mode, target, gas_limit, data])
    return Web3.keccak(bytes([TX_TYPE]) + build_tx_rlp(chain_id, nonce, sender, modified_frames))


def sign_ecdsa(private_key: keys.PrivateKey, msg_hash: bytes):
    sig = private_key.sign_msg_hash(msg_hash)
    r = int(sig.r).to_bytes(32, "big")
    s = int(sig.s).to_bytes(32, "big")
    # ECRECOVER expects 27/28 (not 0/1)
    v = int(sig.v + 27).to_bytes(32, "big")
    return r, s, v


def effective_gas_price(w3, receipt) -> int:
    if receipt.get("effectiveGasPrice") is not None:
        return int(receipt["effectiveGasPrice"])
    base_fee = int(w3.eth.get_block(receipt["blockNumber"])["baseFeePerGas"])
    tip = min(MAX_FEE - base_fee, MAX_PRIORITY_FEE)
    return base_fee + tip


def assert_sender_cost(w3, receipt, bal_before: int, bal_after: int, label: str, extra_wei: int = 0):
    actual_delta = bal_before - bal_after
    expected_delta = effective_gas_price(w3, receipt) * int(receipt["gasUsed"]) + extra_wei
    expect(
        actual_delta == expected_delta,
        f"{label}: sender balance delta mismatch, got {actual_delta}, expected {expected_delta}",
    )


def set_balance(w3, address: str, amount_wei: int):
    resp = w3.provider.make_request("anvil_setBalance", [address, hex(amount_wei)])
    expect("error" not in resp, f"anvil_setBalance failed for {address}: {resp.get('error')}")


def send_signed_frame_tx(
    w3,
    chain_id: int,
    sender_addr: str,
    signer_private_key: keys.PrivateKey,
    frames,
    label: str,
):
    nonce = w3.eth.get_transaction_count(sender_addr)
    sender_bytes = bytes.fromhex(sender_addr[2:])
    frames_copy = [[m, t, g, d] for (m, t, g, d) in frames]

    expect(frames_copy, f"{label}: empty frame list")
    verify_index = next((idx for idx, f in enumerate(frames_copy) if f[0] == FRAME_MODE_VERIFY), None)
    expect(verify_index is not None, f"{label}: at least one VERIFY frame is required")

    sig_hash = compute_signature_hash(chain_id, nonce, sender_bytes, frames_copy)
    r, s, v = sign_ecdsa(signer_private_key, sig_hash)
    frames_copy[verify_index][3] = r + s + v

    raw_tx = bytes([TX_TYPE]) + build_tx_rlp(chain_id, nonce, sender_bytes, frames_copy)
    tx_hash = w3.eth.send_raw_transaction(raw_tx)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
    tx_type = normalize_receipt_type(receipt.get("type"))
    expect(tx_type == TX_TYPE, f"{label}: expected receipt type 0x06, got {receipt.get('type')}")
    return tx_hash, receipt, raw_tx


def build_transfer_wallet_runtime(recipient: str, amount_wei: int = 1) -> bytes:
    """
    Runtime for sender self-call ETH transfer:
      CALL(gas, recipient, amount_wei, 0,0,0,0)
      if CALL fails -> REVERT
    """
    expect(0 <= amount_wei <= 0xFF, "amount_wei must fit in PUSH1")
    recipient_bytes = bytes.fromhex(recipient[2:])
    expect(len(recipient_bytes) == 20, "recipient must be 20 bytes")

    return bytes([
        0x60, 0x00,
        0x60, 0x00,
        0x60, 0x00,
        0x60, 0x00,
        0x60, amount_wei,
        0x73,
    ]) + recipient_bytes + bytes([
        0x5A,
        0xF1,
        0x15,
        0x60, 0x26,
        0x57,
        0x00,
        0x5B,
        0x60, 0x00,
        0x60, 0x00,
        0xFD,
    ])


def compute_create_address(deployer: str, nonce: int) -> str:
    deployer_bytes = bytes.fromhex(deployer[2:])
    encoded = rlp.encode([deployer_bytes, nonce])
    return Web3.to_checksum_address(Web3.keccak(encoded)[12:].hex())


def build_fixed_factory_init_code(child_init: bytes) -> bytes:
    """
    Factory runtime (16 bytes header + appended child initcode):
      CODECOPY child_init to mem[0..len)
      CREATE(0, 0, len)
      POP
      STOP
    """
    expect(len(child_init) <= 0xFF, "child initcode must fit in PUSH1")
    runtime = bytes([
        0x60, len(child_init),
        0x60, 0x10,
        0x60, 0x00,
        0x39,
        0x60, len(child_init),
        0x60, 0x00,
        0x60, 0x00,
        0xF0,
        0x50,
        0x00,
    ]) + child_init
    return mk_init_code(runtime)


def main():
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        print(f"ERROR: Cannot connect to {RPC_URL}")
        print("Start anvil first: cd foundry && cargo run -p anvil -- --chain-id 8141")
        sys.exit(1)

    chain_id = w3.eth.chain_id
    funder = w3.eth.accounts[0]
    recipient = w3.eth.accounts[1]
    print(f"Connected to chain ID {chain_id}")
    print(f"Funder: {funder}")
    print(f"Recipient: {recipient}")
    print()

    # Classic secp256k1 signer (transaction owner key for VERIFY contracts).
    signer_private_key = keys.PrivateKey(os.urandom(32))
    signer_addr = signer_private_key.public_key.to_checksum_address()
    sender_eoa = signer_addr
    print(f"ECDSA signer / sender EOA: {sender_eoa}")

    # Deploy verifiers:
    # - scope 0x2 for Example 1 / 1a / 1b
    # - scope 0x0 for Example 2 frame 0
    verifier_scope2 = deploy_contract(
        w3,
        funder,
        mk_init_code(build_ecdsa_verifier_runtime(signer_addr, 2)),
    )
    verifier_scope0 = deploy_contract(
        w3,
        funder,
        mk_init_code(build_ecdsa_verifier_runtime(signer_addr, 0)),
    )
    sponsor_verify = deploy_contract(w3, funder, mk_init_code(build_sponsor_policy_verifier_runtime()))

    # Deploy targets.
    target_ex1 = deploy_contract(w3, funder, mk_init_code(sstore_runtime(42)))
    postop_target = deploy_contract(w3, funder, mk_init_code(sstore_runtime(0x33)))
    increment_target = deploy_contract(w3, funder, mk_init_code(sstore_increment_runtime()))

    # Deploy ERC20 token for Example 2 (minted to sender_eoa).
    INITIAL_SUPPLY = 1_000_000 * 10**18
    FEE_AMOUNT = 100 * 10**18
    TRANSFER_AMOUNT = 50 * 10**18
    token = deploy_contract(w3, funder, erc20_deploy_data(sender_eoa, INITIAL_SUPPLY), gas=2_000_000)

    print(f"Verifier scope2: {verifier_scope2}")
    print(f"Verifier scope0: {verifier_scope0}")
    print(f"Sponsor verifier (scope1): {sponsor_verify}")
    print(f"Target ex1: {target_ex1}")
    print(f"ERC20 token: {token}")
    print(f"Post-op target: {postop_target}")
    print(f"Increment target: {increment_target}")
    print()

    # Fund sponsor payer account (scope=0x1 verifier target) directly in Anvil state.
    set_balance(w3, sponsor_verify, w3.to_wei(5, "ether"))

    # Fund sender EOA.
    tx = w3.eth.send_transaction({
        "from": funder,
        "to": sender_eoa,
        "nonce": w3.eth.get_transaction_count(funder),
        "value": w3.to_wei(10, "ether"),
        "gas": 21_000,
    })
    w3.eth.wait_for_transaction_receipt(tx)

    # ── Example 1: Simple Transaction ────────────────────────────────────
    print("Example 1: Simple Transaction")
    bal_before = w3.eth.get_balance(sender_eoa)
    frames = [
        encode_frame(FRAME_MODE_VERIFY, bytes.fromhex(verifier_scope2[2:]), 200_000, b""),
        encode_frame(FRAME_MODE_SENDER, bytes.fromhex(target_ex1[2:]), 100_000, b""),
    ]
    tx_hash, receipt, raw = send_signed_frame_tx(
        w3, chain_id, sender_eoa, signer_private_key, frames, "example1"
    )
    bal_after = w3.eth.get_balance(sender_eoa)
    expect(int(receipt["status"]) == 1, "example1: expected status=1")
    slot = int.from_bytes(w3.eth.get_storage_at(target_ex1, 0), "big")
    expect(slot == 42, f"example1: expected slot0=42, got {slot}")
    assert_sender_cost(w3, receipt, bal_before, bal_after, "example1")
    print(f"  PASS tx={tx_hash.hex()} gas={receipt['gasUsed']} slot0={slot}")

    replay_failed = False
    try:
        w3.eth.send_raw_transaction(raw)
    except Exception:
        replay_failed = True
    expect(replay_failed, "example1: replay should be rejected")
    print("  PASS replay rejected")
    print()

    # ── Example 1a: Simple ETH transfer ──────────────────────────────────
    print("Example 1a: Simple ETH Transfer")
    wallet_runtime = build_transfer_wallet_runtime(recipient, amount_wei=1)
    wallet_sender = deploy_contract(w3, funder, mk_init_code(wallet_runtime))

    tx = w3.eth.send_transaction({
        "from": funder,
        "to": wallet_sender,
        "nonce": w3.eth.get_transaction_count(funder),
        "value": w3.to_wei(2, "ether"),
        "gas": 300_000,
    })
    fund_rcpt = w3.eth.wait_for_transaction_receipt(tx)
    expect(int(fund_rcpt["status"]) == 1, "example1a: wallet funding tx failed")
    wallet_funded = w3.eth.get_balance(wallet_sender)
    expect(wallet_funded > 0, "example1a: wallet balance is zero after funding")

    recipient_before = w3.eth.get_balance(recipient)
    wallet_before = w3.eth.get_balance(wallet_sender)
    frames = [
        encode_frame(FRAME_MODE_VERIFY, bytes.fromhex(verifier_scope2[2:]), 200_000, b""),
        encode_frame(FRAME_MODE_SENDER, b"", 100_000, b""),
    ]
    tx_hash, receipt, _ = send_signed_frame_tx(
        w3, chain_id, wallet_sender, signer_private_key, frames, "example1a"
    )
    recipient_after = w3.eth.get_balance(recipient)
    wallet_after = w3.eth.get_balance(wallet_sender)
    expect(int(receipt["status"]) == 1, "example1a: expected status=1")
    expect(
        recipient_after - recipient_before == 1,
        f"example1a: recipient delta expected 1 wei, got {recipient_after - recipient_before}",
    )
    assert_sender_cost(w3, receipt, wallet_before, wallet_after, "example1a", extra_wei=1)
    print(
        f"  PASS tx={tx_hash.hex()} gas={receipt['gasUsed']} recipient_delta={recipient_after - recipient_before}"
    )
    print()

    # ── Example 1b: Deployment-style flow (EIP order) ───────────────────────
    print("Example 1b: Deployment-style flow (DEFAULT -> VERIFY -> SENDER)")
    child_init = mk_init_code(sstore_runtime(0x44))
    factory = deploy_contract(w3, funder, build_fixed_factory_init_code(child_init))
    child_predicted = compute_create_address(factory, 1)
    code_before = w3.eth.get_code(child_predicted)
    expect(len(code_before) == 0, "example1b: child should not exist before tx")

    bal_before = w3.eth.get_balance(sender_eoa)
    frames = [
        encode_frame(FRAME_MODE_DEFAULT, bytes.fromhex(factory[2:]), 250_000, b""),
        encode_frame(FRAME_MODE_VERIFY, bytes.fromhex(verifier_scope2[2:]), 200_000, b""),
        encode_frame(FRAME_MODE_SENDER, bytes.fromhex(child_predicted[2:]), 120_000, b""),
    ]
    tx_hash, receipt, _ = send_signed_frame_tx(
        w3, chain_id, sender_eoa, signer_private_key, frames, "example1b"
    )
    bal_after = w3.eth.get_balance(sender_eoa)
    expect(int(receipt["status"]) == 1, "example1b: expected status=1")
    code_after = w3.eth.get_code(child_predicted)
    expect(len(code_after) > 0, "example1b: child contract was not deployed")
    slot = int.from_bytes(w3.eth.get_storage_at(child_predicted, 0), "big")
    expect(slot == 0x44, f"example1b: expected child slot0=0x44, got {slot}")
    assert_sender_cost(w3, receipt, bal_before, bal_after, "example1b")
    print(f"  PASS tx={tx_hash.hex()} child={child_predicted} slot0={slot}")
    print()

    # ── Example 2: Sponsored-style multi-frame transaction ───────────────
    print("Example 2: Sponsored-style multi-frame flow (real ERC20 transfers)")
    sender_before = w3.eth.get_balance(sender_eoa)
    sponsor_before = w3.eth.get_balance(sponsor_verify)
    sponsor_addr = sponsor_verify  # sponsor receives fee tokens and pays gas
    increment_before = int.from_bytes(w3.eth.get_storage_at(increment_target, 0), "big")
    expect(increment_before == 0, f"example2: increment target initial slot should be 0, got {increment_before}")
    token_bytes = bytes.fromhex(token[2:])
    fee_calldata = erc20_transfer_calldata(sponsor_addr, FEE_AMOUNT)
    transfer_calldata = erc20_transfer_calldata(recipient, TRANSFER_AMOUNT)
    sponsor_policy_data = erc20_sponsor_policy_data(token, FEE_AMOUNT)
    frames = [
        encode_frame(FRAME_MODE_VERIFY, bytes.fromhex(verifier_scope0[2:]), 220_000, b""),
        # Frame 1 carries sponsor policy data and enforces next-frame ERC20 fee payment.
        encode_frame(FRAME_MODE_VERIFY, bytes.fromhex(sponsor_verify[2:]), 250_000, sponsor_policy_data),
        # Frame 2: Fee payment — sender transfers ERC20 tokens to sponsor
        encode_frame(FRAME_MODE_SENDER, token_bytes, 200_000, fee_calldata),
        # Frame 3: User action — sender transfers ERC20 tokens to recipient
        encode_frame(FRAME_MODE_SENDER, token_bytes, 200_000, transfer_calldata),
        # Frame 4: Sponsor post-op action (DEFAULT, msg.sender=ENTRY_POINT)
        encode_frame(FRAME_MODE_DEFAULT, bytes.fromhex(postop_target[2:]), 100_000, b""),
        # Frames 5-7: extra multi-frame increments
        encode_frame(FRAME_MODE_SENDER, bytes.fromhex(increment_target[2:]), 100_000, b""),
        encode_frame(FRAME_MODE_SENDER, bytes.fromhex(increment_target[2:]), 100_000, b""),
        encode_frame(FRAME_MODE_SENDER, bytes.fromhex(increment_target[2:]), 100_000, b""),
    ]
    tx_hash, receipt, _ = send_signed_frame_tx(
        w3, chain_id, sender_eoa, signer_private_key, frames, "example2"
    )
    sender_after = w3.eth.get_balance(sender_eoa)
    sponsor_after = w3.eth.get_balance(sponsor_verify)
    expect(int(receipt["status"]) == 1, "example2: expected status=1")

    # Verify ERC20 balances after transfers
    sender_bal = query_erc20_balance(w3, token, sender_eoa)
    sponsor_bal = query_erc20_balance(w3, token, sponsor_addr)
    recipient_bal = query_erc20_balance(w3, token, recipient)
    expect(
        sender_bal == INITIAL_SUPPLY - FEE_AMOUNT - TRANSFER_AMOUNT,
        f"example2: sender token balance mismatch, got {sender_bal}, expected {INITIAL_SUPPLY - FEE_AMOUNT - TRANSFER_AMOUNT}",
    )
    expect(
        sponsor_bal == FEE_AMOUNT,
        f"example2: sponsor token balance mismatch, got {sponsor_bal}, expected {FEE_AMOUNT}",
    )
    expect(
        recipient_bal == TRANSFER_AMOUNT,
        f"example2: recipient token balance mismatch, got {recipient_bal}, expected {TRANSFER_AMOUNT}",
    )
    postop_slot = int.from_bytes(w3.eth.get_storage_at(postop_target, 0), "big")
    increment_slot = int.from_bytes(w3.eth.get_storage_at(increment_target, 0), "big")
    expect(postop_slot == 0x33, f"example2: post-op target slot mismatch {postop_slot}")
    expect(
        increment_slot == 3,
        f"example2: increment target expected slot0=3 after 3 frames, got {increment_slot}",
    )
    expect(
        sender_after == sender_before,
        f"example2: sender should not pay gas when sponsored, before={sender_before}, after={sender_after}",
    )
    assert_sender_cost(w3, receipt, sponsor_before, sponsor_after, "example2-payer")
    print(
        f"  PASS tx={tx_hash.hex()} ERC20: sender={sender_bal/10**18:.0f} sponsor={sponsor_bal/10**18:.0f} recipient={recipient_bal/10**18:.0f}"
    )
    print(f"  PASS postop_slot={postop_slot:#x} increment_slot={increment_slot}")
    print("  Running sponsor policy negative check (fee mismatch must revert)...")
    bad_frames = [
        encode_frame(FRAME_MODE_VERIFY, bytes.fromhex(verifier_scope0[2:]), 220_000, b""),
        encode_frame(FRAME_MODE_VERIFY, bytes.fromhex(sponsor_verify[2:]), 250_000, sponsor_policy_data),
        # Wrong fee amount (policy expects FEE_AMOUNT)
        encode_frame(FRAME_MODE_SENDER, token_bytes, 200_000, erc20_transfer_calldata(sponsor_addr, FEE_AMOUNT - 1)),
        encode_frame(FRAME_MODE_SENDER, token_bytes, 200_000, transfer_calldata),
    ]
    sender_bal_before_bad = query_erc20_balance(w3, token, sender_eoa)
    sponsor_bal_before_bad = query_erc20_balance(w3, token, sponsor_addr)
    recipient_bal_before_bad = query_erc20_balance(w3, token, recipient)
    _, bad_receipt, _ = send_signed_frame_tx(
        w3, chain_id, sender_eoa, signer_private_key, bad_frames, "example2-policy-negative"
    )
    expect(int(bad_receipt["status"]) == 0, "example2-policy-negative: expected status=0")
    expect(
        query_erc20_balance(w3, token, sender_eoa) == sender_bal_before_bad,
        "example2-policy-negative: sender token balance should remain unchanged",
    )
    expect(
        query_erc20_balance(w3, token, sponsor_addr) == sponsor_bal_before_bad,
        "example2-policy-negative: sponsor token balance should remain unchanged",
    )
    expect(
        query_erc20_balance(w3, token, recipient) == recipient_bal_before_bad,
        "example2-policy-negative: recipient token balance should remain unchanged",
    )
    print("  PASS policy mismatch reverted and ERC20 balances unchanged")
    print()

    print("All EIP-8141 ECDSA example checks passed.")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print(f"ASSERTION FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"UNEXPECTED ERROR: {e}")
        sys.exit(1)
