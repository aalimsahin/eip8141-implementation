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
    python3 e2e/tests/ecdsa_examples_test.py
"""

import os
import sys
from eth_keys import keys
from web3 import Web3

_SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
_UTILS_DIR = os.path.abspath(os.path.join(_SCRIPT_DIR, "..", "utils"))
if _UTILS_DIR not in sys.path:
    sys.path.insert(0, _UTILS_DIR)

from erc20_helpers import (
    build_sponsor_policy_verifier_runtime,
    erc20_deploy_data,
    erc20_sponsor_policy_data,
    erc20_transfer_calldata,
    query_erc20_balance,
)

from eip8141_utils import (
    RPC_URL,
    TX_TYPE,
    FRAME_MODE_DEFAULT,
    FRAME_MODE_VERIFY,
    FRAME_MODE_SENDER,
    expect,
    normalize_receipt_type,
    mk_init_code,
    sstore_runtime,
    sstore_increment_runtime,
    deploy_contract,
    encode_frame,
    build_tx_rlp,
    compute_signature_hash,
    effective_gas_price,
    assert_sender_cost,
    set_balance,
    build_transfer_wallet_runtime,
    compute_create_address,
    build_fixed_factory_init_code,
)


# ─── Crypto-specific Helpers ───────────────────────────────────────────────

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


def sign_ecdsa(private_key: keys.PrivateKey, msg_hash: bytes):
    sig = private_key.sign_msg_hash(msg_hash)
    r = int(sig.r).to_bytes(32, "big")
    s = int(sig.s).to_bytes(32, "big")
    # ECRECOVER expects 27/28 (not 0/1)
    v = int(sig.v + 27).to_bytes(32, "big")
    return r, s, v


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


def run_all_examples(w3, chain_id, funder, recipient):
    """Core test logic — callable from pytest or standalone."""

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
    except Exception as e:
        err_msg = str(e).lower()
        expect(
            "nonce" in err_msg or "already known" in err_msg,
            f"example1: replay rejected with unexpected error: {e}",
        )
        replay_failed = True
    expect(replay_failed, "example1: replay should be rejected")
    print("  PASS replay rejected")

    # Wrong-key negative test
    print("  Wrong-key negative test")
    wrong_signer = keys.PrivateKey(os.urandom(32))
    frames_wk = [
        encode_frame(FRAME_MODE_VERIFY, bytes.fromhex(verifier_scope2[2:]), 200_000, b""),
        encode_frame(FRAME_MODE_SENDER, bytes.fromhex(target_ex1[2:]), 100_000, b""),
    ]
    wrong_key_rejected = False
    try:
        _, wk_receipt, _ = send_signed_frame_tx(
            w3, chain_id, sender_eoa, wrong_signer, frames_wk, "wrong-key"
        )
        wrong_key_rejected = int(wk_receipt["status"]) == 0
    except ValueError as e:
        err_msg = str(e).lower()
        expect(
            "revert" in err_msg or "execution reverted" in err_msg
            or "payer not approved" in err_msg,
            f"wrong-key: rejected with unexpected error: {e}",
        )
        wrong_key_rejected = True
    except Exception as e:
        raise AssertionError(f"wrong-key: unexpected non-RPC error: {e}") from e
    expect(wrong_key_rejected, "wrong-key: tx with wrong signing key should fail")
    print("  PASS wrong key rejected")
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

    # ── Step 3: Failed VERIFY Approval-State Leak Regression ────────────
    print("Step 3: Failed VERIFY Approval-State Leak Regression")
    # A failed VERIFY frame must have ZERO effect on approval state.
    # Frame 0: VERIFY targeting a contract that just REVERTs (no APPROVE called).
    # Frame 1: VERIFY with legit APPROVE(0x2) (sets sender+payer).
    # Frame 2: SENDER frame.
    # If frame 0 leaked state, frame 1's approval could fail or payer could be wrong.
    revert_runtime = bytes([
        0x60, 0x00,  # PUSH1 0
        0x60, 0x00,  # PUSH1 0
        0xFD,        # REVERT
    ])
    reverting_verifier = deploy_contract(w3, funder, mk_init_code(revert_runtime))

    bal_before = w3.eth.get_balance(sender_eoa)
    frames = [
        # Frame 0: VERIFY targeting reverting contract — will fail (status=false)
        encode_frame(FRAME_MODE_VERIFY, bytes.fromhex(reverting_verifier[2:]), 200_000, b"\x00" * 96),
        # Frame 1: VERIFY targeting legit verifier — APPROVE(0x2) sets sender+payer
        encode_frame(FRAME_MODE_VERIFY, bytes.fromhex(verifier_scope2[2:]), 200_000, b""),
        # Frame 2: SENDER frame
        encode_frame(FRAME_MODE_SENDER, bytes.fromhex(target_ex1[2:]), 100_000, b""),
    ]
    tx_hash, receipt, _ = send_signed_frame_tx(
        w3, chain_id, sender_eoa, signer_private_key, frames, "step3-failed-verify"
    )
    bal_after = w3.eth.get_balance(sender_eoa)
    expect(int(receipt["status"]) == 1, "step3: tx should succeed (frame 1 approves)")
    # Payer should be sender_eoa (from APPROVE(0x2)), not the reverting_verifier address.
    # We verify this by checking that the sender paid gas, not the reverting verifier.
    expect(
        bal_after < bal_before,
        "step3: sender should pay gas (payer = sender from APPROVE(0x2))"
    )
    reverting_verifier_bal = w3.eth.get_balance(reverting_verifier)
    # The reverting verifier should NOT have been charged gas.
    # (If state leaked, payer could be set to reverting_verifier's target.)
    assert_sender_cost(w3, receipt, bal_before, bal_after, "step3-payer")
    print(f"  PASS tx={tx_hash.hex()} failed VERIFY did not leak approval state")
    print()

    # ── Step 4: Calldata Gas Charging — Balance Delta Test ───────────────
    print("Step 4: Calldata Gas Charging — Balance Delta Test")
    # Send two frame txs with different calldata sizes and verify that
    # the larger calldata results in more gas charged.

    # Small calldata: 32 bytes of zeros in VERIFY frame data.
    small_data = b"\x00" * 32
    # Large calldata: 1024 bytes of mixed data in VERIFY frame data.
    large_data = bytes([i % 256 for i in range(1024)])

    # Helper to send a frame tx with specific verifier data and measure balance delta.
    def measure_gas_delta(extra_data, label):
        bal_before_inner = w3.eth.get_balance(sender_eoa)
        inner_frames = [
            encode_frame(FRAME_MODE_VERIFY, bytes.fromhex(verifier_scope2[2:]), 200_000, extra_data),
            encode_frame(FRAME_MODE_SENDER, bytes.fromhex(target_ex1[2:]), 100_000, b""),
        ]
        _, inner_receipt, inner_raw = send_signed_frame_tx(
            w3, chain_id, sender_eoa, signer_private_key, inner_frames, label
        )
        bal_after_inner = w3.eth.get_balance(sender_eoa)
        expect(int(inner_receipt["status"]) == 1, f"{label}: expected status=1")
        delta = bal_before_inner - bal_after_inner
        gas_used = int(inner_receipt["gasUsed"])
        return delta, gas_used, inner_raw

    delta_small, gas_small, raw_small = measure_gas_delta(small_data, "step4-small")
    delta_large, gas_large, raw_large = measure_gas_delta(large_data, "step4-large")

    expect(
        delta_large > delta_small,
        f"step4: large calldata delta ({delta_large}) must exceed small ({delta_small})"
    )
    expect(
        gas_large > gas_small,
        f"step4: large calldata gasUsed ({gas_large}) must exceed small ({gas_small})"
    )

    # Verify that gas delta is at least (gasUsed * effective_gas_price).
    egp_small = effective_gas_price(w3, receipt)
    expect(
        delta_small >= gas_small * egp_small,
        f"step4-small: balance delta {delta_small} < gasUsed*egp {gas_small * egp_small}"
    )
    egp_large = effective_gas_price(w3, receipt)
    expect(
        delta_large >= gas_large * egp_large,
        f"step4-large: balance delta {delta_large} < gasUsed*egp {gas_large * egp_large}"
    )

    # Compute expected calldata gas difference from raw tx bytes.
    # Calldata gas: 4 per zero byte, 16 per non-zero byte in the RLP envelope.
    def calldata_gas(raw_bytes):
        """Count intrinsic calldata gas for raw tx bytes (excluding type prefix)."""
        total = 0
        for b in raw_bytes[1:]:  # skip type prefix byte
            total += 4 if b == 0 else 16
        return total

    cd_gas_small = calldata_gas(raw_small)
    cd_gas_large = calldata_gas(raw_large)
    expect(
        cd_gas_large > cd_gas_small,
        f"step4: large tx calldata gas ({cd_gas_large}) must exceed small ({cd_gas_small})"
    )
    print(f"  PASS small: delta={delta_small} gasUsed={gas_small} cdGas={cd_gas_small}")
    print(f"  PASS large: delta={delta_large} gasUsed={gas_large} cdGas={cd_gas_large}")
    print(f"  PASS calldata gas difference = {cd_gas_large - cd_gas_small}")
    print()

    print("All EIP-8141 ECDSA example checks passed.")


def test_ecdsa_examples(w3, chain_id, funder, recipient):
    """Pytest entry point — uses fixtures from conftest.py."""
    run_all_examples(w3, chain_id, funder, recipient)


def main():
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        print(f"ERROR: Cannot connect to {RPC_URL}")
        print("Start anvil first: cd foundry && cargo run -p anvil -- --chain-id 8141")
        sys.exit(1)
    run_all_examples(w3, w3.eth.chain_id, w3.eth.accounts[0], w3.eth.accounts[1])


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print(f"ASSERTION FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"UNEXPECTED ERROR: {e}")
        sys.exit(1)
