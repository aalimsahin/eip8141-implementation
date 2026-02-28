"""
Shared EIP-8141 (Type 0x06) utilities for frame transaction test suites.

Contains constants, RLP encoding, frame helpers, deployment utilities, and
balance assertion functions used by passkey, ECDSA, and dilithium test suites.
"""

import rlp
from web3 import Web3


# ─── Constants ──────────────────────────────────────────────────────────────

RPC_URL = "http://localhost:8545"
TX_TYPE = 0x06

FRAME_MODE_DEFAULT = 0
FRAME_MODE_VERIFY = 1
FRAME_MODE_SENDER = 2

MAX_PRIORITY_FEE = 1_000_000_000  # 1 gwei
MAX_FEE = 30_000_000_000          # 30 gwei
MAX_BLOB_FEE = 0
BLOB_HASHES: tuple = ()


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
    expect(len(runtime) <= 0xFF, f"runtime too large for PUSH1-sized constructor ({len(runtime)} bytes)")
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


def deploy_contract(w3, funder: str, init_code: bytes, gas: int = 700_000) -> str:
    nonce = w3.eth.get_transaction_count(funder)
    tx_hash = w3.eth.send_transaction({
        "from": funder,
        "nonce": nonce,
        "gas": gas,
        "data": init_code,
    })
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    expect(int(receipt["status"]) == 1, f"deploy failed: {receipt}")
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
        list(BLOB_HASHES),
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


def build_transfer_wallet_runtime(recipient: str, amount_wei: int = 1) -> bytes:
    """
    Runtime for sender self-call ETH transfer:
      CALL(gas, recipient, amount_wei, 0,0,0,0)
      if CALL fails -> REVERT
    """
    expect(0 <= amount_wei <= 0xFF, "amount_wei must fit in PUSH1")
    recipient_bytes = bytes.fromhex(recipient[2:])
    expect(len(recipient_bytes) == 20, "recipient must be 20 bytes")

    # Bytecode:
    # PUSH1 0 out_size
    # PUSH1 0 out_offset
    # PUSH1 0 in_size
    # PUSH1 0 in_offset
    # PUSH1 amount
    # PUSH20 recipient
    # GAS
    # CALL
    # ISZERO
    # PUSH1 revert_label(0x26)
    # JUMPI
    # STOP
    # JUMPDEST
    # PUSH1 0
    # PUSH1 0
    # REVERT
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
        0x60, len(child_init),  # PUSH1 len
        0x60, 0x10,             # PUSH1 offset_of_child_init (runtime header len)
        0x60, 0x00,             # PUSH1 mem_dst
        0x39,                   # CODECOPY
        0x60, len(child_init),  # PUSH1 len
        0x60, 0x00,             # PUSH1 mem_offset
        0x60, 0x00,             # PUSH1 value
        0xF0,                   # CREATE
        0x50,                   # POP
        0x00,                   # STOP
    ]) + child_init
    return mk_init_code(runtime)
