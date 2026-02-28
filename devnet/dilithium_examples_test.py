#!/usr/bin/env python3
"""
Dilithium (Post-Quantum) Example Suite for EIP-8141 (Type 0x06)

Validates EIP-8141 with ETHDilithium (CRYSTALS-Dilithium, lattice-based) signing:
1. Example 1: Simple transaction (VERIFY + SENDER)
2. Example 1a: Simple ETH transfer via sender smart-account self-call
3. Example 1b: Account-deployment-style flow in one tx (DEFAULT + VERIFY + SENDER)
4. Example 2: Sponsored-style multi-frame flow (VERIFY/VERIFY/SENDER/SENDER/DEFAULT)

Requirements:
    pip install web3 rlp pycryptodome eth_abi numpy
    pip install git+https://github.com/ZKNoxHQ/NTT.git@main#subdirectory=assets/pythonref/
    cd ethdilithium/pythonref && pip install -e .

Usage:
    cd foundry && cargo run -p anvil -- --chain-id 8141
    python3 devnet/dilithium_examples_test.py
"""

import sys
import os
import json
import rlp
from web3 import Web3
from eth_abi import encode as abi_encode

# Add ethdilithium pythonref to path for dilithium_py imports
_PYTHONREF = os.path.join(os.path.dirname(__file__), "..", "ethdilithium", "pythonref")
if _PYTHONREF not in sys.path:
    sys.path.insert(0, _PYTHONREF)

from dilithium_py.dilithium.default_parameters import Dilithium2 as D
from dilithium_py.keccak_prng.keccak_prng_wrapper import Keccak256PRNG


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

# ISigVerifier.verify(bytes,bytes32,bytes) selector
VERIFY_SELECTOR = Web3.keccak(text="verify(bytes,bytes32,bytes)")[:4]

# setKey(bytes) selector
SETKEY_SELECTOR = Web3.keccak(text="setKey(bytes)")[:4]

# Artifact path for ZKNOX_ethdilithium compiled contract
ARTIFACT_PATH = os.path.join(
    os.path.dirname(__file__), "..", "ethdilithium", "out",
    "ZKNOX_ethdilithium.sol", "ZKNOX_ethdilithium.json",
)


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
    return bytes([0x60, value, 0x60, 0x00, 0x55, 0x00])


def sstore_increment_runtime() -> bytes:
    """
    Runtime that increments slot0 by 1 on each call:
      PUSH1 0x00, SLOAD, PUSH1 0x01, ADD, PUSH1 0x00, SSTORE, STOP
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


def compute_create_address(deployer: str, nonce: int) -> str:
    deployer_bytes = bytes.fromhex(deployer[2:])
    encoded = rlp.encode([deployer_bytes, nonce])
    return Web3.to_checksum_address(Web3.keccak(encoded)[12:].hex())


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


# ─── Contract Bytecodes ────────────────────────────────────────────────────

def load_artifact_bytecode(path: str) -> bytes:
    """Read deployment bytecode from a forge build artifact JSON."""
    with open(path) as f:
        data = json.load(f)
    hex_str = data["bytecode"]["object"]
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)


def build_dilithium_approver_runtime(
    verifier_addr: bytes, pk_addr: bytes, approve_scope: int
) -> bytes:
    """
    Build EVM runtime bytecode for a DilithiumApprover contract.

    The approver is called as a VERIFY frame target with the raw Dilithium
    signature (2420 bytes) as calldata.  It:
      1. Gets sig_hash via TXPARAMLOAD(0x08, 0)
      2. ABI-encodes a STATICCALL to ISigVerifier.verify(bytes pk, bytes32 hash, bytes sig)
      3. Checks that the return value == ISigVerifier.verify.selector
      4. Calls APPROVE(scope, 0, 0)

    See devnet/dilithium_approver.yul for the documented Yul source.
    """
    expect(len(verifier_addr) == 20, "verifier_addr must be 20 bytes")
    expect(len(pk_addr) == 20, "pk_addr must be 20 bytes")
    expect(approve_scope in (0, 1, 2), "approve_scope must be 0/1/2")

    selector_word = VERIFY_SELECTOR + b"\x00" * 28  # left-aligned in 32 bytes
    pk_word = pk_addr + b"\x00" * 12                 # right-padded to 32 bytes

    code = bytearray()

    # ── 1. TXPARAMLOAD(0x08, 0) -> sigHash ──────────────────────────────
    code += bytes([0x60, 0x00])       # PUSH1 0x00  (offset)
    code += bytes([0x60, 0x08])       # PUSH1 0x08  (param_id = sig_hash)
    code += bytes([0xB0])             # TXPARAMLOAD
    code += bytes([0x60, 0x24])       # PUSH1 0x24
    code += bytes([0x52])             # MSTORE  -> mem[0x24] = sigHash

    # ── 2. Build ABI calldata for verify(bytes,bytes32,bytes) ───────────
    # selector at mem[0x00:0x04]
    code += bytes([0x7F]) + selector_word  # PUSH32 selector (left-aligned)
    code += bytes([0x60, 0x00])            # PUSH1 0x00
    code += bytes([0x52])                  # MSTORE

    # offset_pk = 0x60 at mem[0x04:0x24]
    code += bytes([0x60, 0x60])       # PUSH1 0x60
    code += bytes([0x60, 0x04])       # PUSH1 0x04
    code += bytes([0x52])             # MSTORE

    # sigHash already at mem[0x24:0x44] from step 1

    # offset_sig = 0xA0 at mem[0x44:0x64]
    code += bytes([0x60, 0xA0])       # PUSH1 0xA0
    code += bytes([0x60, 0x44])       # PUSH1 0x44
    code += bytes([0x52])             # MSTORE

    # pk_len = 20 at mem[0x64:0x84]
    code += bytes([0x60, 0x14])       # PUSH1 0x14  (20)
    code += bytes([0x60, 0x64])       # PUSH1 0x64
    code += bytes([0x52])             # MSTORE

    # pk_data at mem[0x84:0xA4]
    code += bytes([0x7F]) + pk_word   # PUSH32 pk_addr (right-padded)
    code += bytes([0x60, 0x84])       # PUSH1 0x84
    code += bytes([0x52])             # MSTORE

    # sig_len = calldatasize at mem[0xA4:0xC4]
    code += bytes([0x36])             # CALLDATASIZE
    code += bytes([0x60, 0xA4])       # PUSH1 0xA4
    code += bytes([0x52])             # MSTORE

    # sig_data: copy calldata to mem[0xC4:]
    code += bytes([0x36])             # CALLDATASIZE  (size)
    code += bytes([0x60, 0x00])       # PUSH1 0x00    (calldata offset)
    code += bytes([0x60, 0xC4])       # PUSH1 0xC4    (mem offset)
    code += bytes([0x37])             # CALLDATACOPY

    # ── 3. STATICCALL to verifier ───────────────────────────────────────
    # STATICCALL(gas, addr, argOff, argSize, retOff, retSize)
    code += bytes([0x60, 0x20])       # PUSH1 0x20    retSize
    code += bytes([0x60, 0x00])       # PUSH1 0x00    retOffset
    code += bytes([0x36])             # CALLDATASIZE
    code += bytes([0x60, 0xC4])       # PUSH1 0xC4
    code += bytes([0x01])             # ADD           argSize = 0xC4 + calldatasize
    code += bytes([0x60, 0x00])       # PUSH1 0x00    argOffset
    code += bytes([0x73]) + verifier_addr  # PUSH20 verifier
    code += bytes([0x5A])             # GAS
    code += bytes([0xFA])             # STATICCALL

    # ── 4. Check success + return value ─────────────────────────────────
    code += bytes([0x15])             # ISZERO
    jump_patch_1 = len(code)
    code += bytes([0x60, 0x00])       # PUSH1 <revert_pc>  (patched below)
    code += bytes([0x57])             # JUMPI

    # Load return value and compare to expected selector
    code += bytes([0x60, 0x00])       # PUSH1 0x00
    code += bytes([0x51])             # MLOAD  -> return value (bytes4, left-aligned)
    code += bytes([0x7F]) + selector_word  # PUSH32 expected (selector left-aligned)
    code += bytes([0x14])             # EQ
    code += bytes([0x15])             # ISZERO
    jump_patch_2 = len(code)
    code += bytes([0x60, 0x00])       # PUSH1 <revert_pc>  (patched below)
    code += bytes([0x57])             # JUMPI

    # ── 5. APPROVE ──────────────────────────────────────────────────────
    # Match existing pattern: PUSH scope, PUSH 0, PUSH 0, APPROVE
    code += bytes([0x60, approve_scope])
    code += bytes([0x60, 0x00])
    code += bytes([0x60, 0x00])
    code += bytes([0xAA])             # APPROVE
    code += bytes([0x00])             # STOP

    # ── Revert target ───────────────────────────────────────────────────
    revert_pc = len(code)
    code += bytes([0x5B])             # JUMPDEST
    code += bytes([0x60, 0x00])       # PUSH1 0x00
    code += bytes([0x60, 0x00])       # PUSH1 0x00
    code += bytes([0xFD])             # REVERT

    # Patch jump destinations
    code[jump_patch_1 + 1] = revert_pc
    code[jump_patch_2 + 1] = revert_pc

    return bytes(code)


# ─── Dilithium Key / Signature Helpers ──────────────────────────────────────

def generate_dilithium_keypair(seed: bytes = None):
    """Generate ETH-Dilithium (Keccak256PRNG) keypair."""
    if seed is None:
        seed = os.urandom(32)
    pk, sk = D.key_derive(seed, _xof=Keccak256PRNG, _xof2=Keccak256PRNG)
    return pk, sk, seed


def expand_pk_for_deployment(pk: bytes) -> bytes:
    """
    Expand a raw Dilithium public key into the ABI-encoded format expected
    by the PKContract constructor:  abi.encode(aHatEncoded, tr, t1Encoded).
    """
    rho, t1 = D._unpack_pk(pk)
    A_hat = D._expand_matrix_from_seed(rho, _xof=Keccak256PRNG)
    tr = D._h(pk, 64, _xof=Keccak256PRNG)

    t1 = t1.scale(1 << D.d).to_ntt()

    A_hat_compact = A_hat.compact_256(32)
    t1_compact_raw = t1.compact_256(32)
    t1_compact = [row[0] for row in t1_compact_raw]

    a_hat_encoded = abi_encode(["uint256[][][]"], [A_hat_compact])
    t1_encoded = abi_encode(["uint256[][]"], [t1_compact])

    return abi_encode(
        ["bytes", "bytes", "bytes"],
        [a_hat_encoded, tr, t1_encoded],
    )


def sign_dilithium(sk: bytes, sig_hash: bytes) -> bytes:
    """
    Sign a 32-byte sig_hash with ETH-Dilithium.

    The on-chain ISigVerifier.verify(pk, m, sig) internally constructs
    mPrime = abi.encodePacked(0x00, 0x00, m) before calling verifyInternal.
    The Python sign must use the raw message (sig_hash) — the Solidity
    verifier handles the mPrime prefix on both sign and verify sides.

    Returns: raw 2420-byte signature (cTilde || z || h).
    """
    expect(len(sig_hash) == 32, "sig_hash must be 32 bytes")
    sig = D.sign(sk, sig_hash, deterministic=True, _xof=Keccak256PRNG, _xof2=Keccak256PRNG)
    return sig


def derive_sender_address(pk: bytes) -> str:
    """Derive EIP-8141 sender address from a Dilithium public key."""
    h = Web3.keccak(pk)
    return Web3.to_checksum_address(h[12:].hex())


# ─── Transaction Sending ───────────────────────────────────────────────────

def send_signed_frame_tx(w3, chain_id, sender_addr, sk, frames, label,
                         extra_verify_sks=None):
    """
    Sign and send a type-0x06 frame transaction using Dilithium.

    Places the raw 2420-byte Dilithium signature in each VERIFY frame's data.
    By default the first VERIFY frame gets the primary signature (sk).
    If extra_verify_sks is provided, it maps VERIFY frame indices (0-based
    among ALL frames) to secret keys for additional cryptographic signatures.
    """
    nonce = w3.eth.get_transaction_count(sender_addr)
    sender_bytes = bytes.fromhex(sender_addr[2:])
    frames_copy = [[m, t, g, d] for (m, t, g, d) in frames]

    verify_indices = [idx for idx, f in enumerate(frames_copy) if f[0] == FRAME_MODE_VERIFY]
    expect(len(verify_indices) > 0, f"{label}: at least one VERIFY frame is required")

    sig_hash = compute_signature_hash(chain_id, nonce, sender_bytes, frames_copy)

    # Primary signature goes into the first VERIFY frame
    sig = sign_dilithium(sk, sig_hash)
    expect(len(sig) == 2420, f"{label}: expected 2420-byte sig, got {len(sig)}")
    frames_copy[verify_indices[0]][3] = sig

    # Additional VERIFY frame signatures
    if extra_verify_sks:
        for frame_idx, extra_sk in extra_verify_sks.items():
            expect(
                frame_idx in verify_indices,
                f"{label}: extra_verify_sks frame {frame_idx} is not a VERIFY frame",
            )
            extra_sig = sign_dilithium(extra_sk, sig_hash)
            expect(len(extra_sig) == 2420, f"{label}: expected 2420-byte extra sig, got {len(extra_sig)}")
            frames_copy[frame_idx][3] = extra_sig

    raw_tx = bytes([TX_TYPE]) + build_tx_rlp(chain_id, nonce, sender_bytes, frames_copy)
    tx_hash = w3.eth.send_raw_transaction(raw_tx)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    tx_type = normalize_receipt_type(receipt.get("type"))
    expect(tx_type == TX_TYPE, f"{label}: expected receipt type 0x06, got {receipt.get('type')}")
    return tx_hash, receipt, raw_tx


# ─── Main ──────────────────────────────────────────────────────────────────

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

    # ── Generate Dilithium keypair ──────────────────────────────────────
    print("Generating ETH-Dilithium keypair...")
    pk, sk, seed = generate_dilithium_keypair()
    sender_eoa = derive_sender_address(pk)
    print(f"  Seed:   {seed.hex()}")
    print(f"  PK len: {len(pk)} bytes")
    print(f"  Sender: {sender_eoa}")
    print()

    # ── Deploy ZKNOX_ethdilithium verifier ──────────────────────────────
    print("Deploying ZKNOX_ethdilithium verifier...")
    expect(os.path.exists(ARTIFACT_PATH), f"artifact not found: {ARTIFACT_PATH}\nRun: cd ethdilithium && forge build")
    verifier_bytecode = load_artifact_bytecode(ARTIFACT_PATH)
    verifier = deploy_contract(w3, funder, verifier_bytecode, gas=15_000_000)
    print(f"  Verifier: {verifier}")

    # ── Expand PK and call setKey to deploy PKContract ──────────────────
    print("Expanding public key and deploying PKContract via setKey...")
    expanded_pk = expand_pk_for_deployment(pk)
    print(f"  Expanded PK size: {len(expanded_pk)} bytes")

    setkey_calldata = SETKEY_SELECTOR + abi_encode(["bytes"], [expanded_pk])
    tx_hash = w3.eth.send_transaction({
        "from": funder,
        "to": verifier,
        "data": setkey_calldata,
        "gas": 10_000_000,
    })
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    expect(int(receipt["status"]) == 1, f"setKey failed: {receipt}")
    setkey_gas = int(receipt["gasUsed"])
    print(f"  setKey gas: {setkey_gas}")

    # Predict PKContract address: first CREATE from verifier (nonce=1)
    pk_contract = compute_create_address(verifier, 1)
    pk_code = w3.eth.get_code(pk_contract)
    expect(len(pk_code) > 0, f"PKContract not found at predicted address {pk_contract}")
    print(f"  PKContract: {pk_contract}")

    verifier_bytes = bytes.fromhex(verifier[2:])
    pk_contract_bytes = bytes.fromhex(pk_contract[2:])

    # ── Generate sponsor Dilithium keypair ──────────────────────────────
    print("Generating sponsor Dilithium keypair...")
    sponsor_pk, sponsor_sk, sponsor_seed = generate_dilithium_keypair()
    print(f"  Sponsor seed: {sponsor_seed.hex()}")
    print(f"  Sponsor PK len: {len(sponsor_pk)} bytes")

    # Deploy sponsor's PKContract via setKey
    print("Expanding sponsor public key and deploying PKContract via setKey...")
    sponsor_expanded_pk = expand_pk_for_deployment(sponsor_pk)
    sponsor_setkey_calldata = SETKEY_SELECTOR + abi_encode(["bytes"], [sponsor_expanded_pk])
    tx_hash = w3.eth.send_transaction({
        "from": funder,
        "to": verifier,
        "data": sponsor_setkey_calldata,
        "gas": 10_000_000,
    })
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    expect(int(receipt["status"]) == 1, f"sponsor setKey failed: {receipt}")
    print(f"  Sponsor setKey gas: {int(receipt['gasUsed'])}")

    # Predict sponsor PKContract address: second CREATE from verifier (nonce=2)
    sponsor_pk_contract = compute_create_address(verifier, 2)
    sponsor_pk_code = w3.eth.get_code(sponsor_pk_contract)
    expect(len(sponsor_pk_code) > 0, f"Sponsor PKContract not found at {sponsor_pk_contract}")
    sponsor_pk_contract_bytes = bytes.fromhex(sponsor_pk_contract[2:])
    print(f"  Sponsor PKContract: {sponsor_pk_contract}")
    print()

    # ── Deploy DilithiumApprovers ───────────────────────────────────────
    # scope 0x2 for Examples 1 / 1a / 1b
    # scope 0x0 for Example 2 frame 0 (execution-only, sender's key)
    # scope 0x1 for Example 2 frame 1 (payment-only, sponsor's key)
    print("Deploying DilithiumApprovers...")
    approver_scope2 = deploy_contract(
        w3, funder,
        mk_init_code(build_dilithium_approver_runtime(verifier_bytes, pk_contract_bytes, 2)),
    )
    approver_scope0 = deploy_contract(
        w3, funder,
        mk_init_code(build_dilithium_approver_runtime(verifier_bytes, pk_contract_bytes, 0)),
    )
    # Sponsor approver: cryptographic Dilithium verification with scope 0x1 (payment)
    sponsor_approver = deploy_contract(
        w3, funder,
        mk_init_code(build_dilithium_approver_runtime(verifier_bytes, sponsor_pk_contract_bytes, 1)),
    )
    print(f"  Approver scope2: {approver_scope2}")
    print(f"  Approver scope0: {approver_scope0}")
    print(f"  Sponsor approver (scope1): {sponsor_approver}")

    # ── Deploy targets ──────────────────────────────────────────────────
    target_ex1 = deploy_contract(w3, funder, mk_init_code(sstore_runtime(42)))
    fee_target = deploy_contract(w3, funder, mk_init_code(sstore_runtime(0x11)))
    call_target = deploy_contract(w3, funder, mk_init_code(sstore_runtime(0x22)))
    postop_target = deploy_contract(w3, funder, mk_init_code(sstore_runtime(0x33)))
    increment_target = deploy_contract(w3, funder, mk_init_code(sstore_increment_runtime()))

    print(f"  Target ex1: {target_ex1}")
    print(f"  Fee target: {fee_target}")
    print(f"  Call target: {call_target}")
    print(f"  Post-op target: {postop_target}")
    print(f"  Increment target: {increment_target}")
    print()

    # ── Fund accounts ───────────────────────────────────────────────────
    # Fund sponsor approver contract (scope=0x1 target) — it pays gas when approved.
    set_balance(w3, sponsor_approver, w3.to_wei(5, "ether"))

    # Fund Dilithium sender EOA.
    set_balance(w3, sender_eoa, w3.to_wei(10, "ether"))

    # ── Verify benchmark: dry-run to measure gas ────────────────────────
    print("Benchmarking Dilithium verify gas (dry-run)...")
    test_sig = sign_dilithium(sk, b"\xaa" * 32)
    verify_calldata = (
        VERIFY_SELECTOR
        + abi_encode(
            ["bytes", "bytes32", "bytes"],
            [pk_contract_bytes, b"\xaa" * 32, test_sig],
        )
    )
    try:
        gas_estimate = w3.eth.estimate_gas({
            "from": funder,
            "to": verifier,
            "data": verify_calldata,
        })
        print(f"  Estimated verify gas: {gas_estimate}")
        verify_gas_limit = int(gas_estimate * 1.2)  # 20% margin
    except Exception as e:
        print(f"  Gas estimation failed ({e}), using default 8M")
        verify_gas_limit = 8_000_000
    print(f"  VERIFY frame gas limit: {verify_gas_limit}")
    print()

    # ════════════════════════════════════════════════════════════════════
    # Example 1: Simple Transaction (Dilithium VERIFY + SENDER)
    # ════════════════════════════════════════════════════════════════════
    print("Example 1: Simple Transaction")
    bal_before = w3.eth.get_balance(sender_eoa)
    frames = [
        encode_frame(FRAME_MODE_VERIFY, bytes.fromhex(approver_scope2[2:]), verify_gas_limit, b""),
        encode_frame(FRAME_MODE_SENDER, bytes.fromhex(target_ex1[2:]), 100_000, b""),
    ]
    tx_hash, receipt, raw = send_signed_frame_tx(
        w3, chain_id, sender_eoa, sk, frames, "example1"
    )
    bal_after = w3.eth.get_balance(sender_eoa)
    expect(int(receipt["status"]) == 1, "example1: expected status=1")
    slot = int.from_bytes(w3.eth.get_storage_at(target_ex1, 0), "big")
    expect(slot == 42, f"example1: expected slot0=42, got {slot}")
    assert_sender_cost(w3, receipt, bal_before, bal_after, "example1")
    print(f"  PASS tx={tx_hash.hex()} gas={receipt['gasUsed']} slot0={slot}")

    # Replay should fail
    replay_failed = False
    try:
        w3.eth.send_raw_transaction(raw)
    except Exception:
        replay_failed = True
    expect(replay_failed, "example1: replay should be rejected")
    print("  PASS replay rejected")
    print()

    # ════════════════════════════════════════════════════════════════════
    # Example 1a: Simple ETH Transfer (smart-account self-call)
    # ════════════════════════════════════════════════════════════════════
    print("Example 1a: Simple ETH Transfer")
    wallet_runtime = build_transfer_wallet_runtime(recipient, amount_wei=1)
    wallet_sender = deploy_contract(w3, funder, mk_init_code(wallet_runtime))

    # Fund wallet sender so it can pay gas + transfer value.
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
        encode_frame(FRAME_MODE_VERIFY, bytes.fromhex(approver_scope2[2:]), verify_gas_limit, b""),
        encode_frame(FRAME_MODE_SENDER, b"", 100_000, b""),
    ]
    tx_hash, receipt, _ = send_signed_frame_tx(
        w3, chain_id, wallet_sender, sk, frames, "example1a"
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

    # ════════════════════════════════════════════════════════════════════
    # Example 1b: Deployment-style flow (DEFAULT -> VERIFY -> SENDER)
    # ════════════════════════════════════════════════════════════════════
    print("Example 1b: Deployment-style flow (DEFAULT -> VERIFY -> SENDER)")
    child_init = mk_init_code(sstore_runtime(0x44))
    factory = deploy_contract(w3, funder, build_fixed_factory_init_code(child_init))
    child_predicted = compute_create_address(factory, 1)
    code_before = w3.eth.get_code(child_predicted)
    expect(len(code_before) == 0, "example1b: child should not exist before tx")

    bal_before = w3.eth.get_balance(sender_eoa)
    frames = [
        encode_frame(FRAME_MODE_DEFAULT, bytes.fromhex(factory[2:]), 250_000, b""),
        encode_frame(FRAME_MODE_VERIFY, bytes.fromhex(approver_scope2[2:]), verify_gas_limit, b""),
        encode_frame(FRAME_MODE_SENDER, bytes.fromhex(child_predicted[2:]), 120_000, b""),
    ]
    tx_hash, receipt, _ = send_signed_frame_tx(
        w3, chain_id, sender_eoa, sk, frames, "example1b"
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

    # ════════════════════════════════════════════════════════════════════
    # Example 2: Sponsored-style multi-frame transaction
    # ════════════════════════════════════════════════════════════════════
    print("Example 2: Sponsored-style multi-frame flow")
    sender_before = w3.eth.get_balance(sender_eoa)
    sponsor_before = w3.eth.get_balance(sponsor_approver)
    increment_before = int.from_bytes(w3.eth.get_storage_at(increment_target, 0), "big")
    expect(increment_before == 0, f"example2: increment target initial slot should be 0, got {increment_before}")
    frames = [
        # Frame 0: Dilithium VERIFY approves execution only (scope 0x0) — sender's key
        encode_frame(FRAME_MODE_VERIFY, bytes.fromhex(approver_scope0[2:]), verify_gas_limit, b""),
        # Frame 1: Sponsor VERIFY approves payment (scope 0x1) — sponsor's key (cryptographic)
        encode_frame(FRAME_MODE_VERIFY, bytes.fromhex(sponsor_approver[2:]), verify_gas_limit, b""),
        # Frame 2: Payment action
        encode_frame(FRAME_MODE_SENDER, bytes.fromhex(fee_target[2:]), 100_000, b""),
        # Frame 3: User action
        encode_frame(FRAME_MODE_SENDER, bytes.fromhex(call_target[2:]), 100_000, b""),
        # Frame 4: Sponsor post-op action
        encode_frame(FRAME_MODE_DEFAULT, bytes.fromhex(postop_target[2:]), 100_000, b""),
        # Frames 5-7: extra multi-frame increments (slot0 += 1 each)
        encode_frame(FRAME_MODE_SENDER, bytes.fromhex(increment_target[2:]), 100_000, b""),
        encode_frame(FRAME_MODE_SENDER, bytes.fromhex(increment_target[2:]), 100_000, b""),
        encode_frame(FRAME_MODE_SENDER, bytes.fromhex(increment_target[2:]), 100_000, b""),
    ]
    tx_hash, receipt, _ = send_signed_frame_tx(
        w3, chain_id, sender_eoa, sk, frames, "example2",
        extra_verify_sks={1: sponsor_sk},  # Frame 1 signed with sponsor's key
    )
    sender_after = w3.eth.get_balance(sender_eoa)
    sponsor_after = w3.eth.get_balance(sponsor_approver)
    expect(int(receipt["status"]) == 1, "example2: expected status=1")

    fee_slot = int.from_bytes(w3.eth.get_storage_at(fee_target, 0), "big")
    call_slot = int.from_bytes(w3.eth.get_storage_at(call_target, 0), "big")
    postop_slot = int.from_bytes(w3.eth.get_storage_at(postop_target, 0), "big")
    increment_slot = int.from_bytes(w3.eth.get_storage_at(increment_target, 0), "big")
    expect(fee_slot == 0x11, f"example2: fee target slot mismatch {fee_slot}")
    expect(call_slot == 0x22, f"example2: call target slot mismatch {call_slot}")
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
        f"  PASS tx={tx_hash.hex()} slots fee/call/post/inc={fee_slot:#x}/{call_slot:#x}/{postop_slot:#x}/{increment_slot:#x}"
    )
    print()

    print("All EIP-8141 Dilithium example checks passed.")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print(f"ASSERTION FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        import traceback
        print(f"UNEXPECTED ERROR: {e}")
        traceback.print_exc()
        sys.exit(1)
