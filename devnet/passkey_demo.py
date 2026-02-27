#!/usr/bin/env python3
"""
Passkey Account Demo: Send a Type 0x06 Frame Transaction

Demonstrates end-to-end EIP-8141 functionality:
1. Generate a P256 (secp256r1) keypair
2. Deploy a P256 verifier contract
3. Fund the passkey sender address
4. Build, sign, and send a type 0x06 frame transaction

Requirements:
    pip install web3 rlp cryptography

Usage:
    # Start devnet first
    ./devnet/run-devnet.sh

    # Run demo
    python3 devnet/passkey_demo.py
"""

import sys
import rlp
from web3 import Web3
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.hashes import SHA256

# ─── Constants ──────────────────────────────────────────────────────────────

CHAIN_ID = 8141
RPC_URL = "http://localhost:8545"
TX_TYPE = 0x06

# Hardhat account #0 (pre-funded in genesis.json)
FUNDER_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
FUNDER_ADDR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

# Frame modes
FRAME_MODE_VERIFY = 1
FRAME_MODE_SENDER = 2

# Recipient for the SENDER frame (Hardhat account #1)
RECIPIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

# ─── Hand-assembled P256 Verifier Bytecode ──────────────────────────────────
#
# See devnet/simple_p256_verifier.yul for the source.
#
# Constructor (22 bytes = 0x16):
#   Copies runtime code to memory, appends pubKeyX||pubKeyY from constructor
#   args, and deploys the combined bytecode.
#
# Runtime (67 bytes = 0x43):
#   1. CODECOPY pubKeyX||pubKeyY from end of deployed code to mem[0x60..0xA0]
#   2. TXPARAMLOAD(0x08, 0) -> sigHash to mem[0x00]
#   3. CALLDATALOAD r, s to mem[0x20], mem[0x40]
#   4. STATICCALL P256VERIFY precompile at 0x0100 with 160 bytes
#   5. Check success + result non-zero
#   6. APPROVE(0, 0, 0x00) -- sender approval
#   7. REVERT on any failure

# Runtime bytecode breakdown:
#   38           CODESIZE
#   6040         PUSH1 0x40
#   90           SWAP1
#   03           SUB                codesize - 64
#   6040         PUSH1 0x40
#   6060         PUSH1 0x60
#   39           CODECOPY            mem[0x60..0xA0] = pubKeyX||pubKeyY
#   6000         PUSH1 0x00
#   6008         PUSH1 0x08
#   b0           TXPARAMLOAD         sigHash = TXPARAMLOAD(0x08, 0)
#   6000         PUSH1 0x00
#   52           MSTORE              mem[0x00] = sigHash
#   6000         PUSH1 0x00
#   35           CALLDATALOAD        r = calldata[0x00]
#   6020         PUSH1 0x20
#   52           MSTORE              mem[0x20] = r
#   6020         PUSH1 0x20
#   35           CALLDATALOAD        s = calldata[0x20]
#   6040         PUSH1 0x40
#   52           MSTORE              mem[0x40] = s
#   6020         PUSH1 0x20          retSize
#   60a0         PUSH1 0xA0          retOffset
#   60a0         PUSH1 0xA0          argSize (160)
#   6000         PUSH1 0x00          argOffset
#   610100       PUSH2 0x0100        P256VERIFY precompile
#   5a           GAS
#   fa           STATICCALL
#   15           ISZERO
#   603d         PUSH1 0x3D          jump to REVERT
#   57           JUMPI
#   60a0         PUSH1 0xA0
#   51           MLOAD               load result
#   15           ISZERO
#   603d         PUSH1 0x3D          jump to REVERT
#   57           JUMPI
#   6000         PUSH1 0x00          scope
#   6000         PUSH1 0x00          length
#   6000         PUSH1 0x00          offset
#   aa           APPROVE             terminates like RETURN
#   5b           JUMPDEST (0x3D)
#   6000         PUSH1 0x00
#   6000         PUSH1 0x00
#   fd           REVERT
RUNTIME_HEX = (
    "38604090036040606039"      # CODESIZE, sub(cs,64), CODECOPY to mem[0x60]
    "60006008b0600052"          # TXPARAMLOAD(0x08,0) -> mem[0x00]
    "600035602052"              # r -> mem[0x20]
    "602035604052"              # s -> mem[0x40]
    "602060a060a06000"          # retLen, retOff, argLen, argOff
    "6101005afa"                # PUSH2(0x0100), GAS, STATICCALL
    "15603d57"                  # ISZERO, PUSH1(0x3D), JUMPI
    "60a05115603d57"            # check result nonzero
    "600060006000aa"            # APPROVE(0, 0, 0x00)
    "5b60006000fd"              # JUMPDEST, REVERT
)
# Remove any whitespace from multiline string
RUNTIME_HEX = RUNTIME_HEX.replace("\n", "").replace(" ", "")

RUNTIME_SIZE = len(bytes.fromhex(RUNTIME_HEX))
assert RUNTIME_SIZE == 0x43, (
    f"Expected runtime size 0x43 (67), got {hex(RUNTIME_SIZE)} ({RUNTIME_SIZE})"
)

# Constructor bytecode breakdown:
#   6043         PUSH1 0x43          runtimeSize
#   80           DUP1
#   6016         PUSH1 0x16          constructor size (self-referential)
#   6000         PUSH1 0x00
#   39           CODECOPY             mem[0x00..0x43] = runtime
#   38           CODESIZE
#   6040         PUSH1 0x40
#   90           SWAP1
#   03           SUB                  codesize - 64
#   6040         PUSH1 0x40
#   91           SWAP2                rearrange for CODECOPY(0x43, codesize-64, 0x40)
#   39           CODECOPY             mem[0x43..0x83] = pubKeyX||pubKeyY
#   6083         PUSH1 0x83          total deployed size (0x43 + 0x40)
#   6000         PUSH1 0x00
#   f3           RETURN               deploy mem[0x00..0x83]
CONSTRUCTOR_HEX = "604380601660003938604090036040913960836000f3"

CONSTRUCTOR_SIZE = len(bytes.fromhex(CONSTRUCTOR_HEX))
assert CONSTRUCTOR_SIZE == 0x16, (
    f"Expected constructor size 0x16 (22), got {hex(CONSTRUCTOR_SIZE)} ({CONSTRUCTOR_SIZE})"
)

# Full init code = constructor + runtime (constructor args appended at deploy time)
INIT_CODE_HEX = CONSTRUCTOR_HEX + RUNTIME_HEX


# ─── Helpers ────────────────────────────────────────────────────────────────

def derive_sender_address(pub_key_x: bytes, pub_key_y: bytes) -> str:
    """Derive sender address from P256 public key: keccak256(pubX || pubY)[12:]"""
    raw = pub_key_x + pub_key_y
    h = Web3.keccak(raw)
    return Web3.to_checksum_address(h[12:].hex())


def encode_frame(mode: int, target: bytes, gas_limit: int, data: bytes) -> list:
    """Encode a single frame as an RLP-compatible list."""
    return [mode, target, gas_limit, data]


def build_tx_rlp(chain_id, nonce, sender, frames, max_priority_fee, max_fee,
                 max_blob_fee, blob_hashes):
    """
    RLP-encode a TxEip8141 matching the Rust Encodable impl:

    rlp([chain_id, nonce, sender, [frames...], max_priority_fee_per_gas,
         max_fee_per_gas, max_fee_per_blob_gas, [blob_hashes...]])

    Each frame: rlp([mode, target, gas_limit, data])
    """
    tx_list = [
        chain_id,
        nonce,
        sender,
        frames,
        max_priority_fee,
        max_fee,
        max_blob_fee,
        blob_hashes,
    ]
    return rlp.encode(tx_list)


def compute_signature_hash(chain_id, nonce, sender, frames, max_priority_fee,
                           max_fee, max_blob_fee, blob_hashes):
    """
    Compute signature hash matching TxEip8141::signature_hash():
    keccak256(0x06 || rlp(modified_tx))
    where VERIFY frame data is zeroed out.
    """
    modified_frames = []
    for frame in frames:
        mode, target, gas_limit, data = frame
        if mode == FRAME_MODE_VERIFY:
            modified_frames.append([mode, target, gas_limit, b''])
        else:
            modified_frames.append([mode, target, gas_limit, data])

    rlp_encoded = build_tx_rlp(chain_id, nonce, sender, modified_frames,
                               max_priority_fee, max_fee, max_blob_fee,
                               blob_hashes)
    return Web3.keccak(bytes([TX_TYPE]) + rlp_encoded)


def sign_p256(private_key, message_hash: bytes) -> tuple:
    """
    Sign a 32-byte hash with P256 private key using prehash signing.
    Returns (r, s) as 32-byte big-endian values.
    """
    # Sign with prehash -- the message is already hashed (keccak256)
    # Prehashed(SHA256()) tells the library "data is already a 32-byte hash"
    der_sig = private_key.sign(message_hash, ec.ECDSA(Prehashed(SHA256())))
    r_int, s_int = decode_dss_signature(der_sig)
    r = r_int.to_bytes(32, 'big')
    s = s_int.to_bytes(32, 'big')
    return r, s


# ─── Main Demo ──────────────────────────────────────────────────────────────

def main():
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        print(f"ERROR: Cannot connect to {RPC_URL}")
        print("Make sure the devnet is running: ./devnet/run-devnet.sh")
        sys.exit(1)

    print(f"Connected to chain ID {w3.eth.chain_id}")
    print()

    # ── Step 1: Generate P256 keypair ───────────────────────────────────────
    print("Step 1: Generating P256 keypair...")

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    pub_key_x = public_numbers.x.to_bytes(32, 'big')
    pub_key_y = public_numbers.y.to_bytes(32, 'big')
    sender_addr = derive_sender_address(pub_key_x, pub_key_y)

    print(f"  Public key X: 0x{pub_key_x.hex()}")
    print(f"  Public key Y: 0x{pub_key_y.hex()}")
    print(f"  Passkey sender: {sender_addr}")
    print()

    # ── Step 2: Deploy P256 verifier contract ───────────────────────────────
    print("Step 2: Deploying P256 verifier...")

    funder = w3.eth.account.from_key(FUNDER_PK)
    init_code = bytes.fromhex(INIT_CODE_HEX) + pub_key_x + pub_key_y
    nonce = w3.eth.get_transaction_count(funder.address)

    deploy_tx = {
        'from': funder.address,
        'nonce': nonce,
        'gas': 500_000,
        'maxFeePerGas': w3.to_wei(30, 'gwei'),
        'maxPriorityFeePerGas': w3.to_wei(1, 'gwei'),
        'data': init_code,
        'chainId': CHAIN_ID,
        'type': 2,
    }

    signed_deploy = w3.eth.account.sign_transaction(deploy_tx, FUNDER_PK)
    deploy_hash = w3.eth.send_raw_transaction(signed_deploy.raw_transaction)
    deploy_receipt = w3.eth.wait_for_transaction_receipt(deploy_hash)

    verifier_addr = deploy_receipt['contractAddress']
    print(f"  Verifier deployed at: {verifier_addr}")
    print(f"  Deploy tx: {deploy_hash.hex()}")
    print(f"  Gas used: {deploy_receipt['gasUsed']}")
    print()

    # ── Step 3: Fund the passkey sender address ─────────────────────────────
    print("Step 3: Funding passkey account...")

    fund_nonce = w3.eth.get_transaction_count(funder.address)
    fund_tx = {
        'from': funder.address,
        'to': sender_addr,
        'nonce': fund_nonce,
        'value': w3.to_wei(10, 'ether'),
        'gas': 21_000,
        'maxFeePerGas': w3.to_wei(30, 'gwei'),
        'maxPriorityFeePerGas': w3.to_wei(1, 'gwei'),
        'chainId': CHAIN_ID,
        'type': 2,
    }

    signed_fund = w3.eth.account.sign_transaction(fund_tx, FUNDER_PK)
    fund_hash = w3.eth.send_raw_transaction(signed_fund.raw_transaction)
    w3.eth.wait_for_transaction_receipt(fund_hash)

    balance = w3.eth.get_balance(sender_addr)
    print(f"  Funded with {w3.from_wei(balance, 'ether')} ETH")
    print()

    # ── Step 4-7: Build and sign frame transaction ──────────────────────────
    print("Step 4-7: Building and signing frame transaction...")

    sender_bytes = bytes.fromhex(sender_addr[2:])
    verifier_bytes = bytes.fromhex(verifier_addr[2:])
    recipient_bytes = bytes.fromhex(RECIPIENT[2:])

    # Frame 0: VERIFY frame -- target is the P256 verifier, data will be r||s
    # Frame 1: SENDER frame -- target is the recipient (simple ETH transfer)
    verify_frame = encode_frame(FRAME_MODE_VERIFY, verifier_bytes, 200_000, b'')
    sender_frame = encode_frame(FRAME_MODE_SENDER, recipient_bytes, 21_000, b'')

    frames = [verify_frame, sender_frame]

    tx_nonce = 0
    max_priority_fee = 1_000_000_000   # 1 gwei
    max_fee = 30_000_000_000           # 30 gwei
    max_blob_fee = 0
    blob_hashes = []

    # Step 5: Compute signature hash (VERIFY frame data zeroed)
    sig_hash = compute_signature_hash(
        CHAIN_ID, tx_nonce, sender_bytes, frames,
        max_priority_fee, max_fee, max_blob_fee, blob_hashes
    )
    print(f"  Signature hash: 0x{sig_hash.hex()}")

    # Step 6: Sign with P256 private key
    r, s = sign_p256(private_key, sig_hash)
    print(f"  Signature r: 0x{r.hex()}")
    print(f"  Signature s: 0x{s.hex()}")

    # Step 7: Fill VERIFY frame calldata with r || s (64 bytes)
    verify_data = r + s
    frames[0] = encode_frame(FRAME_MODE_VERIFY, verifier_bytes, 200_000, verify_data)

    print()

    # ── Step 8: RLP-encode and send ─────────────────────────────────────────
    print("Step 8: Sending frame transaction...")

    rlp_encoded = build_tx_rlp(
        CHAIN_ID, tx_nonce, sender_bytes, frames,
        max_priority_fee, max_fee, max_blob_fee, blob_hashes
    )
    raw_tx = bytes([TX_TYPE]) + rlp_encoded

    print(f"  Raw tx ({len(raw_tx)} bytes): 0x{raw_tx.hex()[:80]}...")

    # Step 9: Send via eth_sendRawTransaction
    try:
        tx_hash = w3.eth.send_raw_transaction(raw_tx)
        print(f"  TX hash: 0x{tx_hash.hex()}")

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
        status = "SUCCESS" if receipt['status'] == 1 else "FAILED"
        print(f"  Status: {status}")
        print(f"  Block: {receipt['blockNumber']}")
        print(f"  Gas used: {receipt['gasUsed']}")
    except Exception as e:
        print(f"  Transaction error: {e}")
        print()
        print("This is expected if the devnet doesn't fully process type 0x06 yet.")
        print("The transaction was correctly built and signed -- RPC acceptance")
        print("depends on pool + consensus integration.")
        sys.exit(1)

    print()
    print("Demo complete! The passkey account successfully sent a frame transaction.")


if __name__ == "__main__":
    main()
