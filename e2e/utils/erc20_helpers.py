"""
Shared ERC20 helpers for EIP-8141 example test suites.

Provides deployment, calldata encoding, and balance queries for MinimalERC20.
"""

import json
import os

from web3 import Web3

_ARTIFACT_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "contracts", "out", "MinimalERC20.sol", "MinimalERC20.json"
))

# Function selectors
_TRANSFER_SELECTOR = Web3.keccak(text="transfer(address,uint256)")[:4]
_BALANCE_OF_SELECTOR = Web3.keccak(text="balanceOf(address)")[:4]
_TRANSFER_SELECTOR_U32 = int.from_bytes(_TRANSFER_SELECTOR, "big")
_BALANCE_OF_SELECTOR_U32 = int.from_bytes(_BALANCE_OF_SELECTOR, "big")


class _Asm:
    """Minimal bytecode assembler with label fixups (PUSH2 jump destinations)."""

    def __init__(self):
        self.code = bytearray()
        self.labels = {}
        self.fixups = []

    def op(self, *ops: int):
        for op in ops:
            self.code.append(op & 0xFF)

    def push(self, value: int, size: int = None):
        if value < 0:
            raise ValueError("push value must be non-negative")
        if size is None:
            if value <= 0xFF:
                size = 1
            elif value <= 0xFFFF:
                size = 2
            elif value <= 0xFFFFFF:
                size = 3
            elif value <= 0xFFFFFFFF:
                size = 4
            else:
                size = 32
        if not (1 <= size <= 32):
            raise ValueError(f"invalid PUSH size: {size}")
        max_value = (1 << (8 * size)) - 1
        if value > max_value:
            raise ValueError(f"value 0x{value:x} does not fit PUSH{size}")
        self.code.append(0x5F + size)  # PUSH1..PUSH32
        self.code.extend(value.to_bytes(size, "big"))

    def push_label(self, label: str):
        # PUSH2 <addr>
        self.code.append(0x61)
        pos = len(self.code)
        self.code.extend(b"\x00\x00")
        self.fixups.append((pos, label))

    def label(self, name: str):
        if name in self.labels:
            raise ValueError(f"duplicate label: {name}")
        self.labels[name] = len(self.code)

    def finalize(self) -> bytes:
        for pos, label in self.fixups:
            if label not in self.labels:
                raise ValueError(f"unknown label: {label}")
            addr = self.labels[label]
            if addr > 0xFFFF:
                raise ValueError(f"label address too large for PUSH2: {label}={addr}")
            self.code[pos] = (addr >> 8) & 0xFF
            self.code[pos + 1] = addr & 0xFF
        return bytes(self.code)


def _emit_txparamload(asm: _Asm, param_id: int, index: int):
    # TXPARAMLOAD pops [in1, in2] where in1=param_id, in2=index.
    asm.push(index)
    asm.push(param_id)
    asm.op(0xB0)


def _emit_txparamsize(asm: _Asm, param_id: int, index: int):
    # TXPARAMSIZE pops [in1, in2] where in1=param_id, in2=index.
    asm.push(index)
    asm.push(param_id)
    asm.op(0xB1)


def _emit_txparamcopy(
    asm: _Asm,
    param_id: int,
    index: int,
    dest_offset: int,
    src_offset: int,
    length: int,
):
    # TXPARAMCOPY pops [in1, in2, dest_offset, src_offset, length].
    asm.push(length)
    asm.push(src_offset)
    asm.push(dest_offset)
    asm.push(index)
    asm.push(param_id)
    asm.op(0xB2)


def load_erc20_bytecode() -> bytes:
    """Read MinimalERC20 deployment bytecode from the forge artifact."""
    with open(_ARTIFACT_PATH) as f:
        data = json.load(f)
    hex_str = data["bytecode"]["object"]
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)


def erc20_deploy_data(holder: str, supply: int) -> bytes:
    """Return bytecode + ABI-encoded constructor args for MinimalERC20(holder, supply)."""
    bytecode = load_erc20_bytecode()
    holder_bytes = bytes.fromhex(holder[2:]) if holder.startswith("0x") else bytes.fromhex(holder)
    # constructor(address initialHolder, uint256 initialSupply)
    args = holder_bytes.rjust(32, b"\x00") + supply.to_bytes(32, "big")
    return bytecode + args


def erc20_transfer_calldata(to: str, amount: int) -> bytes:
    """Encode transfer(address,uint256) calldata."""
    to_bytes = bytes.fromhex(to[2:]) if to.startswith("0x") else bytes.fromhex(to)
    return _TRANSFER_SELECTOR + to_bytes.rjust(32, b"\x00") + amount.to_bytes(32, "big")


def erc20_sponsor_policy_data(token: str, fee_amount: int) -> bytes:
    """
    Encode sponsor VERIFY policy as:
      abi.encode(address token, uint256 feeAmount)
    """
    token_bytes = bytes.fromhex(token[2:]) if token.startswith("0x") else bytes.fromhex(token)
    return token_bytes.rjust(32, b"\x00") + fee_amount.to_bytes(32, "big")


def query_erc20_balance(w3, token: str, account: str) -> int:
    """Call balanceOf(account) on a MinimalERC20 token and return the balance as int."""
    account_bytes = bytes.fromhex(account[2:]) if account.startswith("0x") else bytes.fromhex(account)
    calldata = _BALANCE_OF_SELECTOR + account_bytes.rjust(32, b"\x00")
    result = w3.eth.call({"to": token, "data": calldata})
    return int.from_bytes(result, "big")


def build_sponsor_policy_verifier_runtime() -> bytes:
    """
    Build a sponsor policy VERIFY runtime that enforces EIP-8141 Example 2 semantics.

    Expected frame layout at execution time:
    - current frame index = 1 (sponsor VERIFY frame)
    - frame 2 is SENDER mode to token.transfer(sponsor, feeAmount)

    This verifier expects frame-1 calldata:
      abi.encode(address token, uint256 feeAmount)

    Checks:
    1) policy calldata length == 64
    2) current_frame_index == 1
    3) frame_count > 2
    4) frame[2].mode == SENDER
    5) frame[2].target == policy.token
    6) frame[2].data == transfer(sponsor, policy.feeAmount)
    7) token.balanceOf(sender) >= policy.feeAmount
    8) APPROVE(0x1)
    """
    asm = _Asm()

    # policy calldata length must be exactly 64 bytes (address + uint256).
    asm.op(0x36)  # CALLDATASIZE
    asm.push(0x40)
    asm.op(0x14, 0x15)  # EQ, ISZERO
    asm.push_label("revert")
    asm.op(0x57)  # JUMPI

    # mem[0xC0] = policy.token
    asm.push(0x00)
    asm.op(0x35)  # CALLDATALOAD
    asm.push(0x00C0)
    asm.op(0x52)  # MSTORE

    # mem[0xE0] = policy.feeAmount
    asm.push(0x20)
    asm.op(0x35)  # CALLDATALOAD
    asm.push(0x00E0)
    asm.op(0x52)  # MSTORE

    # current_frame_index == 1
    _emit_txparamload(asm, 0x10, 0)
    asm.push(0x01)
    asm.op(0x14, 0x15)  # EQ, ISZERO
    asm.push_label("revert")
    asm.op(0x57)

    # frame_count > 2 (must have at least frame[2]).
    # GT compares top > next, so push threshold first, then frame_count.
    asm.push(0x02)
    _emit_txparamload(asm, 0x09, 0)
    asm.op(0x11, 0x15)  # GT, ISZERO
    asm.push_label("revert")
    asm.op(0x57)

    # frame[2].mode == SENDER (2)
    _emit_txparamload(asm, 0x14, 2)
    asm.push(0x02)
    asm.op(0x14, 0x15)  # EQ, ISZERO
    asm.push_label("revert")
    asm.op(0x57)

    # frame[2].target == policy.token
    _emit_txparamload(asm, 0x11, 2)
    asm.push(0x00C0)
    asm.op(0x51, 0x14, 0x15)  # MLOAD, EQ, ISZERO
    asm.push_label("revert")
    asm.op(0x57)

    # frame[2].data size == 68 (transfer(address,uint256))
    _emit_txparamsize(asm, 0x12, 2)
    asm.push(0x44)
    asm.op(0x14, 0x15)  # EQ, ISZERO
    asm.push_label("revert")
    asm.op(0x57)

    # Copy frame[2].data to mem[0x100:0x144].
    _emit_txparamcopy(asm, 0x12, 2, 0x0100, 0x00, 0x44)

    # selector == transfer(address,uint256)
    asm.push(0x0100)
    asm.op(0x51)  # MLOAD
    asm.push(0xE0)
    asm.op(0x1C)  # SHR 224 => selector
    asm.push(_TRANSFER_SELECTOR_U32, size=4)
    asm.op(0x14, 0x15)  # EQ, ISZERO
    asm.push_label("revert")
    asm.op(0x57)

    # recipient == frame[1].target (sponsor verifier contract address)
    asm.push(0x0104)
    asm.op(0x51)  # MLOAD recipient word
    _emit_txparamload(asm, 0x11, 1)
    asm.op(0x14, 0x15)  # EQ, ISZERO
    asm.push_label("revert")
    asm.op(0x57)

    # amount == policy.feeAmount
    asm.push(0x0124)
    asm.op(0x51)  # MLOAD amount
    asm.push(0x00E0)
    asm.op(0x51, 0x14, 0x15)  # MLOAD fee, EQ, ISZERO
    asm.push_label("revert")
    asm.op(0x57)

    # Build balanceOf(sender) calldata at mem[0x180:0x1A4].
    asm.push(_BALANCE_OF_SELECTOR_U32 << 224, size=32)
    asm.push(0x0180)
    asm.op(0x52)  # MSTORE selector word

    _emit_txparamload(asm, 0x02, 0)  # sender word
    asm.push(0x0184)
    asm.op(0x52)  # MSTORE argument

    # STATICCALL token.balanceOf(sender)
    asm.push(0x20)    # retSize
    asm.push(0x01C0)  # retOffset
    asm.push(0x24)    # argSize
    asm.push(0x0180)  # argOffset
    asm.push(0x00C0)
    asm.op(0x51)      # token address word
    asm.op(0x5A)      # GAS
    asm.op(0xFA)      # STATICCALL
    asm.op(0x15)      # ISZERO
    asm.push_label("revert")
    asm.op(0x57)

    # balance >= feeAmount  <=>  !(balance < feeAmount)
    asm.push(0x00E0)
    asm.op(0x51)      # fee
    asm.push(0x01C0)
    asm.op(0x51)      # balance
    asm.op(0x10)      # LT(balance, fee)
    asm.push_label("revert")
    asm.op(0x57)

    # APPROVE(0x1, 0, 0)
    asm.push(0x01)
    asm.push(0x00)
    asm.push(0x00)
    asm.op(0xAA, 0x00)  # APPROVE, STOP

    asm.label("revert")
    asm.op(0x5B)  # JUMPDEST
    asm.push(0x00)
    asm.push(0x00)
    asm.op(0xFD)  # REVERT

    return asm.finalize()
