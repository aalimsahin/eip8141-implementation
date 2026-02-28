# EIP-8141: Frame Transaction Implementation

A working implementation of [EIP-8141](https://github.com/AlimsahinDev/EIPs/blob/master/EIPS/eip-8141.md) — frame transactions for Ethereum.

## What is EIP-8141?

EIP-8141 introduces **frame transactions** (type `0x06`) — a new transaction format that replaces ECDSA signatures with composable on-chain execution frames. Instead of signing a transaction off-chain, authentication happens on-chain through smart contract verifiers (ECDSA, multisig, passkeys, etc.).

A frame transaction contains an ordered list of **frames**, each targeting a contract with a specific execution mode:

| Mode | Caller | Purpose |
|------|--------|---------|
| **VERIFY** | `ENTRY_POINT` | Runs a verifier contract that must call the `APPROVE` opcode to authorize the sender |
| **DEFAULT** | `ENTRY_POINT` | General-purpose execution after the sender is approved |
| **SENDER** | `tx.sender` | Execution with the sender's own identity after approval |

VERIFY frames always run first. If the verifier doesn't call `APPROVE`, the entire transaction reverts. Once approved, DEFAULT and SENDER frames execute in order.

### New Opcodes

Four new EVM opcodes power frame transactions:

| Opcode | Byte | Description |
|--------|------|-------------|
| **APPROVE** | `0xAA` | Sets `sender_approved = true` — how a verifier says "this sender is legitimate" |
| **TXPARAMLOAD** | `0xB0` | Loads frame tx parameters (sender, nonce, fees, frame count, etc.) onto the stack |
| **TXPARAMSIZE** | `0xB1` | Returns the byte size of a frame's calldata |
| **TXPARAMCOPY** | `0xB2` | Copies frame calldata into memory |

### Transaction Encoding

```
0x06 || rlp([chain_id, nonce, sender, frames, max_priority_fee_per_gas,
             max_fee_per_gas, max_fee_per_blob_gas, blob_versioned_hashes])
```

Each frame: `[mode, target, gas_limit, data]`

The sender is explicit — no signature recovery needed. The `signature_hash()` zeroes out VERIFY frame data before hashing, so verifiers can inspect the transaction without circular dependency.

## How Frame Execution Works

```
1. Build FrameTxContext from the transaction
2. Construct a separate EVM with EIP-8141 opcodes enabled
3. Validate nonce and balance
4. Deduct max_cost from sender, increment nonce
5. Take an accounting checkpoint

6. For each frame:
   ├── VERIFY: checkpoint → execute → save approval flags → revert state → check APPROVE
   └── DEFAULT/SENDER: execute → collect logs

7. If any frame failed:
   └── Revert to accounting checkpoint (undo all frame state, keep nonce + balance)

8. Refund unused gas to sender
9. Single finalize() + commit() — one atomic DB write
```

Each frame runs via `MainnetHandler::execution()`, which returns a `FrameResult` without committing to the database. All state changes stay in the journal, so checkpoint/revert works correctly. VERIFY frames are truly read-only — their state changes are reverted but the approval flag (which lives in chain context, not the journal) is preserved.

## Repository Structure

```
eip8141-implementation/
├── revm-eip8141/     # revm fork with 4 new opcodes (submodule)
├── foundry/          # Foundry (anvil) fork with type 0x06 support (submodule)
└── devnet/           # Demo scripts
    ├── anvil_demo.py             # E2E demo: deploy verifier + send frame tx
    ├── passkey_demo.py           # P256 passkey verification demo
    └── simple_p256_verifier.yul  # Hand-assembled P256 verifier
```

### Submodules

| Repo | Description |
|------|-------------|
| [revm-eip8141](https://github.com/aalimsahin/revm-eip8141) | Fork of revm v34.0.0 — `FrameTxContext`, `FrameTxHost` trait, opcode implementations, `with_eip8141_opcodes()` extension |
| [foundry-eip8141](https://github.com/aalimsahin/foundry-eip8141) | Fork of Foundry — `TxEip8141` type (RLP, EIP-2718, validation), frame execution engine, executor integration |

## Building

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/aalimsahin/eip8141-implementation.git
cd eip8141-implementation

# Build the anvil fork
cd foundry
cargo build -p anvil

# Run tests
cargo test -p foundry-primitives
```

## Running the Demo

```bash
# Start the anvil fork (from foundry/ directory)
cargo run -p anvil

# In another terminal, run the E2E demo
python3 devnet/anvil_demo.py
```

The demo deploys a verifier contract, sends a frame transaction with a VERIFY frame + SENDER frame, and confirms the storage value is set correctly.
