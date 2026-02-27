# EIP-8141: Frame Transaction Implementation

A working implementation of [EIP-8141](https://github.com/AlimsahinDev/EIPs/blob/master/EIPS/eip-8141.md) — frame transactions for Ethereum.

Frame transactions (type `0x06`) enable composable, signature-free execution through ordered frames. Each frame targets a contract with a specific mode:

- **VERIFY** — must call the `APPROVE` opcode to authorize the sender
- **DEFAULT** — executes from `ENTRY_POINT` after approval
- **SENDER** — executes from `tx.sender` after approval

## Repository Structure

```
eip8141-implementation/
├── revm-eip8141/     # revm fork with 4 new opcodes (submodule)
├── foundry/          # Foundry (anvil) fork with type 0x06 support (submodule)
└── devnet/           # Demo scripts
    ├── anvil_demo.py          # E2E demo: deploy verifier + send frame tx
    ├── passkey_demo.py        # P256 passkey verification demo
    └── simple_p256_verifier.yul  # Hand-assembled P256 verifier
```

### Submodules

| Repo | Description |
|------|-------------|
| [revm-eip8141](https://github.com/aalimsahin/revm-eip8141) | Fork of revm v34.0.0 with opcodes: `APPROVE` (0xAA), `TXPARAMLOAD` (0xB0), `TXPARAMSIZE` (0xB1), `TXPARAMCOPY` (0xB2) |
| [foundry-eip8141](https://github.com/aalimsahin/foundry-eip8141) | Fork of Foundry with anvil support for type 0x06 frame transactions |

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

The demo deploys an ECDSA verifier contract, sends a frame transaction with a VERIFY frame + SENDER frame, and checks that the storage value is set correctly.

## How It Works

1. **revm-eip8141** adds four new opcodes to the EVM interpreter. The key opcode is `APPROVE` (0xAA), which sets a flag in the `FrameTxContext` to authorize the sender.

2. **foundry-eip8141** integrates these opcodes into anvil's executor. When a type 0x06 transaction arrives, it constructs a separate EVM with `FrameTxContext` as the chain parameter and executes each frame in sequence using `system_call_with_caller_commit`.

3. The frame execution flow is: VERIFY frames run first to collect approvals, then DEFAULT/SENDER frames execute with the appropriate caller identity.
