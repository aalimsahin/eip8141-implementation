# CLAUDE.md

## Workflow Orchestration

### 1. Plan Mode Default
- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- If something goes sideways, STOP and re-plan immediately – don't keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity

### 2. Subagent Strategy
- Use subagents liberally to keep main context window clean
- Offload research, exploration, and parallel analysis to subagents
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution

### 3. Self-Improvement Loop
- After ANY correction from the user: update `tasks/lessons.md` with the pattern
- Write rules for yourself that prevent the same mistake
- Ruthlessly iterate on these lessons until mistake rate drops
- Review lessons at session start for relevant project

### 4. Verification Before Done
- Never mark a task complete without proving it works
- Diff behavior between main and your changes when relevant
- Ask yourself: "Would a staff engineer approve this?"
- Run tests, check logs, demonstrate correctness

### 5. Demand Elegance (Balanced)
- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes – don't over-engineer
- Challenge your own work before presenting it

### 6. Autonomous Bug Fixing
- When given a bug report: just fix it. Don't ask for hand-holding
- Point at logs, errors, failing tests – then resolve them
- Zero context switching required from the user
- Go fix failing CI tests without being told how

## Core Principles

- **Simplicity First**: Make every change as simple as possible. Impact minimal code.
- **No Laziness**: Find root causes. No temporary fixes. Senior developer standards.
- **Minimal Impact**: Changes should only touch what's necessary. Avoid introducing bugs.

## EIP-8141 Build & Test Commands

```bash
# Build the anvil fork
cd foundry
cargo build -p anvil

# Run EIP-8141 transaction type tests
cargo test -p foundry-primitives

# Run the E2E demo (start anvil first in another terminal)
python3 devnet/anvil_demo.py
```

## EIP-8141 Architecture

- **revm-eip8141/**: Fork of revm v34.0.0 with EIP-8141 opcodes (APPROVE 0xAA, TXPARAMLOAD 0xB0, TXPARAMSIZE 0xB1, TXPARAMCOPY 0xB2)
- **foundry/**: Fork of Foundry with anvil support for type 0x06 frame transactions
- Key integration: `FrameTxContext` as revm Context chain parameter, `execute_eip8141_frame_tx()` in anvil executor

## File Structure

```
eip8141-implementation/
├── revm-eip8141/       # revm fork (submodule)
├── foundry/            # Foundry/anvil fork (submodule)
│   ├── crates/primitives/src/transaction/eip8141.rs  # TxEip8141 type + validation
│   ├── crates/anvil/src/eth/backend/eip8141.rs       # Frame execution engine
│   └── crates/anvil/src/eth/backend/executor.rs      # Integration point
└── devnet/
    ├── anvil_demo.py               # E2E demo
    ├── passkey_demo.py             # P256 passkey demo
    └── simple_p256_verifier.yul    # P256 verifier in Yul
```
