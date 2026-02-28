# CLAUDE.md

## Project Overview

EIP-8141 frame transaction implementation for Ethereum. Introduces type `0x06` transactions that replace ECDSA signatures with composable execution frames (VERIFY, DEFAULT, SENDER modes) and four new opcodes (APPROVE, TXPARAMLOAD, TXPARAMSIZE, TXPARAMCOPY).

## Repository Structure

```
eip8141-implementation/
├── revm-eip8141/       # revm v34.0.0 fork with EIP-8141 opcodes (submodule)
├── foundry/            # Foundry/anvil fork with type 0x06 support (submodule, branch: eip8141)
│   ├── crates/primitives/src/transaction/eip8141.rs  # TxEip8141 type + validation
│   ├── crates/anvil/src/eth/backend/eip8141.rs       # Frame execution engine
│   └── crates/anvil/src/eth/backend/executor.rs      # Detection + dispatch
└── devnet/
    ├── anvil_demo.py               # E2E demo
    ├── passkey_demo.py             # P256 passkey demo
    └── simple_p256_verifier.yul    # P256 verifier in Yul
```

## Build & Test

```bash
# Build anvil (from repo root)
cd foundry && cargo build -p anvil

# Run transaction type unit tests (39 tests)
cargo test -p foundry-primitives

# Run E2E demo (start anvil in another terminal first)
cd .. && python3 devnet/anvil_demo.py
```

## Working with Submodules

```bash
# After cloning, initialize submodules
git submodule update --init --recursive

# Changes to foundry/ or revm-eip8141/ must be committed inside the submodule first,
# then the parent repo's submodule reference must be updated with `git add <submodule>`.
```


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
- After ANY correction from the user: update memory files with the pattern
- Write rules for yourself that prevent the same mistake
- Ruthlessly iterate on these lessons until mistake rate drops

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

### 7. Core Principles
- **Simplicity First**: Make every change as simple as possible. Impact minimal code.
- **No Laziness**: Find root causes. No temporary fixes. Senior developer standards.
- **Minimal Impact**: Changes should only touch what's necessary. Avoid introducing bugs.