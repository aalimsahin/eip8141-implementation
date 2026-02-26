# EIP-8141 Review Report

Date: 2026-02-27  
Scope: Full review of committed EIP-8141 implementation changes

## Summary
- Total findings: 7
- P1 (high): 4
- P2 (medium): 3
- Overall verdict: Patch is incorrect and requires follow-up fixes before considering the implementation complete.

## Findings

### 1) [P1] Bind WebAuthn verification to the current tx hash
- File: `/Users/alimsahin/Desktop/alim2.0/eip8141-implementation/contracts/yul/WebAuthnVerifier.yul` (around line 47)
- Issue: The verifier does not enforce that the WebAuthn challenge matches the current frame transaction `sig_hash`.
- Impact: A valid passkey assertion can be replayed across different transactions for the same key.
- Recommended fix: Explicitly load and validate `sig_hash` against challenge-derived data before approval.

### 2) [P1] Wire EIP-8141 node types into the CLI entrypoint
- File: `/Users/alimsahin/Desktop/alim2.0/eip8141-implementation/reth-eip8141/bin/eip8141/src/main.rs` (around line 36)
- Issue: Binary still launches standard Ethereum node wiring (`EthereumChainSpecParser` + `EthereumNode::default()`).
- Impact: Runtime does not use custom EIP-8141 primitives/EVM configuration; tx type `0x06` is not truly supported.
- Recommended fix: Switch CLI wiring to custom EIP-8141 node types and chain parser.

### 3) [P1] Register frame opcodes when creating the EVM
- File: `/Users/alimsahin/Desktop/alim2.0/eip8141-implementation/reth-eip8141/crates/eip8141-evm/src/evm_factory.rs` (around line 44)
- Issue: Factory delegates to `EthEvmFactory` without installing APPROVE/TXPARAM opcode handlers.
- Impact: Frame verifier contracts using these opcodes fail at runtime.
- Recommended fix: Register the custom instruction handlers during EVM construction.

### 4) [P1] Return calldata for the selected non-VERIFY frame
- File: `/Users/alimsahin/Desktop/alim2.0/eip8141-implementation/reth-eip8141/crates/eip8141-primitives/src/tx.rs` (around line 412)
- Issue: `kind()` selects first non-VERIFY target, but `input()` always returns first frame data.
- Impact: Mismatched target/calldata in `TxEnv` conversion causes incorrect execution or revert.
- Recommended fix: Align `input()` with the same frame selection logic used by `kind()`.

### 5) [P2] Fix Docker build context for genesis file copy
- File: `/Users/alimsahin/Desktop/alim2.0/eip8141-implementation/devnet/docker-compose.yml` (around line 6)
- Issue: Docker build context excludes `devnet/genesis.json`, but Dockerfile copies it.
- Impact: `docker compose build` fails and containerized devnet cannot start.
- Recommended fix: Adjust build context/dockerfile path strategy so `genesis.json` is inside build context.

### 6) [P2] Implement transaction submission in playground handler
- File: `/Users/alimsahin/Desktop/alim2.0/eip8141-implementation/showcase/app/playground/page.tsx` (around line 22)
- Issue: Submit handler always shows “not implemented” error and never sends a transaction.
- Impact: Main playground workflow is non-functional.
- Recommended fix: Build, sign, and submit frame transactions using `showcase/lib/eip8141.ts` and RPC client integration.

### 7) [P2] Reset explorer error state after successful polling
- File: `/Users/alimsahin/Desktop/alim2.0/eip8141-implementation/showcase/app/explorer/page.tsx` (around line 50)
- Issue: Error state is set on failure but never cleared on recovery.
- Impact: UI can remain stuck in error view even after RPC becomes healthy.
- Recommended fix: Clear `error` on successful fetch before/after setting block state.

## Recommended Fix Order
1. Findings 1-4 (core correctness/security/runtime support)
2. Finding 5 (devnet usability)
3. Findings 6-7 (showcase functionality and UX resilience)
