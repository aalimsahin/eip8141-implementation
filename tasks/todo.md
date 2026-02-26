# EIP-8141 Implementation Progress

## Phase 1: Fork Setup + Core Types
- [x] Fork revm and reth on GitHub (aalimsahin/revm-eip8141, aalimsahin/reth-eip8141)
- [x] Clone as git submodules
- [ ] Set up [patch] in reth workspace Cargo.toml
- [ ] Define TxEip8141 struct (requires alloy-consensus fork)
- [ ] Implement RLP encode/decode
- [ ] Implement signature hash computation
- [ ] Extend Transaction enum with Eip8141 variant
- [ ] Implement SignedTransaction wrapper

## Phase 2: revm Opcodes
- [x] Add FrameTxContext to revm (crates/interpreter/src/instructions/frame_tx.rs)
- [x] Define opcode constants (0xaa, 0xb0-0xb2) in bytecode/src/opcode.rs
- [x] Implement APPROVE handler
- [x] Implement TXPARAMLOAD handler
- [x] Implement TXPARAMSIZE handler
- [x] Implement TXPARAMCOPY handler
- [ ] Register in instruction table (via EthInstructions::insert_instruction at runtime)
- [ ] Verify compilation

## Phase 3: Reth Integration
- [ ] FrameEvmConfig / FrameEvmFactory
- [ ] Frame execution loop
- [ ] Block executor integration
- [ ] Custom receipt type
- [ ] Transaction pool validation
- [ ] Consensus validation rules
- [ ] Custom hardfork definition

## Phase 4: Devnet
- [x] Genesis configuration (chainId 8141)
- [x] Launch script (devnet/run-devnet.sh)
- [x] Docker setup (devnet/docker-compose.yml)
- [ ] Verify node starts and produces blocks

## Phase 5: Solidity Contracts
- [x] ECDSAVerifier (contracts/src/ECDSAVerifier.sol)
- [x] MultisigVerifier (contracts/src/MultisigVerifier.sol)
- [x] WebAuthnVerifier (contracts/src/WebAuthnVerifier.sol)
- [ ] Deployment scripts

## Phase 6: Showcase Website
- [ ] Next.js project setup
- [x] EIP-8141 TypeScript encoder (showcase/lib/eip8141.ts)
- [x] viem chain config (showcase/lib/chain.ts)
- [ ] FrameBuilder playground
- [ ] Transaction explorer
- [ ] Signing flows (ECDSA, WebAuthn, Multisig)
