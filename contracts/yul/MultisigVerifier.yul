/// @title MultisigVerifier (Yul)
/// @notice N-of-M ECDSA multisig verifier for EIP-8141 frame transactions.
/// @dev Constructor args: abi.encode(address[] signers, uint256 threshold)
///      Fallback calldata: abi.encode(uint8[] v, bytes32[] r, bytes32[] s)
///      Signatures must be sorted by recovered address (ascending) to prevent duplicates.
///      Signer set is stored in contract storage as a mapping(address => bool).
///      Storage layout: slot 0 = threshold, slot 1 = signerCount,
///      isSigner[addr] at keccak256(addr . 2) where 2 is the mapping slot.
object "MultisigVerifier" {
    code {
        // === Parse constructor args: abi.encode(address[] signers, uint256 threshold) ===
        // Constructor args are appended after init code by the deployer.
        let argSize := sub(codesize(), datasize("MultisigVerifier"))
        let argStart := datasize("MultisigVerifier")

        // Copy args to memory at 0x200
        codecopy(0x200, argStart, argSize)

        // ABI decode: first word is offset to signers array, second is threshold
        let signersOffset := add(0x200, mload(0x200))
        let threshold := mload(add(0x200, 0x20))

        let signerCount := mload(signersOffset)

        // Validate threshold
        if iszero(threshold) { revert(0, 0) }
        if gt(threshold, signerCount) { revert(0, 0) }

        // Store threshold in slot 0, signerCount in slot 1
        sstore(0, threshold)
        sstore(1, signerCount)

        // Store isSigner mapping (slot 2): keccak256(abi.encode(addr, 2))
        for { let i := 0 } lt(i, signerCount) { i := add(i, 1) } {
            let signer := mload(add(signersOffset, add(0x20, mul(i, 0x20))))
            signer := and(signer, 0xffffffffffffffffffffffffffffffffffffffff)

            // Require non-zero address
            if iszero(signer) { revert(0, 0) }

            // Compute storage slot: keccak256(abi.encode(signer, 2))
            mstore(0x00, signer)
            mstore(0x20, 2)
            let slot := keccak256(0x00, 0x40)

            // Check no duplicate
            if sload(slot) { revert(0, 0) }

            sstore(slot, 1)
        }

        // Deploy runtime code
        datacopy(0x00, dataoffset("runtime"), datasize("runtime"))
        return(0x00, datasize("runtime"))
    }

    object "runtime" {
        code {
            // === Read threshold from storage ===
            let threshold := sload(0)

            // === Decode calldata: abi.encode(uint8[] v, bytes32[] r, bytes32[] s) ===
            if lt(calldatasize(), 0x60) { revert(0, 0) }

            // Dynamic arrays: each starts with an offset, then length, then elements
            let vOffset := add(0x04, calldataload(0x00))
            let rOffset := add(0x04, calldataload(0x20))
            let sOffset := add(0x04, calldataload(0x40))

            // Wait -- no function selector, this is a fallback with raw calldata
            // Re-decode without 0x04 offset
            // abi.encode(uint8[], bytes32[], bytes32[]) layout:
            // [0x00]: offset to v array
            // [0x20]: offset to r array
            // [0x40]: offset to s array
            // At each offset: [length][elem0][elem1]...

            let vOff := add(calldataload(0x00), 0x00)
            let rOff := add(calldataload(0x20), 0x00)
            let sOff := add(calldataload(0x40), 0x00)

            // Read lengths (at the offset position in calldata)
            let vLen := calldataload(vOff)
            let rLen := calldataload(rOff)
            let sLen := calldataload(sOff)

            // Require all lengths == threshold
            if iszero(eq(vLen, threshold)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 21)
                mstore(0x44, "wrong signature count")
                revert(0x00, 0x64)
            }
            if iszero(eq(rLen, threshold)) { revert(0, 0) }
            if iszero(eq(sLen, threshold)) { revert(0, 0) }

            // === Get sig_hash via TXPARAMLOAD(0x08, 0) ===
            let sigHash := verbatim_2i_1o(hex"b0", 0x08, 0x00)

            // === Verify each signature ===
            let lastSigner := 0

            for { let i := 0 } lt(i, threshold) { i := add(i, 1) } {
                // Read v[i], r[i], s[i] from calldata
                let vi := calldataload(add(vOff, add(0x20, mul(i, 0x20))))
                let ri := calldataload(add(rOff, add(0x20, mul(i, 0x20))))
                let si := calldataload(add(sOff, add(0x20, mul(i, 0x20))))

                // ecrecover(sigHash, v, r, s)
                mstore(0x00, sigHash)
                mstore(0x20, vi)
                mstore(0x40, ri)
                mstore(0x60, si)

                let ok := staticcall(gas(), 0x01, 0x00, 0x80, 0x80, 0x20)
                if iszero(ok) {
                    mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, 0x20)
                    mstore(0x24, 17)
                    mstore(0x44, "invalid signature")
                    revert(0x00, 0x64)
                }

                let recovered := and(mload(0x80), 0xffffffffffffffffffffffffffffffffffffffff)
                if iszero(recovered) { revert(0, 0) }

                // Check isSigner[recovered]
                mstore(0x00, recovered)
                mstore(0x20, 2)
                let slot := keccak256(0x00, 0x40)
                if iszero(sload(slot)) {
                    mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, 0x20)
                    mstore(0x24, 12)
                    mstore(0x44, "not a signer")
                    revert(0x00, 0x64)
                }

                // Ensure sorted (ascending) - prevents duplicate signatures
                if iszero(gt(recovered, lastSigner)) {
                    mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, 0x20)
                    mstore(0x24, 18)
                    mstore(0x44, "signers not sorted")
                    revert(0x00, 0x64)
                }

                lastSigner := recovered
            }

            // === APPROVE(offset=0, length=0, scope=0x02) ===
            verbatim_3i_0o(hex"aa", 0x00, 0x00, 0x02)
        }
    }
}
