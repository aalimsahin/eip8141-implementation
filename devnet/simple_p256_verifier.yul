/// @title P256Verifier (Yul)
/// @notice Verifies P256 (secp256r1) signatures for EIP-8141 frame transactions.
/// @dev Constructor takes pubKeyX and pubKeyY as 64-byte ABI-encoded arguments
///      appended after the init code. Fallback expects calldata: r(32) || s(32).
///
///      Runtime flow:
///      1. Read pubKeyX, pubKeyY from end of deployed bytecode
///      2. Get sig_hash via TXPARAMLOAD(0x08, 0)
///      3. Read r || s from calldata
///      4. Call P256VERIFY precompile at 0x0100 with:
///         sig_hash(32) | r(32) | s(32) | pubKeyX(32) | pubKeyY(32)
///      5. If valid: APPROVE(0, 0, 0x00) — sender approval
///      6. If invalid: REVERT
object "P256Verifier" {
    /// Constructor: deploys runtime code with pubKeyX || pubKeyY appended
    code {
        let runtimeSize := datasize("runtime")
        // Copy runtime code to memory at 0x00
        datacopy(0x00, dataoffset("runtime"), runtimeSize)

        // Copy constructor args (pubKeyX || pubKeyY, 64 bytes) from end of creation code
        // Args are appended after init_code in the deployment tx
        let argsOffset := sub(codesize(), 0x40)
        datacopy(add(0x00, runtimeSize), argsOffset, 0x40)

        // Deploy: runtime + pubKeyX + pubKeyY
        return(0x00, add(runtimeSize, 0x40))
    }

    object "runtime" {
        code {
            // === Read pubKeyX, pubKeyY from end of deployed code (64 bytes) ===
            // Store at mem[0x60..0xA0] to prepare for precompile input layout
            let _codeSize := codesize()
            codecopy(0x60, sub(_codeSize, 0x40), 0x40)

            // === Get sig_hash via TXPARAMLOAD(param_id=0x08, offset=0x00) ===
            let sigHash := verbatim_2i_1o(hex"b0", 0x08, 0x00)
            mstore(0x00, sigHash)

            // === Read r, s from calldata (64 bytes) ===
            if lt(calldatasize(), 64) {
                revert(0, 0)
            }
            let r := calldataload(0x00)
            let s := calldataload(0x20)
            mstore(0x20, r)
            mstore(0x40, s)

            // === Call P256VERIFY precompile at 0x0100 ===
            // Input layout (160 bytes): sig_hash | r | s | pubKeyX | pubKeyY
            // Already at mem[0x00..0xA0]
            let success := staticcall(gas(), 0x0100, 0x00, 0xA0, 0xA0, 0x20)

            if iszero(success) {
                revert(0, 0)
            }

            // P256VERIFY returns bytes32 with last byte = 1 if valid, empty if invalid
            let result := mload(0xA0)
            if iszero(result) {
                revert(0, 0)
            }

            // === APPROVE(offset=0, length=0, scope=0x00) — sender approval ===
            verbatim_3i_0o(hex"aa", 0x00, 0x00, 0x00)
        }
    }
}
