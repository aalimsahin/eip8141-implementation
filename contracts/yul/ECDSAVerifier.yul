/// @title ECDSAVerifier (Yul)
/// @notice Verifies ECDSA signatures for EIP-8141 frame transactions.
/// @dev Compiled with `solc --strict-assembly` to support verbatim opcodes.
///      Constructor takes owner address as a 32-byte ABI-encoded argument.
///      Fallback expects calldata: abi.encode(uint8 v, bytes32 r, bytes32 s)
object "ECDSAVerifier" {
    /// Constructor: reads owner from constructor args appended after code
    code {
        // Copy constructor argument (address _owner, 32 bytes)
        // It's appended after the deployed code
        let owner := 0
        // Load the 32-byte constructor arg (right after init code)
        datacopy(0x00, dataoffset("runtime"), datasize("runtime"))
        let argOffset := add(dataoffset("runtime"), datasize("runtime"))
        datacopy(0x80, argOffset, 0x20)
        owner := mload(0x80)

        // Store owner as immutable by prepending it to runtime code
        // Runtime code will read it from its own deployed bytecode
        // Strategy: deploy runtime code with owner embedded at a known offset

        // We'll store owner in memory right before runtime code
        // Then the runtime code will use CODECOPY to read it

        // Layout in deployed code: [runtime_bytecode][owner_32_bytes]
        let runtimeSize := datasize("runtime")
        datacopy(0x00, dataoffset("runtime"), runtimeSize)
        mstore(add(0x00, runtimeSize), owner)
        return(0x00, add(runtimeSize, 0x20))
    }

    object "runtime" {
        code {
            // === Read owner from end of deployed code ===
            let _codeSize := codesize()
            codecopy(0x00, sub(_codeSize, 0x20), 0x20)
            let owner := mload(0x00)

            // === Decode calldata: abi.encode(uint8 v, bytes32 r, bytes32 s) ===
            // v is at offset 0 (32 bytes, uint8 padded), r at 32, s at 64
            if lt(calldatasize(), 96) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 26)
                mstore(0x44, "ECDSAVerifier: bad calldata")
                revert(0x00, 0x64)
            }
            let v := calldataload(0x00)
            let r := calldataload(0x20)
            let s := calldataload(0x40)

            // === Get sig_hash via TXPARAMLOAD(0x08, 0) ===
            let sigHash := verbatim_2i_1o(hex"b0", 0x08, 0x00)

            // === ecrecover(sigHash, v, r, s) ===
            // Precompile at address 0x01
            // Input: hash(32) | v(32) | r(32) | s(32)
            mstore(0x00, sigHash)
            mstore(0x20, v)
            mstore(0x40, r)
            mstore(0x60, s)

            let success := staticcall(gas(), 0x01, 0x00, 0x80, 0x80, 0x20)
            if iszero(success) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 29)
                mstore(0x44, "ECDSAVerifier: ecrecover fail")
                revert(0x00, 0x64)
            }

            let recovered := mload(0x80)
            // Mask to 20 bytes (address)
            recovered := and(recovered, 0xffffffffffffffffffffffffffffffffffffffff)

            // === Verify recovered == owner ===
            if iszero(eq(recovered, and(owner, 0xffffffffffffffffffffffffffffffffffffffff))) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 31)
                mstore(0x44, "ECDSAVerifier: invalid signer")
                revert(0x00, 0x64)
            }

            // === APPROVE(offset=0, length=0, scope=0x02) ===
            // Approves both sender and payer
            verbatim_3i_0o(hex"aa", 0x00, 0x00, 0x02)
        }
    }
}
