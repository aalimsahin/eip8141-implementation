/// @title DilithiumApprover — EIP-8141 VERIFY frame wrapper for ETHDilithium
/// @notice This Yul source documents the approver bytecode constructed in
///         dilithium_examples_test.py::build_dilithium_approver_runtime().
///         It is NOT compiled directly; the Python test assembles equivalent
///         EVM bytecode with parameterized verifier and pk addresses.
///
/// Memory layout for STATICCALL to ISigVerifier.verify(bytes,bytes32,bytes):
///   0x00: selector (4 bytes)
///   0x04: ABI offset to pk  = 0x60
///   0x24: sigHash (bytes32)
///   0x44: ABI offset to sig = 0xA0
///   0x64: pk length = 0x14 (20 bytes)
///   0x84: pk address (20 bytes, right-padded to 32)
///   0xA4: sig length = calldatasize
///   0xC4: sig data (raw calldata from VERIFY frame)
///
/// Hardcoded (baked into deployed bytecode):
///   - VERIFIER_ADDR: address of ZKNOX_ethdilithium contract
///   - PK_ADDR:       address of PKContract (from setKey)
///   - APPROVE_SCOPE: 0/1/2

object "DilithiumApprover" {
    object "runtime" {
        code {
            // 1. Get signature hash via TXPARAMLOAD(param_id=0x08, offset=0x00)
            let sigHash := verbatim_2i_1o(hex"b0", 0x08, 0x00)
            mstore(0x24, sigHash)

            // 2. Write ISigVerifier.verify selector at bytes 0x00-0x03
            //    selector = bytes4(keccak256("verify(bytes,bytes32,bytes)"))
            mstore(0x00, shl(224, 0x024ad318))

            // 3. ABI head: offsets for dynamic params
            mstore(0x04, 0x60)  // offset to pk bytes
            // sigHash already at 0x24
            mstore(0x44, 0xA0)  // offset to sig bytes

            // 4. pk tail (20-byte address)
            mstore(0x64, 0x14)                    // pk length = 20
            mstore(0x84, shl(96, 0x0000000000000000000000000000000000000000))  // PK_ADDR placeholder

            // 5. sig tail (raw Dilithium signature from calldata)
            mstore(0xA4, calldatasize())           // sig length
            calldatacopy(0xC4, 0, calldatasize())  // sig data

            // 6. STATICCALL verifier
            let inputSize := add(0xC4, calldatasize())
            let ok := staticcall(
                gas(),
                0x0000000000000000000000000000000000000000,  // VERIFIER_ADDR placeholder
                0x00,          // input offset
                inputSize,     // input size
                0x00,          // output offset (reuse input area)
                0x20           // output size (bytes4, padded to 32)
            )

            // 7. Check success + return value
            if iszero(ok) { revert(0, 0) }
            let retval := mload(0x00)
            // ISigVerifier.verify.selector = 0x024ad318 (left-aligned bytes4)
            if iszero(eq(retval, shl(224, 0x024ad318))) { revert(0, 0) }

            // 8. APPROVE(scope, 0, 0)
            verbatim_3i_0o(hex"aa", 0x00, 0x00, 0x00)  // APPROVE_SCOPE placeholder
        }
    }
}
