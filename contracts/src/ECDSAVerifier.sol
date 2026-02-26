// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ECDSAVerifier
/// @notice EIP-8141 VERIFY frame contract for standard ECDSA signature validation.
/// @dev Called as STATICCALL in a VERIFY frame. Must invoke APPROVE opcode (0xaa) on success.
contract ECDSAVerifier {
    address public immutable owner;

    constructor(address _owner) {
        owner = _owner;
    }

    /// @notice Verify an ECDSA signature against the frame transaction's signature hash.
    /// @dev The signature hash is obtained via TXPARAMLOAD(0x08, 0).
    ///      frameData = abi.encodePacked(v, r, s) where v is uint8, r and s are bytes32.
    fallback() external {
        // Read the signature hash from TXPARAM (in1=0x08, in2=0x00)
        bytes32 sigHash;
        assembly {
            // TXPARAMLOAD: pops (in1, in2), pushes 32-byte value
            // in1 = 0x08 (signature hash), in2 = 0x00
            mstore(0x00, 0x08)
            mstore(0x20, 0x00)
            // Use raw opcode 0xb0 (TXPARAMLOAD)
            sigHash := verbatim_2i_1o(hex"b0", 0x08, 0x00)
        }

        // Read frame data size via TXPARAMSIZE
        uint256 dataSize;
        assembly {
            // TXPARAMSIZE(0x12, current_frame_index) returns size of current frame data
            let frameIdx := verbatim_2i_1o(hex"b0", 0x10, 0x00) // current frame index
            dataSize := verbatim_2i_1o(hex"b1", 0x12, frameIdx)
        }

        // Read frame data via TXPARAMCOPY
        bytes memory frameData = new bytes(dataSize);
        assembly {
            let frameIdx := verbatim_2i_1o(hex"b0", 0x10, 0x00)
            // TXPARAMCOPY(in1, in2, dest_offset, src_offset, length)
            verbatim_5i_0o(hex"b2", 0x12, frameIdx, add(frameData, 0x20), 0x00, dataSize)
        }

        // Decode signature: (uint8 v, bytes32 r, bytes32 s)
        require(frameData.length == 65, "ECDSAVerifier: invalid sig length");
        uint8 v;
        bytes32 r;
        bytes32 s;
        assembly {
            v := byte(0, mload(add(frameData, 0x20)))
            r := mload(add(frameData, 0x21))
            s := mload(add(frameData, 0x41))
        }

        address recovered = ecrecover(sigHash, v, r, s);
        require(recovered != address(0), "ECDSAVerifier: invalid signature");
        require(recovered == owner, "ECDSAVerifier: unauthorized signer");

        // Call APPROVE with scope 0x2 (combined sender + payment approval)
        assembly {
            // APPROVE pops (offset, length, scope)
            // offset=0, length=0 (no return data), scope=0x2
            verbatim_3i_0o(hex"aa", 0x00, 0x00, 0x02)
        }
    }
}
