// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ECDSAVerifier
/// @notice Verifies ECDSA signatures for EIP-8141 frame transactions.
/// @dev Called by VERIFY frames. Uses TXPARAM opcodes to read sig_hash,
///      verifies ecrecover matches the owner, then calls APPROVE.
///
///      COMPILATION NOTE: This file uses `verbatim` in inline assembly for
///      custom EVM opcodes (TXPARAMLOAD 0xb0, APPROVE 0xaa). The `verbatim`
///      builtin is only available in standalone Yul, not Solidity inline assembly.
///      For deployable bytecode, compile the Yul version: yul/ECDSAVerifier.yul
///      using `solc --strict-assembly`. This Solidity file serves as a readable
///      reference for the contract's logic.
contract ECDSAVerifier {
    /// @notice The owner address whose signature is required.
    address public immutable owner;

    constructor(address _owner) {
        owner = _owner;
    }

    /// @notice Verify an ECDSA signature passed in the VERIFY frame's calldata.
    /// @dev Calldata format: abi.encode(uint8 v, bytes32 r, bytes32 s)
    ///      The sig_hash is read via TXPARAMLOAD opcode.
    fallback() external {
        // Decode v, r, s from calldata (the VERIFY frame's data)
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(msg.data, (uint8, bytes32, bytes32));

        // Get the signature hash via TXPARAMLOAD
        bytes32 sigHash;
        assembly {
            sigHash := verbatim_2i_1o(hex"b0", 0x08, 0)
        }

        // Recover the signer
        address recovered = ecrecover(sigHash, v, r, s);
        require(recovered == owner, "ECDSAVerifier: invalid signature");

        // Approve both sender and payer
        assembly {
            verbatim_3i_0o(hex"aa", 0, 0, 0x02)
        }
    }
}
