// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title WebAuthnVerifier
/// @notice Verifies WebAuthn/Passkey (P-256) signatures for EIP-8141 frame transactions.
/// @dev Uses the RIP-7212 P256VERIFY precompile at address 0x100.
///
///      COMPILATION NOTE: Uses `verbatim` for custom opcodes (TXPARAMLOAD 0xb0,
///      APPROVE 0xaa). Compile the Yul version (yul/WebAuthnVerifier.yul) for
///      deployable bytecode. This Solidity file is a readable reference.
contract WebAuthnVerifier {
    /// @notice The P-256 public key X coordinate.
    bytes32 public immutable pubKeyX;
    /// @notice The P-256 public key Y coordinate.
    bytes32 public immutable pubKeyY;

    /// @notice RIP-7212 P256VERIFY precompile address.
    address constant P256_VERIFIER = address(0x100);

    constructor(bytes32 _pubKeyX, bytes32 _pubKeyY) {
        pubKeyX = _pubKeyX;
        pubKeyY = _pubKeyY;
    }

    /// @notice Verify a WebAuthn P-256 signature.
    /// @dev Calldata format: abi.encode(bytes32 r, bytes32 s, bytes authenticatorData, bytes clientDataJSON)
    ///      The sig_hash is used as the challenge in the WebAuthn assertion.
    fallback() external {
        (bytes32 r, bytes32 s, bytes memory authenticatorData, bytes memory clientDataJSON) =
            abi.decode(msg.data, (bytes32, bytes32, bytes, bytes));

        // Get the signature hash (used as the WebAuthn challenge)
        bytes32 sigHash;
        assembly {
            sigHash := verbatim_2i_1o(hex"b0", 0x08, 0)
        }

        // Compute the WebAuthn message hash
        // message = sha256(authenticatorData || sha256(clientDataJSON))
        bytes32 clientDataHash = sha256(clientDataJSON);
        bytes32 message = sha256(abi.encodePacked(authenticatorData, clientDataHash));

        // Call P256VERIFY precompile: input = (message_hash, r, s, x, y)
        bytes memory input = abi.encode(message, r, s, pubKeyX, pubKeyY);
        (bool success, bytes memory result) = P256_VERIFIER.staticcall(input);

        require(success && result.length == 32, "P256 verification failed");
        require(abi.decode(result, (uint256)) == 1, "invalid P256 signature");

        assembly {
            verbatim_3i_0o(hex"aa", 0, 0, 0x02)
        }
    }
}
