// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title WebAuthnVerifier
/// @notice EIP-8141 VERIFY frame contract for WebAuthn / Passkey (P-256) signature validation.
/// @dev Uses the P256VERIFY precompile (RIP-7212) at address 0x100 for secp256r1 verification.
///      This enables biometric authentication (Touch ID, Face ID) for Ethereum transactions.
contract WebAuthnVerifier {
    bytes32 public immutable pubKeyX;
    bytes32 public immutable pubKeyY;

    /// @dev P256VERIFY precompile address (RIP-7212, active since Pectra)
    address constant P256_VERIFIER = address(0x0000000000000000000000000000000000000100);

    constructor(bytes32 _pubKeyX, bytes32 _pubKeyY) {
        pubKeyX = _pubKeyX;
        pubKeyY = _pubKeyY;
    }

    fallback() external {
        // Read signature hash via TXPARAMLOAD
        bytes32 sigHash;
        assembly {
            sigHash := verbatim_2i_1o(hex"b0", 0x08, 0x00)
        }

        // Read frame data
        uint256 dataSize;
        assembly {
            let frameIdx := verbatim_2i_1o(hex"b0", 0x10, 0x00)
            dataSize := verbatim_2i_1o(hex"b1", 0x12, frameIdx)
        }
        bytes memory frameData = new bytes(dataSize);
        assembly {
            let frameIdx := verbatim_2i_1o(hex"b0", 0x10, 0x00)
            verbatim_5i_0o(hex"b2", 0x12, frameIdx, add(frameData, 0x20), 0x00, dataSize)
        }

        // Decode: (bytes32 r, bytes32 s, bytes authenticatorData, bytes clientDataJSON)
        (bytes32 r, bytes32 s, bytes memory authData, bytes memory clientData) =
            abi.decode(frameData, (bytes32, bytes32, bytes, bytes));

        // Reconstruct the WebAuthn message:
        // message = sha256(authenticatorData || sha256(clientDataJSON))
        bytes32 clientDataHash = sha256(clientData);
        bytes32 message = sha256(abi.encodePacked(authData, clientDataHash));

        // Verify P-256 signature via RIP-7212 precompile
        // Input: hash (32) || r (32) || s (32) || x (32) || y (32) = 160 bytes
        // Output: 1 (valid) or 0 (invalid), 32 bytes
        (bool success, bytes memory result) = P256_VERIFIER.staticcall(
            abi.encodePacked(message, r, s, pubKeyX, pubKeyY)
        );
        require(success && result.length == 32, "WebAuthnVerifier: P256 call failed");
        uint256 verified;
        assembly {
            verified := mload(add(result, 0x20))
        }
        require(verified == 1, "WebAuthnVerifier: invalid P-256 signature");

        // APPROVE scope 0x2 (combined approval)
        assembly {
            verbatim_3i_0o(hex"aa", 0x00, 0x00, 0x02)
        }
    }
}
