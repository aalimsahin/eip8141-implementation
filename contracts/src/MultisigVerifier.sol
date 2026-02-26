// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MultisigVerifier
/// @notice N-of-M ECDSA multisig verifier for EIP-8141 frame transactions.
///
/// @dev COMPILATION NOTE: Uses `verbatim` for custom opcodes (TXPARAMLOAD 0xb0,
///      APPROVE 0xaa). Compile the Yul version (yul/MultisigVerifier.yul) for
///      deployable bytecode. This Solidity file is a readable reference.
contract MultisigVerifier {
    /// @notice Required number of signatures.
    uint256 public immutable threshold;
    /// @notice Total number of signers.
    uint256 public immutable signerCount;
    /// @notice Mapping of authorized signers.
    mapping(address => bool) public isSigner;

    constructor(address[] memory _signers, uint256 _threshold) {
        require(_threshold > 0 && _threshold <= _signers.length, "invalid threshold");
        threshold = _threshold;
        signerCount = _signers.length;
        for (uint256 i = 0; i < _signers.length; i++) {
            require(_signers[i] != address(0), "zero address");
            require(!isSigner[_signers[i]], "duplicate signer");
            isSigner[_signers[i]] = true;
        }
    }

    /// @notice Verify N-of-M ECDSA signatures.
    /// @dev Calldata: abi.encode(uint8[] v, bytes32[] r, bytes32[] s)
    ///      Signatures must be sorted by signer address (ascending) to prevent duplicates.
    fallback() external {
        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) =
            abi.decode(msg.data, (uint8[], bytes32[], bytes32[]));

        require(v.length == threshold, "wrong signature count");
        require(r.length == threshold, "wrong r count");
        require(s.length == threshold, "wrong s count");

        bytes32 sigHash;
        assembly {
            sigHash := verbatim_2i_1o(hex"b0", 0x08, 0)
        }

        address lastSigner = address(0);
        for (uint256 i = 0; i < threshold; i++) {
            address recovered = ecrecover(sigHash, v[i], r[i], s[i]);
            require(recovered != address(0), "invalid signature");
            require(isSigner[recovered], "not a signer");
            require(recovered > lastSigner, "signers not sorted");
            lastSigner = recovered;
        }

        assembly {
            verbatim_3i_0o(hex"aa", 0, 0, 0x02)
        }
    }
}
