// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IFrameVerifier
/// @notice Interface for EIP-8141 frame transaction verifiers.
/// @dev Verifiers are called by VERIFY frames as STATICALLs.
///      They must read the sig_hash via TXPARAMLOAD, verify the proof
///      in calldata, and call APPROVE to approve the transaction.
interface IFrameVerifier {
    /// @notice Returns a description of this verifier's scheme.
    function scheme() external view returns (string memory);
}
