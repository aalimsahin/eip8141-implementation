// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MultisigVerifier
/// @notice EIP-8141 VERIFY frame contract for N-of-M multisig validation.
/// @dev Requires threshold number of valid ECDSA signatures from registered signers.
contract MultisigVerifier {
    address[] public signers;
    uint256 public threshold;

    constructor(address[] memory _signers, uint256 _threshold) {
        require(_threshold > 0 && _threshold <= _signers.length, "invalid threshold");
        // Ensure signers are sorted (ascending) for duplicate prevention
        for (uint256 i = 1; i < _signers.length; i++) {
            require(_signers[i] > _signers[i - 1], "signers must be sorted");
        }
        signers = _signers;
        threshold = _threshold;
    }

    function isSigner(address addr) public view returns (bool) {
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == addr) return true;
        }
        return false;
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

        // Decode: array of 65-byte signatures, packed
        uint256 sigCount = dataSize / 65;
        require(sigCount >= threshold, "MultisigVerifier: not enough signatures");

        address lastSigner;
        uint256 validCount;

        for (uint256 i = 0; i < sigCount; i++) {
            uint8 v;
            bytes32 r;
            bytes32 s;
            uint256 offset = i * 65;
            assembly {
                let ptr := add(add(frameData, 0x20), offset)
                v := byte(0, mload(ptr))
                r := mload(add(ptr, 0x01))
                s := mload(add(ptr, 0x21))
            }

            address recovered = ecrecover(sigHash, v, r, s);
            require(recovered != address(0), "MultisigVerifier: invalid signature");
            require(recovered > lastSigner, "MultisigVerifier: sigs must be sorted by signer");
            require(isSigner(recovered), "MultisigVerifier: unknown signer");

            lastSigner = recovered;
            validCount++;
        }

        require(validCount >= threshold, "MultisigVerifier: threshold not met");

        // APPROVE scope 0x2 (combined approval)
        assembly {
            verbatim_3i_0o(hex"aa", 0x00, 0x00, 0x02)
        }
    }
}
