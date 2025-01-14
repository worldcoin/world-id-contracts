// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";
import {ITreeVerifier4844} from "../../interfaces/ITreeVerifier4844.sol";

/// @title Simple Verifier
/// @author Worldcoin
/// @notice A dumb verifier to make it easy to fuzz test successes and failures.
contract SimpleVerifier is ITreeVerifier {
    uint256 batchSize;

    event VerifiedProof(uint256 batchSize);

    constructor(uint256 _batchSize) {
        batchSize = _batchSize;
    }

    function verifyProof(uint256[8] memory proof, uint256[1] memory input) external {
        bool result = proof[0] % 2 == 0;

        input[0] = 0;
        if (result) {
            emit VerifiedProof(batchSize);
        }
    }
}

/// @title Simple Verifier for EIP-4844 proofs.
/// @author Worldcoin
/// @notice A dumb verifier to make it easy to fuzz test successes and failures.
contract SimpleVerifier4844 is ITreeVerifier4844 {
    uint256 batchSize;

    event VerifiedProof(uint256 batchSize);

    constructor(uint256 _batchSize) {
        batchSize = _batchSize;
    }

    function verifyProof(
        uint256[8] memory proof,
        uint256[2] memory,
        uint256[2] memory,
        uint256[6] memory input
    ) external {
        bool result = proof[0] % 2 == 0;

        input[0] = 0;
        if (result) {
            emit VerifiedProof(batchSize);
        }
    }
}

library SimpleVerify {
    function isValidInput(uint256 a) public pure returns (bool) {
        return a % 2 == 0;
    }
}
