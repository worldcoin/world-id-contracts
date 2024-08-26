// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";

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

library SimpleVerify {
    function isValidInput(uint256 a) public pure returns (bool) {
        return a % 2 == 0;
    }
}
