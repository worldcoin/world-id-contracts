// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {ISemaphoreVerifier} from "src/interfaces/ISemaphoreVerifier.sol";

/// @title Simple Verifier
/// @author Worldcoin
/// @notice A dumb verifier to make it easy to fuzz test successes and failures.
contract SimpleSemaphoreVerifier is ISemaphoreVerifier {
    error Semaphore__InvalidProof();

    function verifyProof(uint256[8] calldata proof, uint256[4] memory input) external pure {
        delete input;

        if (proof[0] % 2 == 0) {
            revert Semaphore__InvalidProof();
        }
    }
}
