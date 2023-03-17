// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ISemaphoreVerifier} from "semaphore/packages/contracts/contracts/interfaces/ISemaphoreVerifier.sol";

/// @title Simple Verifier
/// @author Worldcoin
/// @notice A dumb verifier to make it easy to fuzz test successes and failures.
contract SimpleSemaphoreVerifier is ISemaphoreVerifier {
    error Semaphore__InvalidProof();

    function verifyProof(
        uint256 merkleTreeRoot,
        uint256 nullifierHash,
        uint256 signal,
        uint256 externalNullifier,
        uint256[8] calldata proof,
        uint256 merkleTreeDepth
    ) external view {
        delete merkleTreeRoot;
        delete nullifierHash;
        delete signal;
        delete externalNullifier;
        delete merkleTreeDepth;

        if (proof[7] == 0) {
            revert Semaphore__InvalidProof();
        }
    }
}
