// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ISemaphoreVerifier} from "semaphore/packages/contracts/contracts/interfaces/ISemaphoreVerifier.sol";

/// @title Simple Verifier
/// @author Worldcoin
/// @notice A dumb verifier to make it easy to fuzz test successes and failures.
contract SimpleSemaphoreVerifier is ISemaphoreVerifier {
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
    }
}

library SimpleVerify {
    function isValidInput(uint256 a) public pure returns (bool) {
        return a % 2 == 0;
    }

    function calculateInputHash(
        uint32 startIndex,
        uint256 preRoot,
        uint256 postRoot,
        uint256[] calldata identityCommitments
    ) public pure returns (bytes32 hash) {
        bytes memory bytesToHash =
            abi.encodePacked(startIndex, preRoot, postRoot, identityCommitments);

        hash = keccak256(bytesToHash);
    }
}
