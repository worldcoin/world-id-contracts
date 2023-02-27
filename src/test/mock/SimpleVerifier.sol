// SPDX-License-Identifier: MIT
pragma solidity 0.8.4;

import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";

/// @title Simple Verifier
/// @author Worldcoin
/// @notice A dumb verifier to make it easy to fuzz test successes and failures.
contract SimpleVerifier is ITreeVerifier {
    function verifyProof(
        uint256 root,
        uint256 signalHash,
        uint256 nullifierHash,
        uint256 externalNullifierHash,
        uint256[8] calldata proof
    ) external pure override returns (bool) {
        delete root;
        delete signalHash;
        delete nullifierHash;
        delete externalNullifierHash;
        return proof[0] % 2 == 0;
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
