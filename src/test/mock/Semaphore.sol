// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {Verifier} from "semaphore/base/Verifier.sol";
import {ISemaphore} from "../../interfaces/ISemaphore.sol";
import {SemaphoreCore} from "semaphore/base/SemaphoreCore.sol";
import {SemaphoreGroups} from "semaphore/base/SemaphoreGroups.sol";

contract Semaphore is ISemaphore, SemaphoreCore, Verifier, SemaphoreGroups {
    function isValidProof(
        bytes32 signal,
        uint256 root,
        uint256 nullifierHash,
        uint256 externalNullifier,
        uint256[8] calldata proof
    ) public view returns (bool) {
        uint256 signalHash = uint256(keccak256(abi.encodePacked(signal))) >> 8;

        uint256[4] memory publicSignals = [
            root,
            nullifierHash,
            signalHash,
            externalNullifier
        ];

        return
            verifyProof(
                [proof[0], proof[1]],
                [[proof[2], proof[3]], [proof[4], proof[5]]],
                [proof[6], proof[7]],
                publicSignals
            );
    }

    function createGroup(
        uint256 groupId,
        uint8 depth,
        uint256 zeroValue
    ) public {
        _createGroup(groupId, depth, zeroValue);
    }

    function addMember(uint256 groupId, uint256 identityCommitment) public {
        _addMember(groupId, identityCommitment);
    }

    function getRoot(uint256 groupId)
        public
        view
        override(ISemaphore, SemaphoreGroups)
        returns (uint256)
    {
        return SemaphoreGroups.getRoot(groupId);
    }
}
