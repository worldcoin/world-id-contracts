// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import { Verifier } from 'semaphore/base/Verifier.sol';
import { ISemaphore } from './interfaces/ISemaphore.sol';
import { SemaphoreCore } from 'semaphore/base/SemaphoreCore.sol';
import { SemaphoreGroups } from 'semaphore/base/SemaphoreGroups.sol';
import {
    IncrementalBinaryTree,
    IncrementalTreeData
} from '@zk-kit/incremental-merkle-tree.sol/contracts/IncrementalBinaryTree.sol';

/// @title Semaphore Group Manager
/// @author Miguel Piedrafita
/// @notice A simple implementation of a ZK-based identity group manager using Semaphore
contract Semaphore is ISemaphore, SemaphoreCore, Verifier, SemaphoreGroups {
    using IncrementalBinaryTree for IncrementalTreeData;

    ///////////////////////////////////////////////////////////////////////////////
    ///                                  ERRORS                                 ///
    //////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when trying to update or create groups without being the manager
    error Unauthorized();

    /// @notice Thrown when trying to create a group with id 0, since this can later cause issues with root history verification.
    error InvalidId();

    /// @notice Thrown when attempting to validate a root that doesn't belong to the specified group.
    error InvalidRoot();

    ///////////////////////////////////////////////////////////////////////////////
    ///                                 STRUCTS                                  ///
    //////////////////////////////////////////////////////////////////////////////

    /// @notice Stores the group a root belongs to, along with a timestamp for when it was generated
    /// @param groupId The group this root belongs to
    /// @param timestamp The time the root was generated at
    struct RootHistory {
        uint128 groupId;
        uint128 timestamp;
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                              CONFIG STORAGE                            ///
    //////////////////////////////////////////////////////////////////////////////

    /// @notice The amount of time an outdated root for a group is considered as valid
    /// @dev This prevents proofs getting invalidated in the mempool by another tx modifying the group
    uint256 internal constant ROOT_HISTORY_EXPIRY = 1 hours;

    /// @notice The address that manages this contract, which is allowed to update and create groups.
    address public manager = msg.sender;

    mapping(uint256 => RootHistory) internal rootHistory;

    ///////////////////////////////////////////////////////////////////////////////
    ///                          GROUP MANAGEMENT LOGIC                        ///
    //////////////////////////////////////////////////////////////////////////////

    /// @notice Create a new identity group. Can only be called by the manager
    /// @param groupId The id of the group
    /// @param depth The depth of the tree
    /// @param zeroValue The zero value of the tree
    function createGroup(
        uint256 groupId,
        uint8 depth,
        uint256 zeroValue
    ) public {
        if (msg.sender != manager) revert Unauthorized();
        if (groupId == 0) revert InvalidId();

        _createGroup(groupId, depth, zeroValue);
    }

    /// @notice Add a new member to an existing group. Can only be called by the manager
    /// @param groupId The id of the group
    /// @param identityCommitment The identity commitment for the new member
    function addMember(uint256 groupId, uint256 identityCommitment) public {
        if (msg.sender != manager) revert Unauthorized();
        if (getDepth(groupId) == 0) revert InvalidId();

        groups[groupId].insert(identityCommitment);

        uint256 root = getRoot(groupId);
        rootHistory[root] = RootHistory({
            groupId: uint128(groupId),
            timestamp: uint128(block.timestamp)
        });

        emit MemberAdded(groupId, identityCommitment, root);
    }

    /// @notice Remove a member from an existing group. Can only be called by the manager
    /// @param groupId The id of the group
    /// @param identityCommitment The identity commitment for the member that'll be removed
    /// @param proofSiblings An array of the sibling nodes of the proof of membership
    /// @param proofPathIndices The path of the proof of membership
    function removeMember(
        uint256 groupId,
        uint256 identityCommitment,
        uint256[] calldata proofSiblings,
        uint8[] calldata proofPathIndices
    ) public {
        if (msg.sender != manager) revert Unauthorized();
        if (getDepth(groupId) == 0) revert InvalidId();

        groups[groupId].remove(identityCommitment, proofSiblings, proofPathIndices);

        uint256 root = getRoot(groupId);
        rootHistory[root] = RootHistory({
            groupId: uint128(groupId),
            timestamp: uint128(block.timestamp)
        });

        emit MemberRemoved(groupId, identityCommitment, groups[groupId].root);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                          PROOF VALIDATION LOGIC                        ///
    //////////////////////////////////////////////////////////////////////////////

    /// @notice Reverts if the zero-knowledge proof is invalid.
    /// @param root The of the Merkle tree
    /// @param groupId The id of the Semaphore group
    /// @param signalHash A keccak256 hash of the Semaphore signal
    /// @param nullifierHash The nullifier hash
    /// @param externalNullifierHash A keccak256 hash of the external nullifier
    /// @param proof The zero-knowledge proof
    /// @dev  Note that a double-signaling check is not included here, and should be carried by the caller.
    function verifyProof(
        uint256 root,
        uint256 groupId,
        uint256 signalHash,
        uint256 nullifierHash,
        uint256 externalNullifierHash,
        uint256[8] calldata proof
    ) public view {
        RootHistory memory rootData = rootHistory[root];

        if (
            rootData.groupId != groupId ||
            block.timestamp - rootData.timestamp > ROOT_HISTORY_EXPIRY
        ) revert InvalidRoot();

        uint256[4] memory publicSignals = [root, nullifierHash, signalHash, externalNullifierHash];

        verifyProof(
            [proof[0], proof[1]],
            [[proof[2], proof[3]], [proof[4], proof[5]]],
            [proof[6], proof[7]],
            publicSignals
        );
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                               CONFIG LOGIC                             ///
    //////////////////////////////////////////////////////////////////////////////

    /// @notice Transfer management access to a different address, or to 0x0 to renounce. Can only be called by the manager
    /// @param newManager The address of the new manager
    function transferAccess(address newManager) public {
        if (msg.sender != manager) revert Unauthorized();

        manager = newManager;
    }
}
