// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {Verifier} from "semaphore/base/Verifier.sol";
import {IWorldID} from "./interfaces/IWorldID.sol";
import {SemaphoreCore} from "semaphore/base/SemaphoreCore.sol";
import {SemaphoreGroups} from "semaphore/base/SemaphoreGroups.sol";
import {
    IncrementalBinaryTree,
    IncrementalTreeData
} from "@zk-kit/incremental-merkle-tree.sol/contracts/IncrementalBinaryTree.sol";

/// @title Semaphore Group Manager
/// @author Worldcoin
/// @notice A simple implementation of a ZK-based identity group manager using Semaphore
contract Semaphore is IWorldID, SemaphoreCore {
    ///////////////////////////////////////////////////////////////////////////////
    ///                                  ERRORS                                 ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when trying to update or create groups without being the manager
    error Unauthorized();

    /// @notice Thrown when trying to create a group with id 0, since this can later cause issues with root history verification.
    error InvalidId();

    /// @notice Thrown when attempting to validate a root that doesn't belong to the specified group.
    error InvalidRoot();

    /// @notice Thrown when attempting to validate a root that has expired.
    error ExpiredRoot();

    /// @notice Thrown when attempting to validate a root that has yet to be added to the root history.
    error NonExistentRoot();

    /// @notice Thrown when trying to insert the initial leaf into a given group.
    error InvalidCommitment();

    ///////////////////////////////////////////////////////////////////////////////
    ///                              CONFIG STORAGE                             ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice The amount of time an outdated root for a group is considered as valid.
    /// @dev This prevents proofs getting invalidated in the mempool by another tx modifying the group.
    uint256 internal constant ROOT_HISTORY_EXPIRY = 1 hours;

    /// @notice Represents the initial leaf in an empty merkle tree.
    /// @dev Prevents the empty leaf from being inserted into the root history.
    uint256 internal constant EMPTY_LEAF = uint256(0);

    /// @notice The address that manages this contract, which is allowed to update and create groups.
    address public manager = msg.sender;

    /// @notice A mapping from the value of the merkle tree root to the timestamp at which it existed.
    mapping(uint256 => uint128) internal rootHistory;

    /// @notice The latest root of the merkle tree.
    uint256 public latestRoot;

    ///////////////////////////////////////////////////////////////////////////////
    ///                          INTERNAL FUNCTIONALITY                         ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice The verifier instance needed for operating within the semaphore protocol.
    Verifier private semaphoreVerifier;

    ///////////////////////////////////////////////////////////////////////////////
    ///                          GROUP MANAGEMENT LOGIC                         ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Add a new member to an existing group. Can only be called by the manager
    /// @param identityCommitment The identity commitment for the new member
    function addMember(uint256 identityCommitment) public {
        // if (msg.sender != manager) revert Unauthorized();

        // if (identityCommitment == EMPTY_LEAF) revert InvalidCommitment();

        // uint256 leafIndex = groups[groupId].insert(identityCommitment);

        // uint256 root = getRoot(groupId);
        // rootHistory[root] = RootHistory({groupId: uint128(groupId), timestamp: uint128(block.timestamp)});

        // latestRoots[groupId] = root;

        // emit MemberAdded(groupId, leafIndex, identityCommitment, root);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                                MODIFIERS                                ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice A modifier that states that the annotated function must only be called by the owner of the contract.
    /// @dev Will revert with `Unauthorized` if the caller is not the owner of this contract.
    modifier mustBeCalledByOwner() virtual {
        if (msg.sender != manager) {
            revert Unauthorized();
        }
        _;
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                    SEMAPHORE PROOF VALIDATION LOGIC                     ///
    ///////////////////////////////////////////////////////////////////////////////

    /// A verifier for the semaphore protocol.
    ///
    /// @notice Reverts if the zero-knowledge proof is invalid.
    /// @param root The of the Merkle tree
    /// @param signalHash A keccak256 hash of the Semaphore signal
    /// @param nullifierHash The nullifier hash
    /// @param externalNullifierHash A keccak256 hash of the external nullifier
    /// @param proof The zero-knowledge proof
    /// @dev  Note that a double-signaling check is not included here, and should be carried by the caller.
    function verifyProof(
        uint256 root,
        uint256 signalHash,
        uint256 nullifierHash,
        uint256 externalNullifierHash,
        uint256[8] calldata proof
    ) public view {
        uint256[4] memory publicSignals = [root, nullifierHash, signalHash, externalNullifierHash];

        if (checkValidRoot(root)) {
            semaphoreVerifier.verifyProof(
                [proof[0], proof[1]],
                [[proof[2], proof[3]], [proof[4], proof[5]]],
                [proof[6], proof[7]],
                publicSignals
            );
        }
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                            CONFIGURATION LOGIC                          ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Transfer management access to a different address, or to 0x0 to renounce.
    /// @dev Can only be called by the manager of the contract. Will revert if it is not.
    /// @param newManager The address of the new manager
    function transferAccess(address newManager) public mustBeCalledByOwner {
        manager = newManager;
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                              VIEW FUNCTIONS                             ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Checks if a given root value is valid and has been added to the root history.
    /// @dev Reverts with `ExpiredRoot` if the root has expired, and `NonExistentRoot` if the root is not in the root history.
    /// @param root The root of a given identity group.
    function checkValidRoot(uint256 root) public view returns (bool) {
        if (root != latestRoot) {
            uint128 rootTimestamp = rootHistory[root];

            // A root is no longer valid if it has expired.
            if (block.timestamp - rootTimestamp > ROOT_HISTORY_EXPIRY) {
                revert ExpiredRoot();
            }

            // A root does not exist if it has no associated timestamp.
            if (rootTimestamp == 0) {
                revert NonExistentRoot();
            }
        }

        return true;
    }
}
