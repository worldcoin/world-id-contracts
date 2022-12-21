// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {Verifier as SemaphoreVerifier} from "semaphore/base/Verifier.sol";
import {IWorldID} from "./interfaces/IWorldID.sol";
import {SemaphoreCore} from "semaphore/base/SemaphoreCore.sol";
import {SemaphoreGroups} from "semaphore/base/SemaphoreGroups.sol";
import {
    IncrementalBinaryTree,
    IncrementalTreeData
} from "@zk-kit/incremental-merkle-tree.sol/contracts/IncrementalBinaryTree.sol";
import {Verifier as MerkleTreeVerifier} from "./generated/TreeVerifier.sol";

/// @title WorldID Identity Manager
/// @author Worldcoin
/// @notice An implementation of a batch-based identity manager for the WorldID protocol.
/// @dev The manager is based on the principle of verifying externally-created Zero Knowledge Proofs
///      to perform the insertions.
contract Semaphore is IWorldID, SemaphoreCore {
    ///////////////////////////////////////////////////////////////////////////////
    ///                       PUBLIC CONFIGURATION STORAGE                      ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice The address that manages this contract, which is allowed to update and create groups.
    address public manager = msg.sender;

    /// @notice The latest root of the merkle tree.
    uint256 public latestRoot;

    ///////////////////////////////////////////////////////////////////////////////
    ///                             EXTERNAL CONSTANTS                          ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice A constant representing a root that doesn't exist.
    /// @dev Can be checked against when querying for root data.
    function NO_SUCH_ROOT() public pure returns (RootInfo memory rootInfo) {
        return RootInfo(0x0, 0x0, false);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                               PUBLIC TYPES                              ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice The proof data for verifying the merkle tree proof.
    /// @dev Corresponds to `MerkleTreeVerifier.Proof` but provides an external interface.
    ///
    /// @param ar Corresponds to `ar` in the proof or `A` in the internal proof.
    /// @param bs Corresponds to `bs` in the proof or `B` in the internal proof.
    /// @param krs Corresponds to `krs` in the proof or `C` in the internal proof.
    struct MerkleTreeProof {
        G1Point ar;
        G2Point bs;
        G1Point krs;
    }

    /// @notice A structure representing a G1 point.
    /// @dev Used for providing the merkle tree proof data.
    struct G1Point {
        uint256 x;
        uint256 y;
    }

    /// @notice A structure representing a G2 point.
    /// @dev Used for providing the merkle tree proof data.
    struct G2Point {
        uint256[2] x;
        uint256[2] y;
    }

    /// @notice Provides information about a merkle tree root.
    ///
    /// @param root The value of the merkle tree root.
    /// @param timestamp The timestamp at which the root was inserted into the history.
    /// @param isValid Whether or not the root is valid (has not expired).
    struct RootInfo {
        uint256 root;
        uint128 timestamp;
        bool isValid;
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                       PRIVATE CONFIGURATION STORAGE                      ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice A mapping from the value of the merkle tree root to the timestamp at which it 
    ///         existed.
    mapping(uint256 => uint128) internal rootHistory;

    ///////////////////////////////////////////////////////////////////////////////
    ///                             INTERNAL CONSTANTS                          ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice The amount of time an outdated root for a group is considered as valid.
    /// @dev This prevents proofs getting invalidated in the mempool by another tx modifying the 
    ///      group.
    uint256 internal constant ROOT_HISTORY_EXPIRY = 1 hours;

    /// @notice Represents the initial leaf in an empty merkle tree.
    /// @dev Prevents the empty leaf from being inserted into the root history.
    uint256 internal constant EMPTY_LEAF = uint256(0);

    /// @notice The `r` for the finite field `Fr` under which arithmetic is done on the proof input.
    /// @dev Used internally to ensure that the proof input is scaled to within the field `Fr`.
    uint256 internal constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    ///////////////////////////////////////////////////////////////////////////////
    ///                          INTERNAL FUNCTIONALITY                         ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice The verifier instance needed for verifying batch identity insertions.
    MerkleTreeVerifier private merkleTreeVerifier = new MerkleTreeVerifier();

    /// @notice The verifier instance needed for operating within the semaphore protocol.
    SemaphoreVerifier private semaphoreVerifier = new SemaphoreVerifier();

    ///////////////////////////////////////////////////////////////////////////////
    ///                           IDENTITY MANAGEMENT                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Registers identities into the WorldID system. Can only be called by the manager.
    /// @dev Registration is performed off-chain and verified on-chain via the `insertionProof`. 
    ///      This saves gas and time over inserting identities one at a time.
    ///
    /// @param insertionProof The proof that given the conditions (`preRoot`, `startIndex` and 
    ///        `identityCommitments`), insertion into the tree results in `postRoot`.
    /// @param preRoot The value for the root of the tree before the `identityCommitments` have been
    ////       inserted.
    /// @param startIndex The position in the tree at which the insertions were made.
    /// @param identityCommitments The identities that were inserted into the tree to give
    ///
    /// @custom:reverts Unauthorized If the message sender is not authorised to add identities.
    /// @custom:reverts InvalidCommitment If one or more of the provided commitments is invalid.
    /// @custom:reverts NotLatestRoot If the provided `preRoot` is not the latest root.
    /// @custom:reverts ProofValidationFailure If `insertionProof` cannot be verified using the 
    ///                 provided inputs.
    function registerIdentities(
        MerkleTreeProof calldata insertionProof,
        uint256 preRoot,
        uint32 startIndex,
        uint256[] calldata identityCommitments,
        uint256 postRoot
    ) public mustBeCalledByManager {
        // `registerIdentities` can only operate on the latest root and with valid commitments.
        if (preRoot != latestRoot) {
            revert NotLatestRoot(preRoot, latestRoot);
        }
        validateIdentityCommitments(identityCommitments);

        // Having validated the preconditions we can now check the proof itself.
        bytes32 inputHash =
            calculateTreeVerifierInputHash(startIndex, preRoot, postRoot, identityCommitments);

        // No matter what, the inputs can result in a hash that is not an element of the scalar
        // field in which we're operating. We reduce it into the field before handing it to the
        // verifier.
        uint256 reducedElement = reduceInputElementInSnarkScalarField(uint256(inputHash));

        try merkleTreeVerifier.verifyProof(
            [insertionProof.ar.x, insertionProof.ar.y],
            [insertionProof.bs.x, insertionProof.bs.y],
            [insertionProof.krs.x, insertionProof.krs.y],
            [reducedElement]
        ) returns (bool verifierResult) {
            // If the proof did not verify, we revert with a failure.
            if (!verifierResult) {
                revert ProofValidationFailure();
            }

            // If it did verify, we need to update the contract's state.
            latestRoot = postRoot;
            rootHistory[postRoot] = uint128(block.timestamp);
        } catch Error(string memory errString) {
            /// This is not the revert we're looking for.
            revert(errString);
        } catch {
            // If we reach here we know it's the internal error, as the tree verifier only uses
            // `require`s otherwise, which will be re-thrown above.
            revert ProofValidationFailure();
        }
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                             UTILITY FUNCTIONS                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Calculates the input hash for the merkle tree verifier.
    /// @dev Implements the computation described below.
    ///
    /// @param startIndex The index in the tree from which inserting started.
    /// @param preRoot The root value of the tree before these insertions were made.
    /// @param postRoot The root value of the tree after these insertsions were made.
    /// @param identityCommitments The identities that were added to the tree to produce `postRoot`.
    ///
    /// We keccak hash all input to save verification gas. Inputs are arranged as follows:
    /// StartIndex || PreRoot || PostRoot || IdComms[0] || IdComms[1] || ... || IdComms[batchSize-1]
    ///     32	   ||   256   ||   256    ||    256     ||    256     || ... ||     256 bits
    function calculateTreeVerifierInputHash(
        uint32 startIndex,
        uint256 preRoot,
        uint256 postRoot,
        uint256[] calldata identityCommitments
    ) public pure returns (bytes32 hash) {
        bytes memory bytesToHash =
            abi.encodePacked(startIndex, preRoot, postRoot, identityCommitments);

        hash = keccak256(bytesToHash);
    }

    /// @notice Allows a caller to query the root history for information about a given root.
    /// @dev Should be used sparingly as the query can be quite expensive.
    ///
    /// @param root The root for which you are querying information.
    /// @return rootInfo The information about `root`, or `NO_SUCH_ROOT` if `root` does not exist.
    function queryRoot(uint256 root) public view returns (RootInfo memory rootInfo) {
        if (root == latestRoot) {
            return RootInfo(latestRoot, rootHistory[latestRoot], true);
        } else {
            uint128 rootTimestamp = rootHistory[root];

            if (rootTimestamp == 0) {
                return NO_SUCH_ROOT();
            }

            bool isValid = !(block.timestamp - rootTimestamp > ROOT_HISTORY_EXPIRY);
            return RootInfo(root, rootTimestamp, isValid);
        }
    }

    /// @notice Validates an array of identity commitments, reverting if it finds an invalid one.
    ///
    /// @param identityCommitments The array of identity commitments to be validated.
    ///
    /// @custom:reverts Reverts with `InvalidCommitment` if one or more of the provided commitments
    ///                 is invalid.
    function validateIdentityCommitments(uint256[] calldata identityCommitments) private pure {
        for (uint256 i = 0; i < identityCommitments.length; ++i) {
            if (identityCommitments[i] == EMPTY_LEAF) {
                revert InvalidCommitment(identityCommitments[i]);
            }
        }
    }

    /// @notice Reduces the `input` element into the finite field `Fr` using the modulo operation.
    /// @dev `r` in this case is given by `SNARK_SCALAR_FIELD`.
    ///
    /// @param input The number to reduce into `Fr`.
    /// @return elem The value of `input` reduced to be an element of `Fr`.
    function reduceInputElementInSnarkScalarField(uint256 input)
        private
        pure
        returns (uint256 elem)
    {
        return input % SNARK_SCALAR_FIELD;
    }

    /// @notice Checks if a given root value is valid and has been added to the root history.
    /// @dev Reverts with `ExpiredRoot` if the root has expired, and `NonExistentRoot` if the root 
    ///      is not in the root history.
    /// 
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

    ///////////////////////////////////////////////////////////////////////////////
    ///                     DEPLOYED CONTRACT CONFIGURATION                     ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Transfer management access to a different address, or to 0x0 to renounce.
    /// @dev Can only be called by the manager of the contract. Will revert if it is not.
    /// 
    /// @param newManager The address to become the new manager of the contract.
    function transferAccess(address newManager) public mustBeCalledByManager {
        manager = newManager;
    }

    /// @notice Sets the current root if it is not already current.
    ///
    /// @param newRoot The new root to make the current root.
    function setCurrentRoot(uint256 newRoot) public mustBeCalledByManager {
        latestRoot = newRoot;

        uint128 timestamp = rootHistory[newRoot];
        if (timestamp == 0) {
            rootHistory[newRoot] = uint128(block.timestamp);
        }
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                                MODIFIERS                                ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice A modifier that states that the annotated function must only be called by the 
    ///         manager of the contract.
    ///
    /// @custom:reverts Reverts with `Unauthorised` if the caller is not the manager, with the
    ///                 message sender as the payload of the error.
    modifier mustBeCalledByManager() virtual {
        if (msg.sender != manager) {
            revert Unauthorized(msg.sender);
        }
        _;
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                                  ERRORS                                 ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when trying to execute a privileged action without being the contract
    ///         manager.
    error Unauthorized(address user);

    /// @notice Thrown when one or more of the identity commitments to be inserted is invalid.
    error InvalidCommitment(uint256 commitment);

    /// @notice Thrown when the provided proof cannot be verified for the accompanying inputs.
    error ProofValidationFailure();

    /// @notice Thrown when the provided root is not the very latest root.
    error NotLatestRoot(uint256 providedRoot, uint256 latestRoot);

    /// @notice Thrown when attempting to validate a root that has expired.
    error ExpiredRoot();

    /// @notice Thrown when attempting to validate a root that has yet to be added to the root
    ///         history.
    error NonExistentRoot();

    ///////////////////////////////////////////////////////////////////////////////
    ///                    SEMAPHORE PROOF VALIDATION LOGIC                     ///
    ///////////////////////////////////////////////////////////////////////////////

    /// A verifier for the semaphore protocol.
    ///
    /// @notice Reverts if the zero-knowledge proof is invalid.
    /// @dev Note that a double-signaling check is not included here, and should be carried by the 
    ///      caller.
    /// 
    /// @param root The of the Merkle tree
    /// @param signalHash A keccak256 hash of the Semaphore signal
    /// @param nullifierHash The nullifier hash
    /// @param externalNullifierHash A keccak256 hash of the external nullifier
    /// @param proof The zero-knowledge proof
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
}
