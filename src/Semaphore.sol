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

    /// @notice Provides information about a merkle tree root.
    ///
    /// @param root The value of the merkle tree root.
    /// @param supersededTimestamp The timestamp at which the root was inserted into the history.
    ///        This may be 0 if the requested root is the current root (which has not yet been
    ///        inserted into the history).
    /// @param isValid Whether or not the root is valid (has not expired).
    struct RootInfo {
        uint256 root;
        uint128 supersededTimestamp;
        bool isValid;
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                       PRIVATE CONFIGURATION STORAGE                      ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice A mapping from the value of the merkle tree root to the timestamp at which the root
    ///         was superseded by a newer one.
    mapping(uint256 => uint128) internal rootHistory;

    ///////////////////////////////////////////////////////////////////////////////
    ///                             INTERNAL CONSTANTS                          ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice The amount of time an outdated root is considered as valid.
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
    ///                              CONSTRUCTION                               ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Creates a new instance of the contract.
    ///
    /// @param initialRoot The initial value for the `latestRoot` in the contract. When deploying
    ///        this should be set to the root of an empty tree.
    constructor(uint256 initialRoot) {
        latestRoot = initialRoot;
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                           IDENTITY MANAGEMENT                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Registers identities into the WorldID system. Can only be called by the manager.
    /// @dev Registration is performed off-chain and verified on-chain via the `insertionProof`.
    ///      This saves gas and time over inserting identities one at a time.
    ///
    /// @param insertionProof The proof that given the conditions (`preRoot`, `startIndex` and
    ///        `identityCommitments`), insertion into the tree results in `postRoot`. Elements 0 and
    ///        1 are the `x` and `y` coordinates for `ar` respectively. Elements 2 and 3 are the `x`
    ///        coordinate for `bs`, and elements 4 and 5 are the `y` coordinate for `bs`. Elements 6
    ///        and 7 are the `x` and `y` coordinates for `krs`.
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
        // MerkleTreeProof calldata insertionProof,
        uint256[8] calldata insertionProof,
        uint256 preRoot,
        uint32 startIndex,
        uint256[] calldata identityCommitments,
        uint256 postRoot
    ) public onlyManager {
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
            [insertionProof[0], insertionProof[1]],
            [[insertionProof[2], insertionProof[3]], [insertionProof[4], insertionProof[5]]],
            [insertionProof[6], insertionProof[7]],
            [reducedElement]
        ) returns (bool verifierResult) {
            // If the proof did not verify, we revert with a failure.
            if (!verifierResult) {
                revert ProofValidationFailure();
            }

            // If it did verify, we need to update the contract's state. We set the currently valid
            // root to the root after the insertions.
            latestRoot = postRoot;

            // We also need to add the previous root to the history, and set the timestamp at which
            // it was expired.
            rootHistory[preRoot] = uint128(block.timestamp);
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
    ///                  Note that if the queried root is the current, the timestamp will be invalid
    ///                  as the root has not been superseded.
    function queryRoot(uint256 root) public view returns (RootInfo memory rootInfo) {
        if (root == latestRoot) {
            return RootInfo(latestRoot, 0, true);
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

    /// @notice Checks if the provided `input` is in reduced form within the field `Fr`.
    /// @dev `r` in this case is given by `SNARK_SCALAR_FIELD`.
    /// 
    /// @param input The input to check for being in reduced form.
    /// @return isInReducedForm Returns `true` if `input` is in reduced form, `false` otherwise.
    function isInputInReducedForm(uint256 input) public pure returns (bool isInReducedForm) {
        return input < SNARK_SCALAR_FIELD;
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
    function transferAccess(address newManager) public onlyManager {
        manager = newManager;
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                                MODIFIERS                                ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice A modifier that states that the annotated function must only be called by the
    ///         manager of the contract.
    ///
    /// @custom:reverts Reverts with `Unauthorised` if the caller is not the manager, with the
    ///                 message sender as the payload of the error.
    modifier onlyManager() virtual {
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
