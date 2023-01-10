// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {ITreeVerifier} from "./interfaces/ITreeVerifier.sol";
import {IWorldID} from "./interfaces/IWorldID.sol";
import {Verifier as SemaphoreVerifier} from "semaphore/base/Verifier.sol";

import {OwnableUpgradeable} from "contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title WorldID Identity Manager Implementation Version 1
/// @author Worldcoin
/// @notice An implementation of a batch-based identity manager for the WorldID protocol.
/// @dev The manager is based on the principle of verifying externally-created Zero Knowledge Proofs
///      to perform the insertions.
/// @dev This is the implementation delegated to by a proxy. All updates to the implementation
///      should inherit from the latest version of the implementation. To this end, all functions
///      here should be marked virtual to enable updating logic.
contract WorldIDIdentityManagerImplV1 is OwnableUpgradeable, UUPSUpgradeable, IWorldID {
    ///////////////////////////////////////////////////////////////////////////////
    ///                    !!!!! DATA: DO NOT REORDER !!!!!                     ///
    ///////////////////////////////////////////////////////////////////////////////

    // To ensure compatibility between upgrades, it is exceedingly important that no reordering of
    // these variables takes place. If reordering happens, a storage clash will occur (effectively a
    // memory safety error).

    /// @notice The latest root of the identity merkle tree.
    uint256 public latestRoot;

    /// @notice A mapping from the value of the merkle tree root to the timestamp at which the root
    ///         was superseded by a newer one.
    mapping(uint256 => uint128) internal rootHistory;

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

    /// @notice The verifier instance needed for verifying batch identity insertions.
    ITreeVerifier private merkleTreeVerifier;

    /// @notice The verifier instance needed for operating within the semaphore protocol.
    SemaphoreVerifier private semaphoreVerifier = new SemaphoreVerifier();

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

    /// @notice Represents the kind of element that has not been provided in reduced form.
    enum UnreducedElementType {
        PreRoot,
        IdentityCommitment,
        PostRoot
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                             CONSTANT FUNCTIONS                          ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice A constant representing a root that doesn't exist.
    /// @dev Can be checked against when querying for root data.
    function NO_SUCH_ROOT() public pure returns (RootInfo memory rootInfo) {
        return RootInfo(0x0, 0x0, false);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                             INITIALIZATION                              ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Initializes the contract.
    /// @dev Must be called exactly once.
    ///
    /// @param initialRoot The initial value for the `latestRoot` in the contract. When deploying
    ///        this should be set to the root of the empty tree.
    /// @param merkleTreeVerifier_ The initial tree verifier to use.
    ///
    /// @custom:reverts string If called more than once.
    function initialize(uint256 initialRoot, ITreeVerifier merkleTreeVerifier_)
        public
        virtual
        initializer
    {
        // First, ensure that all of the children are initialised.
        __delegate_init();

        // Now perform the implementation's init logic.
        latestRoot = initialRoot;
        merkleTreeVerifier = merkleTreeVerifier_;
    }

    /// @notice Responsible for initialising all of the supertypes of this contract.
    /// @dev Must be called exactly once.
    /// @dev When adding new superclasses, ensure that any initialization that they need to perform
    ///      is accounted for here.
    ///
    /// @custom:reverts string If called more than once.
    function __delegate_init() internal virtual {
        __Ownable_init();
        __UUPSUpgradeable_init();
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                             AUTHENTICATION                              ///
    ///////////////////////////////////////////////////////////////////////////////

    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {
        // No body needed as `onlyOwner` handles it.
    }

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
    ) public view virtual {
        // TODO [Ara] Bring the impl back
    }
}
