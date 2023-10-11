// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {WorldIDImpl} from "./abstract/WorldIDImpl.sol";

import {IWorldID} from "./interfaces/IWorldID.sol";
import {ITreeVerifier} from "./interfaces/ITreeVerifier.sol";
import {ISemaphoreVerifier} from "src/interfaces/ISemaphoreVerifier.sol";
import {IBridge} from "./interfaces/IBridge.sol";

import {SemaphoreTreeDepthValidator} from "./utils/SemaphoreTreeDepthValidator.sol";
import {VerifierLookupTable} from "./data/VerifierLookupTable.sol";

/// @title WorldID Identity Manager Implementation Version 1
/// @author Worldcoin
/// @notice An implementation of a batch-based identity manager for the WorldID protocol.
/// @dev The manager is based on the principle of verifying externally-created Zero Knowledge Proofs
///      to perform the insertions.
/// @dev This is the implementation delegated to by a proxy.
contract WorldIDIdentityManagerImplV1 is WorldIDImpl, IWorldID {
    ///////////////////////////////////////////////////////////////////////////////
    ///                   A NOTE ON IMPLEMENTATION CONTRACTS                    ///
    ///////////////////////////////////////////////////////////////////////////////

    // This contract is designed explicitly to operate from behind a proxy contract. As a result,
    // there are a few important implementation considerations:
    //
    // - All updates made after deploying a given version of the implementation should inherit from
    //   the latest version of the implementation. This prevents storage clashes.
    // - All functions that are less access-restricted than `private` should be marked `virtual` in
    //   order to enable the fixing of bugs in the existing interface.
    // - Any function that reads from or modifies state (i.e. is not marked `pure`) must be
    //   annotated with the `onlyProxy` and `onlyInitialized` modifiers. This ensures that it can
    //   only be called when it has access to the data in the proxy, otherwise results are likely to
    //   be nonsensical.
    // - This contract deals with important data for the WorldID system. Ensure that all newly-added
    //   functionality is carefully access controlled using `onlyOwner`, or a more granular access
    //   mechanism.
    // - Do not assign any contract-level variables at the definition site unless they are
    //   `constant`.
    //
    // Additionally, the following notes apply:
    //
    // - Initialisation and ownership management are not protected behind `onlyProxy` intentionally.
    //   This ensures that the contract can safely be disposed of after it is no longer used.
    // - Carefully consider what data recovery options are presented as new functionality is added.
    //   Care must be taken to ensure that a migration plan can exist for cases where upgrades
    //   cannot recover from an issue or vulnerability.

    ///////////////////////////////////////////////////////////////////////////////
    ///                    !!!!! DATA: DO NOT REORDER !!!!!                     ///
    ///////////////////////////////////////////////////////////////////////////////

    // To ensure compatibility between upgrades, it is exceedingly important that no reordering of
    // these variables takes place. If reordering happens, a storage clash will occur (effectively a
    // memory safety error).

    /// @notice The address of the contract authorized to perform identity management operations.
    /// @dev The identity operator defaults to being the same as the owner.
    address internal _identityOperator;

    /// @notice The latest root of the identity merkle tree.
    uint256 internal _latestRoot;

    /// @notice A mapping from the value of the merkle tree root to the timestamp at which the root
    ///         was superseded by a newer one.
    mapping(uint256 => uint128) internal rootHistory;

    /// @notice The amount of time an outdated root is considered as valid.
    /// @dev This prevents proofs getting invalidated in the mempool by another tx modifying the
    ///      group.
    uint256 internal rootHistoryExpiry;

    /// @notice The `r` for the finite field `Fr` under which arithmetic is done on the proof input.
    /// @dev Used internally to ensure that the proof input is scaled to within the field `Fr`.
    uint256 internal constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant SNARK_SCALAR_FIELD_MIN_ONE =
        21888242871839275222246405745257275088548364400416034343698204186575808495616;

    /// @notice The table of verifiers for verifying batch identity insertions.
    VerifierLookupTable internal batchInsertionVerifiers;

    /// @notice The table of verifiers for verifying identity updates.
    /// @dev preserved for storage reasons, no longer used
    VerifierLookupTable internal identityUpdateVerifiers;

    /// @notice The verifier instance needed for operating within the semaphore protocol.
    ISemaphoreVerifier internal semaphoreVerifier;

    /// @notice The interface of the bridge contract from L1 to supported target chains.
    /// @dev preserved for storage reasons, no longer used
    IBridge internal _stateBridge;

    /// @notice Boolean flag to enable/disable the state bridge.
    bool internal _isStateBridgeEnabled;

    /// @notice The depth of the Semaphore merkle tree.
    uint8 internal treeDepth;

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
    /// @dev preserved for ABI backwards compatibility with V1, no longer used
    /// all elements come out reduced from the circuit
    enum UnreducedElementType {
        PreRoot,
        IdentityCommitment,
        PostRoot
    }

    /// @notice Represents the kind of change that is made to the root of the tree.
    enum TreeChange {
        Insertion,
        Deletion
    }

    /// @notice Represents the kinds of dependencies that can be updated.
    enum Dependency {
        StateBridge,
        InsertionVerifierLookupTable,
        DeletionVerifierLookupTable,
        SemaphoreVerifier
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
    ///                                  ERRORS                                 ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when encountering an element that should be reduced as a member of `Fr` but
    ///         is not.
    /// @dev `r` in this case is given by `SNARK_SCALAR_FIELD`.
    ///
    /// @param elementType The kind of element that was encountered unreduced.
    /// @param element The value of that element.
    /// @dev preserved for ABI backwards compatibility with V1, no longer used,
    /// all elements come out reduced from the circuit
    error UnreducedElement(UnreducedElementType elementType, uint256 element);

    /// @notice Thrown when trying to execute a privileged action without being the contract
    ///         manager.
    ///
    /// @param user The user that attempted the action that they were not authorised for.
    error Unauthorized(address user);

    /// @notice Thrown when one or more of the identity commitments to be inserted is invalid.
    ///
    /// @param index The index in the array of identity commitments where the invalid commitment was
    ///        found.
    /// @dev This error is no longer in use as we now verify the commitments off-chain within the circuit
    /// no need to check for reduced elements or invalid commitments.
    /// @dev preserved for ABI backwards compatibility with V1, no longer used,
    /// all elements are validated by the circuit
    error InvalidCommitment(uint256 index);

    /// @notice Thrown when the provided proof cannot be verified for the accompanying inputs.
    error ProofValidationFailure();

    /// @notice Thrown when the provided root is not the very latest root.
    ///
    /// @param providedRoot The root that was provided as the `preRoot` for a transaction.
    /// @param latestRoot The actual latest root at the time of the transaction.
    error NotLatestRoot(uint256 providedRoot, uint256 latestRoot);

    /// @notice Thrown when attempting to enable the bridge when it is already enabled.
    /// @dev preserved for ABI backwards compatibility with V1, no longer used
    error StateBridgeAlreadyEnabled();

    /// @notice Thrown when attempting to disable the bridge when it is already disabled.
    /// @dev preserved for ABI backwards compatibility with V1, no longer used
    error StateBridgeAlreadyDisabled();

    /// @notice Thrown when attempting to set the state bridge address to the zero address.
    /// @dev preserved for ABI backwards compatibility with V1, no longer used
    error InvalidStateBridgeAddress();

    /// @notice Thrown when Semaphore tree depth is not supported.
    ///
    /// @param depth Passed tree depth.
    error UnsupportedTreeDepth(uint8 depth);

    /// @notice Thrown when the inputs to `removeIdentities` do not match in
    ///         length.
    /// @dev preserved for ABI backwards compatibility with V1, no longer used
    error MismatchedInputLengths();

    /// @notice Thrown when a verifier is initialized to be the zero address
    error InvalidVerifier();

    /// @notice Thrown when a verifier lookup table is initialized to be the zero address
    error InvalidVerifierLUT();

    ///////////////////////////////////////////////////////////////////////////////
    ///                                  EVENTS                                 ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Emitted when the current root of the tree is updated.
    ///
    /// @param preRoot The value of the tree's root before the update.
    /// @param kind Either "insertion" or "update", the kind of alteration that was made to the
    ///        tree.
    /// @param postRoot The value of the tree's root after the update.
    event TreeChanged(uint256 indexed preRoot, TreeChange indexed kind, uint256 indexed postRoot);

    /// @notice Emitted when a dependency's address is updated via an admin action.
    ///
    /// @param kind The kind of dependency that was updated.
    /// @param oldAddress The old address of that dependency.
    /// @param newAddress The new address of that dependency.
    event DependencyUpdated(
        Dependency indexed kind, address indexed oldAddress, address indexed newAddress
    );

    /// @notice Emitted when the state bridge is enabled or disabled.
    ///
    /// @param isEnabled Set to `true` if the event comes from the state bridge being enabled,
    ///        `false` otherwise.
    /// @dev preserved for ABI backwards compatibility with V1, no longer used
    event StateBridgeStateChange(bool indexed isEnabled);

    /// @notice Emitted when the root history expiry time is changed.
    ///
    /// @param oldExpiryTime The expiry time prior to the change.
    /// @param newExpiryTime The expiry time after the change.
    event RootHistoryExpirySet(uint256 indexed oldExpiryTime, uint256 indexed newExpiryTime);

    /// @notice Emitted when the identity operator is changed.
    ///
    /// @param oldOperator The address of the old identity operator.
    /// @param newOperator The address of the new identity operator.
    event IdentityOperatorChanged(address indexed oldOperator, address indexed newOperator);

    /// @notice Emitter when the WorldIDIdentityManagerImpl is initialized.

    /// @param _treeDepth The depth of the MerkeTree
    /// @param initialRoot The initial value for the `latestRoot` in the contract. When deploying
    ///        this should be set to the root of the empty tree.
    event WorldIDIdentityManagerImplInitialized(uint8 _treeDepth, uint256 initialRoot);

    ///////////////////////////////////////////////////////////////////////////////
    ///                             INITIALIZATION                              ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Constructs the contract.
    constructor() {
        // When called in the constructor, this is called in the context of the implementation and
        // not the proxy. Calling this thereby ensures that the contract cannot be spuriously
        // initialized on its own.
        _disableInitializers();
    }

    /// @notice Initializes the contract.
    /// @dev Must be called exactly once.
    /// @dev This is marked `reinitializer()` to allow for updated initialisation steps when working
    ///      with upgrades based upon this contract. Be aware that there are only 256 (zero-indexed)
    ///      initialisations allowed, so decide carefully when to use them. Many cases can safely be
    ///      replaced by use of setters.
    /// @dev This function is explicitly not virtual as it does not make sense to override even when
    ///      upgrading. Create a separate initializer function instead.
    ///
    /// @param _treeDepth The depth of the MerkeTree
    /// @param initialRoot The initial value for the `latestRoot` in the contract. When deploying
    ///        this should be set to the root of the empty tree.
    /// @param _batchInsertionVerifiers The verifier lookup table for batch insertions.
    /// @param _batchUpdateVerifiers The verifier lookup table for batch updates.
    /// @param _semaphoreVerifier The verifier to use for semaphore protocol proofs.
    ///
    /// @custom:reverts string If called more than once at the same initialisation number.
    /// @custom:reverts UnsupportedTreeDepth If passed tree depth is not among defined values.
    /// @custom:reverts InvalidVerifierLUT if `_batchInsertionVerifiers` or `_batchUpdateVerifiers` is set to the zero address
    /// @custom:reverts InvalidVerifier if `_semaphoreVerifier` is set to the zero address
    function initialize(
        uint8 _treeDepth,
        uint256 initialRoot,
        VerifierLookupTable _batchInsertionVerifiers,
        VerifierLookupTable _batchUpdateVerifiers,
        ISemaphoreVerifier _semaphoreVerifier
    ) public reinitializer(1) {
        if (address(_batchInsertionVerifiers) == address(0)) {
            revert InvalidVerifierLUT();
        }

        if (address(_batchUpdateVerifiers) == address(0)) {
            revert InvalidVerifierLUT();
        }

        if (address(_semaphoreVerifier) == address(0)) {
            revert InvalidVerifier();
        }
        // First, ensure that all of the parent contracts are initialised.
        __delegateInit();

        if (!SemaphoreTreeDepthValidator.validate(_treeDepth)) {
            revert UnsupportedTreeDepth(_treeDepth);
        }

        // Now perform the init logic for this contract.
        treeDepth = _treeDepth;
        rootHistoryExpiry = 1 hours;
        _latestRoot = initialRoot;
        batchInsertionVerifiers = _batchInsertionVerifiers;
        identityUpdateVerifiers = _batchUpdateVerifiers;
        semaphoreVerifier = _semaphoreVerifier;
        _identityOperator = owner();

        // Say that the contract is initialized.
        __setInitialized();

        emit WorldIDIdentityManagerImplInitialized(_treeDepth, initialRoot);
    }

    /// @notice Responsible for initialising all of the supertypes of this contract.
    /// @dev Must be called exactly once.
    /// @dev When adding new superclasses, ensure that any initialization that they need to perform
    ///      is accounted for here.
    ///
    /// @custom:reverts string If called more than once.
    function __delegateInit() internal virtual onlyInitializing {
        __WorldIDImpl_init();
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                           IDENTITY MANAGEMENT                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Registers identities into the WorldID system.
    /// @dev Can only be called by the identity operator.
    /// @dev Registration is performed off-chain and verified on-chain via the `insertionProof`.
    ///      This saves gas and time over inserting identities one at a time.
    ///
    /// @param insertionProof The proof that given the conditions (`preRoot`, `startIndex` and
    ///        `identityCommitments`), insertion into the tree results in `postRoot`. Elements 0 and
    ///        1 are the `x` and `y` coordinates for `ar` respectively. Elements 2 and 3 are the `x`
    ///        coordinate for `bs`, and elements 4 and 5 are the `y` coordinate for `bs`. Elements 6
    ///        and 7 are the `x` and `y` coordinates for `krs`.
    /// @param preRoot The value for the root of the tree before the `identityCommitments` have been
    ////       inserted. Must be an element of the field `Kr`. (already in reduced form)
    /// @param startIndex The position in the tree at which the insertions were made.
    /// @param identityCommitments The identities that were inserted into the tree starting at
    ///        `startIndex` and `preRoot` to give `postRoot`. All of the commitments must be
    ///        elements of the field `Kr`.
    /// @param postRoot The root obtained after inserting all of `identityCommitments` into the tree
    ///        described by `preRoot`. Must be an element of the field `Kr`. (alread in reduced form)
    ///
    /// @custom:reverts Unauthorized If the message sender is not authorised to add identities.
    /// @custom:reverts NotLatestRoot If the provided `preRoot` is not the latest root.
    /// @custom:reverts ProofValidationFailure If `insertionProof` cannot be verified using the
    ///                 provided inputs.
    /// @custom:reverts VerifierLookupTable.NoSuchVerifier If the batch sizes doesn't match a known
    ///                 verifier.
    function registerIdentities(
        uint256[8] calldata insertionProof,
        uint256 preRoot,
        uint32 startIndex,
        uint256[] calldata identityCommitments,
        uint256 postRoot
    ) public virtual onlyProxy onlyInitialized onlyIdentityOperator {
        if (preRoot != _latestRoot) {
            revert NotLatestRoot(preRoot, _latestRoot);
        }
        // Having validated the preconditions we can now check the proof itself.
        bytes32 inputHash = calculateIdentityRegistrationInputHash(
            startIndex, preRoot, postRoot, identityCommitments
        );

        // No matter what, the inputs can result in a hash that is not an element of the scalar
        // field in which we're operating. We reduce it into the field before handing it to the
        // verifier. All other elements that are passed as calldata are reduced in the circuit.
        uint256 reducedElement = uint256(inputHash) % SNARK_SCALAR_FIELD;

        // We need to look up the correct verifier before we can verify.
        ITreeVerifier insertionVerifier =
            batchInsertionVerifiers.getVerifierFor(identityCommitments.length);

        // With that, we can properly try and verify.
        try insertionVerifier.verifyProof(insertionProof, [reducedElement]) {
            // If it did verify, we need to update the contract's state. We set the currently valid
            // root to the root after the insertions.
            _latestRoot = postRoot;

            // We also need to add the previous root to the history, and set the timestamp at
            // which it was expired.
            rootHistory[preRoot] = uint128(block.timestamp);

            emit TreeChanged(preRoot, TreeChange.Insertion, postRoot);
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

    /// @notice Calculates the input hash for the identity registration verifier.
    /// @dev Implements the computation described below.
    ///
    /// @param startIndex The index in the tree from which inserting started.
    /// @param preRoot The root value of the tree before these insertions were made.
    /// @param postRoot The root value of the tree after these insertions were made.
    /// @param identityCommitments The identities that were added to the tree to produce `postRoot`.
    ///
    /// @return hash The input hash calculated as described below.
    ///
    /// We keccak hash all input to save verification gas. Inputs are arranged as follows:
    ///
    /// StartIndex || PreRoot || PostRoot || IdComms[0] || IdComms[1] || ... || IdComms[batchSize-1]
    ///     32	   ||   256   ||   256    ||    256     ||    256     || ... ||     256 bits
    function calculateIdentityRegistrationInputHash(
        uint32 startIndex,
        uint256 preRoot,
        uint256 postRoot,
        uint256[] calldata identityCommitments
    ) public view virtual onlyProxy onlyInitialized returns (bytes32 hash) {
        bytes memory bytesToHash =
            abi.encodePacked(startIndex, preRoot, postRoot, identityCommitments);

        hash = keccak256(bytesToHash);
    }

    /// @notice Allows a caller to query the latest root.
    ///
    /// @return root The value of the latest tree root.
    function latestRoot() public view virtual onlyProxy onlyInitialized returns (uint256) {
        return _latestRoot;
    }

    /// @notice Allows a caller to query the root history for information about a given root.
    /// @dev Should be used sparingly as the query can be quite expensive.
    ///
    /// @param root The root for which you are querying information.
    /// @return rootInfo The information about `root`, or `NO_SUCH_ROOT` if `root` does not exist.
    ///         Note that if the queried root is the current, the timestamp will be invalid as the
    ///         root has not been superseded.
    function queryRoot(uint256 root)
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (RootInfo memory)
    {
        if (root == _latestRoot) {
            return RootInfo(_latestRoot, 0, true);
        } else {
            uint128 rootTimestamp = rootHistory[root];

            if (rootTimestamp == 0) {
                return NO_SUCH_ROOT();
            }

            bool isValid = !(block.timestamp - rootTimestamp > rootHistoryExpiry);
            return RootInfo(root, rootTimestamp, isValid);
        }
    }

    /// @notice Reverts if the provided root value is not valid.
    /// @dev A root is valid if it is either the latest root, or not the latest root but has not
    ///      expired.
    ///
    /// @param root The root of the merkle tree to check for validity.
    ///
    /// @custom:reverts ExpiredRoot If the provided `root` has expired.
    /// @custom:reverts NonExistentRoot If the provided `root` does not exist in the history.
    function requireValidRoot(uint256 root) public view virtual onlyProxy onlyInitialized {
        // The latest root is always valid.
        if (root == _latestRoot) {
            return;
        }

        // Otherwise, we need to check things via the timestamp.
        uint128 rootTimestamp = rootHistory[root];

        // A root does not exist if it has no associated timestamp.
        if (rootTimestamp == 0) {
            revert NonExistentRoot();
        }

        // A root is no longer valid if it has expired.
        if (block.timestamp - rootTimestamp > rootHistoryExpiry) {
            revert ExpiredRoot();
        }
    }

    /// @notice Gets the address for the lookup table of merkle tree verifiers used for identity
    ///         registrations.
    ///
    /// @return addr The address of the contract being used as the verifier lookup table.
    function getRegisterIdentitiesVerifierLookupTableAddress()
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (address)
    {
        return address(batchInsertionVerifiers);
    }

    /// @notice Sets the address for the lookup table of merkle tree verifiers used for identity
    ///         registrations.
    /// @dev Only the owner of the contract can call this function.
    ///
    /// @param newTable The new verifier lookup table to be used for verifying identity
    ///        registrations.
    /// @custom:reverts InvalidVerifierLUT if `newTable` is set to the zero address
    function setRegisterIdentitiesVerifierLookupTable(VerifierLookupTable newTable)
        public
        virtual
        onlyProxy
        onlyInitialized
        onlyOwner
    {
        if (address(newTable) == address(0)) {
            revert InvalidVerifierLUT();
        }

        VerifierLookupTable oldTable = batchInsertionVerifiers;
        batchInsertionVerifiers = newTable;
        emit DependencyUpdated(
            Dependency.InsertionVerifierLookupTable, address(oldTable), address(newTable)
        );
    }

    /// @notice Gets the address of the verifier used for verification of semaphore proofs.
    ///
    /// @return addr The address of the contract being used as the verifier.
    function getSemaphoreVerifierAddress()
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (address)
    {
        return address(semaphoreVerifier);
    }

    /// @notice Sets the address for the semaphore verifier to be used for verification of
    ///         semaphore proofs.
    /// @dev Only the owner of the contract can call this function.
    ///
    /// @param newVerifier The new verifier instance to be used for verifying semaphore proofs.
    /// @custom:reverts InvalidVerifier if `newVerifier` is set to the zero address
    function setSemaphoreVerifier(ISemaphoreVerifier newVerifier)
        public
        virtual
        onlyProxy
        onlyInitialized
        onlyOwner
    {
        if (address(newVerifier) == address(0)) {
            revert InvalidVerifier();
        }

        ISemaphoreVerifier oldVerifier = semaphoreVerifier;
        semaphoreVerifier = newVerifier;
        emit DependencyUpdated(
            Dependency.SemaphoreVerifier, address(oldVerifier), address(newVerifier)
        );
    }

    /// @notice Gets the current amount of time used to expire roots in the history.
    ///
    /// @return expiryTime The amount of time it takes for a root to expire.
    function getRootHistoryExpiry()
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (uint256)
    {
        return rootHistoryExpiry;
    }

    /// @notice Sets the time to wait before expiring a root from the root history.
    /// @dev Only the owner of the contract can call this function.
    ///
    /// @param newExpiryTime The new time to use to expire roots.
    function setRootHistoryExpiry(uint256 newExpiryTime)
        public
        virtual
        onlyProxy
        onlyInitialized
        onlyOwner
    {
        if (newExpiryTime == 0) {
            revert("Expiry time cannot be zero.");
        }
        uint256 oldExpiry = rootHistoryExpiry;
        rootHistoryExpiry = newExpiryTime;

        emit RootHistoryExpirySet(oldExpiry, newExpiryTime);
    }

    /// @notice Gets the Semaphore tree depth the contract was initialized with.
    ///
    /// @return initializedTreeDepth Tree depth.
    function getTreeDepth() public view virtual onlyProxy onlyInitialized returns (uint8) {
        return treeDepth;
    }

    /// @notice Gets the address that is authorised to perform identity operations on this identity
    ///         manager instance.
    ///
    /// @return _ The address authorized to perform identity operations.
    function identityOperator() public view virtual onlyProxy onlyInitialized returns (address) {
        return _identityOperator;
    }

    /// @notice Sets the address that is authorised to perform identity operations on this identity
    ///         manager instance.
    ///
    /// @param newIdentityOperator The address of the new identity operator.
    ///
    /// @return _ The address of the old identity operator.
    function setIdentityOperator(address newIdentityOperator)
        public
        virtual
        onlyProxy
        onlyInitialized
        onlyOwner
        returns (address)
    {
        address oldOperator = _identityOperator;
        _identityOperator = newIdentityOperator;
        emit IdentityOperatorChanged(oldOperator, newIdentityOperator);
        return oldOperator;
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                    SEMAPHORE PROOF VALIDATION LOGIC                     ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice A verifier for the semaphore protocol.
    /// @dev Note that a double-signaling check is not included here, and should be carried by the
    ///      caller.
    ///
    /// @param proof The zero-knowledge proof
    /// @param root The of the Merkle tree
    /// @param signalHash A keccak256 hash of the Semaphore signal
    /// @param nullifierHash The nullifier hash
    /// @param externalNullifierHash A keccak256 hash of the external nullifier
    ///
    /// @custom:reverts string If the zero-knowledge proof cannot be verified for the public inputs.
    function verifyProof(
        uint256 root,
        uint256 signalHash,
        uint256 nullifierHash,
        uint256 externalNullifierHash,
        uint256[8] calldata proof
    ) public view virtual onlyProxy onlyInitialized {
        // Check the preconditions on the inputs.
        requireValidRoot(root);

        // With that done we can now verify the proof.
        semaphoreVerifier.verifyProof(
            proof, [root, nullifierHash, signalHash, externalNullifierHash]
        );
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                    SEMAPHORE PROOF VALIDATION LOGIC                     ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures that the guarded operation can only be performed by the authorized identity
    ///         operator contract.
    ///
    /// @custom:reverts Unauthorized If the caller is not the identity operator.
    modifier onlyIdentityOperator() {
        if (msg.sender != _identityOperator) {
            revert Unauthorized(msg.sender);
        }

        _;
    }
}
