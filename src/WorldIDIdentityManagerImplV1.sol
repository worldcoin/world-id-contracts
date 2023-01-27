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
/// @dev This is the implementation delegated to by a proxy.
contract WorldIDIdentityManagerImplV1 is OwnableUpgradeable, UUPSUpgradeable, IWorldID {
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
    //   annotated with the `onlyProxy` modifier. This ensures that it can only be called when it
    //   has access to the data in the proxy, otherwise results are likely to be nonsensical.
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

    /// @notice Whether the initialization has been completed.
    /// @dev This relies on the fact that a default-init `bool` is `false` here.
    bool internal _initialized;

    /// @notice The latest root of the identity merkle tree.
    uint256 internal _latestRoot;

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
    SemaphoreVerifier private semaphoreVerifier;

    /// @notice The interface of the bridge contract from L1 to supported target chains.
    address internal _stateBridgeProxyAddress;

    /// @notice Boolean flag to enable/disable the state bridge.
    bool internal _isStateBridgeEnabled;

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
    ///                                  ERRORS                                 ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when encountering an element that should be reduced as a member of `Fr` but
    ///         is not.
    /// @dev `r` in this case is given by `SNARK_SCALAR_FIELD`.
    ///
    /// @param elementType The kind of element that was encountered unreduced.
    /// @param element The value of that element.
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
    error InvalidCommitment(uint256 index);

    /// @notice Thrown when the provided proof cannot be verified for the accompanying inputs.
    error ProofValidationFailure();

    /// @notice Thrown when the provided root is not the very latest root.
    ///
    /// @param providedRoot The root that was provided as the `preRoot` for a transaction.
    /// @param latestRoot The actual latest root at the time of the transaction.
    error NotLatestRoot(uint256 providedRoot, uint256 latestRoot);

    /// @notice Thrown when attempting to validate a root that has expired.
    error ExpiredRoot();

    /// @notice Thrown when attempting to validate a root that has yet to be added to the root
    ///         history.
    error NonExistentRoot();

    /// @notice Thrown when attempting to call a function while the implementation has not been
    ///         initialized.
    error ImplementationNotInitialized();

    /// @notice Thrown when attempting to send a transaction to the state bridge proxy that fails.
    error StateBridgeProxySendRootMultichainFailure();

    /// @notice Thrown when attempting to enable the bridge when it is already enabled.
    error StateBridgeAlreadyEnabled();

    /// @notice Thrown when attempting to disable the bridge when it is already disabled.
    error StateBridgeAlreadyDisabled();

    /// @notice Thrown when attempting to set the state bridge proxy address to the zero address.
    error InvalidStateBridgeProxyAddress();

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
    ///
    /// @param initialRoot The initial value for the `latestRoot` in the contract. When deploying
    ///        this should be set to the root of the empty tree.
    /// @param _merkleTreeVerifier The initial tree verifier to use.
    /// @param _enableStateBridge Whether or not the state bridge should be enabled when
    ///        initialising the identity manager.
    /// @param initialStateBridgeProxyAddress The initial state bridge proxy address to use.
    ///
    /// @custom:reverts string If called more than once at the same initalisation number.
    function initialize(
        uint256 initialRoot,
        ITreeVerifier _merkleTreeVerifier,
        bool _enableStateBridge,
        address initialStateBridgeProxyAddress
    ) public reinitializer(1) {
        // First, ensure that all of the parent contracts are initialised.
        __delegate_init();

        // Now perform the init logic for this contract.
        _latestRoot = initialRoot;
        merkleTreeVerifier = _merkleTreeVerifier;
        semaphoreVerifier = new SemaphoreVerifier();
        _stateBridgeProxyAddress = initialStateBridgeProxyAddress;
        _isStateBridgeEnabled = _enableStateBridge;

        // Say that the contract is initialized.
        _initialized = true;
    }

    /// @notice Responsible for initialising all of the supertypes of this contract.
    /// @dev Must be called exactly once.
    /// @dev When adding new superclasses, ensure that any initialization that they need to perform
    ///      is accounted for here.
    ///
    /// @custom:reverts string If called more than once.
    function __delegate_init() internal virtual onlyInitializing {
        __Ownable_init();
        __UUPSUpgradeable_init();
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
    ////       inserted. Must be an element of the field `Kr`.
    /// @param startIndex The position in the tree at which the insertions were made.
    /// @param identityCommitments The identities that were inserted into the tree starting at
    ///        `startIndex` and `preRoot` to give `postRoot`. All of the commitments must be
    ///        elements of the field `Kr`.
    /// @param postRoot The root obtained after inserting all of `identityCommitments` into the tree
    ///        described by `preRoot`. Must be an element of the field `Kr`.
    ///
    /// @custom:reverts Unauthorized If the message sender is not authorised to add identities.
    /// @custom:reverts InvalidCommitment If one or more of the provided commitments is invalid.
    /// @custom:reverts NotLatestRoot If the provided `preRoot` is not the latest root.
    /// @custom:reverts ProofValidationFailure If `insertionProof` cannot be verified using the
    ///                 provided inputs.
    /// @custom:reverts UnreducedElement If any of the `preRoot`, `postRoot` and
    ///                 `identityCommitments` is not an element of the field `Kr`. It describes the
    ///                 type and value of the unreduced element.
    function registerIdentities(
        // MerkleTreeProof calldata insertionProof,
        uint256[8] calldata insertionProof,
        uint256 preRoot,
        uint32 startIndex,
        uint256[] calldata identityCommitments,
        uint256 postRoot
    ) public virtual onlyProxy onlyInitialized onlyOwner {
        // We can only operate on the latest root in reduced form.
        if (!isInputInReducedForm(preRoot)) {
            revert UnreducedElement(UnreducedElementType.PreRoot, preRoot);
        }
        if (preRoot != _latestRoot) {
            revert NotLatestRoot(preRoot, _latestRoot);
        }

        // As the `startIndex` is restricted to a uint32, where
        // `type(uint32).max <<< SNARK_SCALAR_FIELD`, we are safe not to check this. As verified in
        // the tests, a revert happens if you pass a value larger than `type(uint32).max` when
        // calling outside the type-checker.

        // We need the post root to be in reduced form.
        if (!isInputInReducedForm(postRoot)) {
            revert UnreducedElement(UnreducedElementType.PostRoot, postRoot);
        }

        // We can only operate on identities that are valid and in reduced form.
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
            _latestRoot = postRoot;

            // We also need to add the previous root to the history, and set the timestamp at which
            // it was expired.
            rootHistory[preRoot] = uint128(block.timestamp);

            // With the update confirmed, we send the root across multiple chains to ensure sync.
            sendRootToStateBridge();
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
    ) public view virtual onlyProxy onlyInitialized returns (bytes32 hash) {
        bytes memory bytesToHash =
            abi.encodePacked(startIndex, preRoot, postRoot, identityCommitments);

        hash = keccak256(bytesToHash);
    }

    /// @notice Allows a caller to query the latest root.
    ///
    /// @return root The value of the latest tree root.
    function latestRoot() public view virtual onlyProxy onlyInitialized returns (uint256 root) {
        return _latestRoot;
    }

    /// @notice Sends the latest root to the state bridge.
    /// @dev Only sends if the state bridge address is not the zero address.
    ///
    function sendRootToStateBridge() internal virtual onlyProxy onlyInitialized {
        if (_isStateBridgeEnabled && _stateBridgeProxyAddress != address(0)) {
            (bool success,) = _stateBridgeProxyAddress.call(
                abi.encodeWithSignature("sendRootMultichain(uint256)", _latestRoot)
            );

            // If the call to the state bridge proxy failed, we revert with a failure.
            if (!success) revert StateBridgeProxySendRootMultichainFailure();
        }
    }

    /// @notice Allows a caller to query the address of the current stateBridgeProxy.
    ///
    /// @return proxy The address of the currently used stateBridgeProxy
    function stateBridgeProxyAddress()
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (address proxy)
    {
        return _stateBridgeProxyAddress;
    }

    /// @notice Allows a caller to upgrade the stateBridgeProxy.
    /// @dev Only the owner of the contract can call this function.
    ///
    /// @param newStateBridgeProxyAddress The address of the new stateBridgeProxy
    function setStateBridgeProxyAddress(address newStateBridgeProxyAddress)
        public
        virtual
        onlyProxy
        onlyInitialized
        onlyOwner
    {
        if (newStateBridgeProxyAddress == address(0)) {
            revert InvalidStateBridgeProxyAddress();
        }

        if (!_isStateBridgeEnabled) {
            enableStateBridge();
        }

        _stateBridgeProxyAddress = newStateBridgeProxyAddress;
    }

    /// @notice Enables the state bridge.
    /// @dev Only the owner of the contract can call this function.
    function enableStateBridge() public virtual onlyProxy onlyInitialized onlyOwner {
        if (!_isStateBridgeEnabled) {
            _isStateBridgeEnabled = true;
        } else {
            revert StateBridgeAlreadyEnabled();
        }
    }

    /// @notice Disables the state bridge.
    /// @dev Only the owner of the contract can call this function.
    function disableStateBridge() public virtual onlyProxy onlyInitialized onlyOwner {
        if (_isStateBridgeEnabled) {
            _isStateBridgeEnabled = false;
        } else {
            revert StateBridgeAlreadyDisabled();
        }
    }

    /// @notice Allows a caller to query the root history for information about a given root.
    /// @dev Should be used sparingly as the query can be quite expensive.
    ///
    /// @param root The root for which you are querying information.
    /// @return rootInfo The information about `root`, or `NO_SUCH_ROOT` if `root` does not exist.
    ///                  Note that if the queried root is the current, the timestamp will be invalid
    ///                  as the root has not been superseded.
    function queryRoot(uint256 root)
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (RootInfo memory rootInfo)
    {
        if (root == _latestRoot) {
            return RootInfo(_latestRoot, 0, true);
        } else {
            uint128 rootTimestamp = rootHistory[root];

            if (rootTimestamp == 0) {
                return NO_SUCH_ROOT();
            }

            bool isValid = !(block.timestamp - rootTimestamp > ROOT_HISTORY_EXPIRY);
            return RootInfo(root, rootTimestamp, isValid);
        }
    }

    /// @notice Validates an array of identity commitments, reverting if it finds one that is
    ///         invalid or has not been reduced.
    /// @dev Identities are not valid if an identity is a non-zero element that occurs after a zero
    ///      element in the array.
    ///
    /// @param identityCommitments The array of identity commitments to be validated.
    ///
    /// @custom:reverts Reverts with `InvalidCommitment` if one or more of the provided commitments
    ///                 is invalid.
    /// @custom:reverts Reverts with `UnreducedElement` if one or more of the provided commitments
    ///                 is not in reduced form.
    function validateIdentityCommitments(uint256[] calldata identityCommitments)
        internal
        view
        virtual
    {
        bool previousIsZero = false;

        for (uint256 i = 0; i < identityCommitments.length; ++i) {
            uint256 commitment = identityCommitments[i];
            if (previousIsZero && commitment != EMPTY_LEAF) {
                revert InvalidCommitment(i);
            }
            if (!isInputInReducedForm(commitment)) {
                revert UnreducedElement(UnreducedElementType.IdentityCommitment, commitment);
            }
            previousIsZero = commitment == EMPTY_LEAF;
        }
    }

    /// @notice Checks if the provided `input` is in reduced form within the field `Fr`.
    /// @dev `r` in this case is given by `SNARK_SCALAR_FIELD`.
    ///
    /// @param input The input to check for being in reduced form.
    /// @return isInReducedForm Returns `true` if `input` is in reduced form, `false` otherwise.
    function isInputInReducedForm(uint256 input)
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (bool isInReducedForm)
    {
        return input < SNARK_SCALAR_FIELD;
    }

    /// @notice Reduces the `input` element into the finite field `Fr` using the modulo operation.
    /// @dev `r` in this case is given by `SNARK_SCALAR_FIELD`.
    ///
    /// @param input The number to reduce into `Fr`.
    /// @return elem The value of `input` reduced to be an element of `Fr`.
    function reduceInputElementInSnarkScalarField(uint256 input)
        internal
        pure
        virtual
        returns (uint256 elem)
    {
        return input % SNARK_SCALAR_FIELD;
    }

    /// @notice Checks if a given root value is valid and has been added to the root history.
    /// @dev Reverts with `ExpiredRoot` if the root has expired, and `NonExistentRoot` if the root
    ///      is not in the root history.
    ///
    /// @param root The root of a given identity group.
    /// @custom:reverts ExpiredRoot If the root is not valid due to being expired.
    /// @custom:reverts NonExistentRoot If the root does not exist.
    function checkValidRoot(uint256 root)
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (bool)
    {
        if (root != _latestRoot) {
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
    ///                             AUTHENTICATION                              ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Is called when upgrading the contract to check whether it should be performed.
    ///
    /// @param newImplementation The address of the implementation being upgraded to.
    ///
    /// @custom:reverts string If the upgrade should not be performed.
    function _authorizeUpgrade(address newImplementation)
        internal
        virtual
        override
        onlyProxy
        onlyOwner
    {
        // No body needed as `onlyOwner` handles it.
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                    SEMAPHORE PROOF VALIDATION LOGIC                     ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice A verifier for the semaphore protocol.
    /// @dev Note that a double-signaling check is not included here, and should be carried by the
    ///      caller.
    ///
    /// @param root The of the Merkle tree
    /// @param signalHash A keccak256 hash of the Semaphore signal
    /// @param nullifierHash The nullifier hash
    /// @param externalNullifierHash A keccak256 hash of the external nullifier
    /// @param proof The zero-knowledge proof
    ///
    /// @custom:reverts string If the zero-knowledge proof cannot be verified for the public inputs.
    function verifyProof(
        uint256 root,
        uint256 signalHash,
        uint256 nullifierHash,
        uint256 externalNullifierHash,
        uint256[8] calldata proof
    ) public view virtual onlyProxy onlyInitialized {
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
    ///                             AUTHENTICATION                              ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Asserts that the annotated function can only be called once the contract has been
    ///         initialized.
    modifier onlyInitialized() {
        if (!_initialized) {
            revert ImplementationNotInitialized();
        }
        _;
    }
}
