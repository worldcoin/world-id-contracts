pragma solidity ^0.8.21;

import "./WorldIDIdentityManagerImplV1.sol";

/// @title WorldID Identity Manager Implementation Version 2
/// @author Worldcoin
/// @notice An implementation of a batch-based identity manager for the WorldID protocol.
/// @dev The manager is based on the principle of verifying externally-created Zero Knowledge Proofs
///      to perform the deletions.
/// @dev This is the implementation delegated to by a proxy.
contract WorldIDIdentityManagerImplV2 is WorldIDIdentityManagerImplV1 {
    ///////////////////////////////////////////////////////////////////////////////
    ///                   A NOTE ON IMPLEMENTATION CONTRACTS                    ///
    ///////////////////////////////////////////////////////////////////////////////

    // This contract is designed explicitly to operate from behind a proxy contract. As a result,
    // there are a few important implementation considerations:
    //
    // - All updates made after deploying a given version of the implementation should inherit from
    //   the latest version of the implementation. This contract inherits from its previous implementation
    //   WorldIDIdentityManagerImplV1. This prevents storage clashes.
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

    /// @notice The table of verifiers for verifying batch identity deletions.
    VerifierLookupTable internal batchDeletionVerifiers;

    /// @notice Thrown when the WorldIDIdentityManagerImplV2 contract is initalized
    event WorldIDIdentityManagerImplV2Initialized();

    /// @notice Thrown when the bytes calldata packedDeletionIndices array
    /// is not a multiple of 4 (to make up 32 bit indices)
    error InvalidDeletionIndices();

    /// @notice Initializes the V2 implementation contract.
    /// @param _batchDeletionVerifiers The table of verifiers for verifying batch identity deletions.
    /// @dev Must be called exactly once
    /// @dev This is marked `reinitializer()` to allow for updated initialisation steps when working
    ///      with upgrades based upon this contract. Be aware that there are only 256 (zero-indexed)
    ///      initialisations allowed, so decide carefully when to use them. Many cases can safely be
    ///      replaced by use of setters.
    /// @dev This function is explicitly not virtual as it does not make sense to override even when
    ///      upgrading. Create a separate initializer function instead.
    ///
    ///
    /// @custom:reverts InvalidVerifierLUT if `_batchDeletionVerifiers` is set to the zero address
    function initializeV2(VerifierLookupTable _batchDeletionVerifiers) public reinitializer(2) {
        if (address(_batchDeletionVerifiers) == address(0)) {
            revert InvalidVerifierLUT();
        }

        batchDeletionVerifiers = _batchDeletionVerifiers;

        emit WorldIDIdentityManagerImplV2Initialized();
    }

    ///////////////////////////////////////////////////////////////////
    ///                     IDENTITY MANAGEMENT                     ///
    ///////////////////////////////////////////////////////////////////

    /// @notice Deletes identities from the WorldID system.
    /// @dev Can only be called by the identity operator.
    /// @dev Deletion is performed off-chain and verified on-chain via the `deletionProof`.
    ///      This saves gas and time over deleting identities one at a time.
    ///
    /// @param deletionProof The proof that given the conditions (`preRoot` and `packedDeletionIndices`),
    ///        deletion into the tree results in `postRoot`. Elements 0 and 1 are the `x` and `y`
    ///        coordinates for `ar` respectively. Elements 2 and 3 are the `x` coordinate for `bs`,
    ///         and elements 4 and 5 are the `y` coordinate for `bs`. Elements 6 and 7 are the `x`
    ///         and `y` coordinates for `krs`.
    /// @param packedDeletionIndices The indices of the identities that were deleted from the tree. The batch size is inferred from the length of this
    //// array: batchSize = packedDeletionIndices / 4
    /// @param preRoot The value for the root of the tree before the corresponding identity commitments have
    /// been deleted. Must be an element of the field `Kr`.
    /// @param postRoot The root obtained after deleting all of `identityCommitments` into the tree
    ///        described by `preRoot`. Must be an element of the field `Kr`.
    ///
    /// @custom:reverts Unauthorized If the message sender is not authorised to add identities.
    /// @custom:reverts NotLatestRoot If the provided `preRoot` is not the latest root.
    /// @custom:reverts ProofValidationFailure If `deletionProof` cannot be verified using the
    ///                 provided inputs.
    /// @custom:reverts VerifierLookupTable.NoSuchVerifier If the batch sizes doesn't match a known
    ///                 verifier.
    /// @custom:reverts InvalidDeletionIndices if the length of `packedDeletionIndices`
    /// is not a multiple of 4 (8*4 = 32 bits per index)
    function deleteIdentities(
        uint256[8] calldata deletionProof,
        bytes calldata packedDeletionIndices,
        uint256 preRoot,
        uint256 postRoot
    ) public virtual onlyProxy onlyInitialized onlyIdentityOperator {
        if (packedDeletionIndices.length % 4 != 0) {
            revert InvalidDeletionIndices();
        }

        uint32 batchSize = uint32(packedDeletionIndices.length / 4);

        if (preRoot != _latestRoot) {
            revert NotLatestRoot(preRoot, _latestRoot);
        }

        // Having validated the preconditions we can now check the proof itself.
        bytes32 inputHash =
            calculateIdentityDeletionInputHash(packedDeletionIndices, preRoot, postRoot, batchSize);

        // No matter what, the inputs can result in a hash that is not an element of the scalar
        // field in which we're operating. We reduce it into the field before handing it to the
        // verifier. All other elements that are passed as calldata are reduced in the circuit.
        uint256 reducedElement = uint256(inputHash) % SNARK_SCALAR_FIELD;

        // We need to look up the correct verifier before we can verify.
        ITreeVerifier deletionVerifier = batchDeletionVerifiers.getVerifierFor(batchSize);

        // With that, we can properly try and verify.
        try deletionVerifier.verifyProof(deletionProof, [reducedElement]) {
            // If it did verify, we need to update the contract's state. We set the currently valid
            // root to the root after the deletions.
            _latestRoot = postRoot;

            // We also need to add the previous root to the history, and set the timestamp at
            // which it was expired.
            rootHistory[preRoot] = uint128(block.timestamp);

            emit TreeChanged(preRoot, TreeChange.Deletion, postRoot);
        } catch Error(string memory errString) {
            /// This is not the revert we're looking for.
            revert(errString);
        } catch {
            // If we reach here we know it's the internal error, as the tree verifier only uses
            // `require`s otherwise, which will be re-thrown above.
            revert ProofValidationFailure();
        }
    }

    /// @notice Gets the address for the lookup table of merkle tree verifiers used for batch identity
    ///         deletions.
    /// @dev The deletion verifier supports batch deletions of size 10, 100 and 1000 members per batch.
    ///
    /// @return addr The address of the contract being used as the verifier lookup table.
    function getDeleteIdentitiesVerifierLookupTableAddress()
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (address)
    {
        return address(batchDeletionVerifiers);
    }

    /// @notice Sets the address for the lookup table of merkle tree verifiers used for identity
    ///         deletions.
    /// @dev Only the owner of the contract can call this function.
    ///
    /// @param newTable The new verifier lookup table to be used for verifying identity
    ///        deletions.
    /// @custom:reverts InvalidVerifierLUT if `newTable` is set to the zero address
    function setDeleteIdentitiesVerifierLookupTable(VerifierLookupTable newTable)
        public
        virtual
        onlyProxy
        onlyInitialized
        onlyOwner
    {
        if (address(newTable) == address(0)) {
            revert InvalidVerifierLUT();
        }

        VerifierLookupTable oldTable = batchDeletionVerifiers;
        batchDeletionVerifiers = newTable;
        emit DependencyUpdated(
            Dependency.DeletionVerifierLookupTable, address(oldTable), address(newTable)
        );
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                             UTILITY FUNCTIONS                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Calculates the input hash for the identity deletion verifier.
    /// @dev Implements the computation described below.
    ///
    /// @param packedDeletionIndices The indices of the identities that were deleted from the tree.
    /// @param preRoot The root value of the tree before these deletions were made.
    /// @param postRoot The root value of the tree after these deletions were made.
    /// @param batchSize The number of identities that were deleted in this batch
    ///
    /// @return hash The input hash calculated as described below.
    ///
    /// @dev the deletion indices are packed into bytes calldata where each deletion index is 32 bits
    ///     wide. The indices are encoded using abi.encodePacked for testing.
    ///
    /// We keccak hash all input to save verification gas. Inputs for the hash are arranged as follows:
    ///
    /// packedDeletionIndices || PreRoot || PostRoot
    ///   32 bits * batchSize ||   256   ||    256
    function calculateIdentityDeletionInputHash(
        bytes calldata packedDeletionIndices,
        uint256 preRoot,
        uint256 postRoot,
        uint32 batchSize
    ) public view virtual onlyProxy onlyInitialized returns (bytes32 hash) {
        assembly {
            let startOffset := mload(0x40)
            let indicesByteSize := mul(batchSize, 4)
            calldatacopy(startOffset, packedDeletionIndices.offset, indicesByteSize)
            let rootsOffset := add(startOffset, indicesByteSize)
            mstore(rootsOffset, preRoot)
            mstore(add(rootsOffset, 32), postRoot)
            hash := keccak256(startOffset, add(64, indicesByteSize))
        }
    }
}
