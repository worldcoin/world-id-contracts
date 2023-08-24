pragma solidity ^0.8.21;

import "./WorldIDIdentityManagerImplV1.sol";

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

    ///////////////////////////////////////////////////////////////////
    ///                     IDENTITY MANAGEMENT                     ///
    ///////////////////////////////////////////////////////////////////

    /// @notice Deletes identities from the WorldID system.
    /// @dev Can only be called by the owner.
    /// @dev Deletion is performed off-chain and verified on-chain via the `deletionProof`.
    ///      This saves gas and time over deleting identities one at a time.
    ///
    /// @param deletionProof The proof that given the conditions (`preRoot`, `startIndex` and
    ///        `identityCommitments`), deletion into the tree results in `postRoot`. Elements 0 and
    ///        1 are the `x` and `y` coordinates for `ar` respectively. Elements 2 and 3 are the `x`
    ///        coordinate for `bs`, and elements 4 and 5 are the `y` coordinate for `bs`. Elements 6
    ///        and 7 are the `x` and `y` coordinates for `krs`.
    /// @param preRoot The value for the root of the tree before the `identityCommitments` have been
    ///       inserted. Must be an element of the field `Kr`.
    /// @param deletionIndices The indices of the identities that were deleted from the tree.
    /// @param postRoot The root obtained after deleting all of `identityCommitments` into the tree
    ///        described by `preRoot`. Must be an element of the field `Kr`.
    ///
    /// @custom:reverts Unauthorized If the message sender is not authorised to add identities.
    /// @custom:reverts InvalidCommitment If one or more of the provided commitments is invalid.
    /// @custom:reverts NotLatestRoot If the provided `preRoot` is not the latest root.
    /// @custom:reverts ProofValidationFailure If `deletionProof` cannot be verified using the
    ///                 provided inputs.
    /// @custom:reverts UnreducedElement If any of the `preRoot`, `postRoot` and
    ///                 `identityCommitments` is not an element of the field `Kr`. It describes the
    ///                 type and value of the unreduced element.
    /// @custom:reverts VerifierLookupTable.NoSuchVerifier If the batch sizes doesn't match a known
    ///                 verifier.
    /// @custom:reverts VerifierLookupTable.BatchTooLarge If the batch size exceeds the maximum
    ///                 batch size.
    function deleteIdentities(
        uint256[8] calldata deletionProof,
        uint256 preRoot,
        uint32[] calldata deletionIndices,
        uint256 postRoot
    ) public virtual onlyProxy onlyInitialized onlyIdentityOperator {
        // We can only operate on the latest root in reduced form.
        if (preRoot >= SNARK_SCALAR_FIELD) {
            revert UnreducedElement(UnreducedElementType.PreRoot, preRoot);
        }
        if (preRoot != _latestRoot) {
            revert NotLatestRoot(preRoot, _latestRoot);
        }

        // As the `startIndex` is restricted to a uint32, where
        // `type(uint32).max <<< SNARK_SCALAR_FIELD`, we are safe not to check this. As verified in
        // the tests, a revert happens if you pass a value larger than `type(uint32).max` when
        // calling outside the type-checker's protection.

        // We need the post root to be in reduced form.
        if (postRoot >= SNARK_SCALAR_FIELD) {
            revert UnreducedElement(UnreducedElementType.PostRoot, postRoot);
        }

        // Having validated the preconditions we can now check the proof itself.
        bytes32 inputHash = calculateIdentityDeletionInputHash(deletionIndices, preRoot, postRoot);

        // No matter what, the inputs can result in a hash that is not an element of the scalar
        // field in which we're operating. We reduce it into the field before handing it to the
        // verifier.
        uint256 reducedElement = uint256(inputHash) % SNARK_SCALAR_FIELD;

        // We need to look up the correct verifier before we can verify.
        ITreeVerifier deletionVerifier =
            batchDeletionVerifiers.getVerifierFor(deletionIndices.length);

        // With that, we can properly try and verify.
        try deletionVerifier.verifyProof(
            [deletionProof[0], deletionProof[1]],
            [[deletionProof[2], deletionProof[3]], [deletionProof[4], deletionProof[5]]],
            [deletionProof[6], deletionProof[7]],
            [reducedElement]
        ) returns (bool verifierResult) {
            // If the proof did not verify, we revert with a failure.
            if (!verifierResult) {
                revert ProofValidationFailure();
            }

            // If it did verify, we need to update the contract's state. We set the currently valid
            // root to the root after the insertions.
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
    function setDeleteIdentitiesVerifierLookupTable(VerifierLookupTable newTable)
        public
        virtual
        onlyProxy
        onlyInitialized
        onlyOwner
    {
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
    /// @param deletionIndices The indices of the identities that were deleted from the tree.
    /// @param preRoot The root value of the tree before these insertions were made.
    /// @param postRoot The root value of the tree after these insertions were made.
    ///
    /// @return hash The input hash calculated as described below.
    ///
    /// We keccak hash all input to save verification gas. Inputs are arranged as follows:
    ///
    /// deletionIndices[0] || deletionIndices[1] || ... || deletionIndices[batchSize-1] || PreRoot || PostRoot
    ///        32          ||        32          || ... ||              32              ||   256   ||    256
    function calculateIdentityDeletionInputHash(
        uint32[] calldata deletionIndices,
        uint256 preRoot,
        uint256 postRoot
    ) public view virtual onlyProxy onlyInitialized returns (bytes32 hash) {
        bytes memory bytesToHash = abi.encodePacked(deletionIndices, preRoot, postRoot);

        hash = keccak256(bytesToHash);
    }
}
