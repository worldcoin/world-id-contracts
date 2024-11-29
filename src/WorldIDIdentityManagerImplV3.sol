pragma solidity ^0.8.24;

import "./WorldIDIdentityManagerImplV2.sol";
import "./interfaces/ITreeVerifier4844.sol";
import {VerifierLookupTable4844} from "./data/VerifierLookupTable4844.sol";

/// @title WorldID Identity Manager Implementation Version 3
/// @author Worldcoin
/// @notice An implementation of a batch-based identity manager for the WorldID protocol.
/// @dev The manager is based on the principle of verifying externally-created Zero Knowledge Proofs
///      to perform the insertion using EIP-4844.
/// @dev This is the implementation delegated to by a proxy.
contract WorldIDIdentityManagerImplV3 is WorldIDIdentityManagerImplV2 {
    ///////////////////////////////////////////////////////////////////////////////
    ///                   A NOTE ON IMPLEMENTATION CONTRACTS                    ///
    ///////////////////////////////////////////////////////////////////////////////

    // This contract is designed explicitly to operate from behind a proxy contract. As a result,
    // there are a few important implementation considerations:
    //
    // - All updates made after deploying a given version of the implementation should inherit from
    //   the latest version of the implementation. This contract inherits from its previous implementation
    //   WorldIDIdentityManagerImplV2. This prevents storage clashes.
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

    /// @notice The table of verifiers for verifying batch identity insertions following the EIP-4844 scheme.
    VerifierLookupTable4844 internal batchInsertion4844Verifiers;

    /// @notice Thrown when the WorldIDIdentityManagerImplV3 contract is initialized
    event WorldIDIdentityManagerImplV3Initialized();

    /// @notice Initializes the V3 implementation contract.
    /// @param _batchInsertion4844Verifiers The table of verifiers for verifying batch identity insertions.
    /// @dev Must be called exactly once
    /// @dev This is marked `reinitializer()` to allow for updated initialisation steps when working
    ///      with upgrades based upon this contract. Be aware that there are only 256 (zero-indexed)
    ///      initialisations allowed, so decide carefully when to use them. Many cases can safely be
    ///      replaced by use of setters.
    /// @dev This function is explicitly not virtual as it does not make sense to override even when
    ///      upgrading. Create a separate initializer function instead.
    ///
    ///
    /// @custom:reverts InvalidVerifierLUT if `_batchInsertion4844Verifiers` is set to the zero address
    function initializeV3(VerifierLookupTable4844 _batchInsertion4844Verifiers)
        public
        reinitializer(3)
    {
        if (address(_batchInsertion4844Verifiers) == address(0)) {
            revert InvalidVerifierLUT();
        }

        batchInsertion4844Verifiers = _batchInsertion4844Verifiers;

        emit WorldIDIdentityManagerImplV3Initialized();
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                             UTILITY FUNCTIONS                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Gets the address for the lookup table of merkle tree verifiers used for identity
    ///         registrations.
    ///
    /// @return addr The address of the contract being used as the verifier lookup table.
    function getRegisterIdentities4844VerifierLookupTableAddress()
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (address)
    {
        return address(batchInsertion4844Verifiers);
    }

    /// @notice Sets the address for the lookup table of merkle tree verifiers used for identity
    ///         registrations.
    /// @dev Only the owner of the contract can call this function.
    ///
    /// @param newTable The new verifier lookup table to be used for verifying identity
    ///        registrations.
    /// @custom:reverts InvalidVerifierLUT if `newTable` is set to the zero address
    function setRegisterIdentities4844VerifierLookupTable(VerifierLookupTable4844 newTable)
        public
        virtual
        onlyProxy
        onlyInitialized
        onlyOwner
    {
        if (address(newTable) == address(0)) {
            revert InvalidVerifierLUT();
        }

        VerifierLookupTable4844 oldTable = batchInsertion4844Verifiers;
        batchInsertion4844Verifiers = newTable;
        emit DependencyUpdated(
            Dependency.InsertionVerifierLookupTable, address(oldTable), address(newTable)
        );
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                               PUBLIC TYPES                              ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Parameters for registerIdentities4844 function.
    /// @dev This struct holds the parameters for registering identities and verifying the insertion proof
    ///      using KZG proofs as described in EIP-4844.
    struct RegisterIdentities4844Params {
        /// @notice The proof that given the conditions, insertion into the tree results in `postRoot`.
        ///         Elements 0 and 1 are the `x` and `y` coordinates for `ar` respectively. Elements 2 and 3 are the
        ///         `x` coordinate for `bs`, and elements 4 and 5 are the `y` coordinate for `bs`. Elements 6 and 7
        ///         are the `x` and `y` coordinates for `krs`.
        uint256[8] insertionProof;
        /// @notice The Pedersen commitments from the proof.
        uint256[2] commitments;
        /// @notice The proof of knowledge for the Pedersen commitments.
        uint256[2] commitmentPok;
        /// @notice KZG commitment for the polynomial extrapolated from the identities.
        uint128[3] kzgCommitment;
        /// @notice KZG proof associated with the commitment.
        uint128[3] kzgProof;
        /// @notice Expected evaluation of the polynomial at a certain point equal to KZG challenge.
        uint256 expectedEvaluation;
        /// @notice The value for the root of the tree before the `identityCommitments` have been inserted.
        ///         Must be an element of the field `Kr`. (already in reduced form)
        uint256 preRoot;
        /// @notice The root obtained after inserting all of `identityCommitments` into the tree described
        ///         by `preRoot`. Must be an element of the field `Kr`. (already in reduced form)
        uint256 postRoot;
        /// @notice Hash of all inserted identities, constructed by taking a root of the Merkle Tree of minimal
        ///         depth containing all identities.
        bytes32 inputHash;
        /// @notice Number of identities being registered in this batch.
        uint32 batchSize;
        /// @notice The position in the tree at which the insertions were made.
        uint32 startIndex;
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                                  ERRORS                                 ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the point evaluation precompile returns failure.
    ///         This means KZG proof cannot be verified.
    error KzgProofVerificationFailed();

    ///////////////////////////////////////////////////////////////////
    ///                     IDENTITY MANAGEMENT                     ///
    ///////////////////////////////////////////////////////////////////

    /// @notice Registers identities into the WorldID system following the EIP-4844 scheme.
    /// @dev Can only be called by the identity operator.
    /// @dev Registration is performed off-chain and verified on-chain via insertion proof
    ///      and KZG proof. This saves gas and time over inserting identities one at a time.
    ///
    /// @param params parameters for the process defined by the `RegisterIdentities4844Params` structure.
    /// @custom:reverts Unauthorized If the message sender is not authorised to add identities.
    /// @custom:reverts NotLatestRoot If the provided `params.preRoot` is not the latest root.
    /// @custom:reverts ProofValidationFailure If `params.insertionProof` cannot be verified using the
    ///                 provided inputs.
    /// @custom:reverts VerifierLookupTable.NoSuchVerifier If the batch sizes doesn't match a known
    ///                 verifier.
    /// @custom:reverts KzgProofVerificationFailed If KZG proof verification fails
    function registerIdentities4844(RegisterIdentities4844Params calldata params)
        public
        virtual
        onlyProxy
        onlyInitialized
        onlyIdentityOperator
    {
        if (params.preRoot != _latestRoot) {
            revert NotLatestRoot(params.preRoot, _latestRoot);
        }

        bytes32 kzgCommitmentHash = blobhash(0);
        bytes32 kzgChallenge = computeKzgChallenge(params.inputHash, kzgCommitmentHash);
        bool success = evaluatePoint(
            kzgCommitmentHash,
            kzgChallenge,
            bytes32(params.expectedEvaluation),
            params.kzgCommitment,
            params.kzgProof
        );
        if (!success) {
            revert KzgProofVerificationFailed();
        }

        // We need to look up the correct verifier before we can verify.
        ITreeVerifier4844 insertionVerifier =
            batchInsertion4844Verifiers.getVerifierFor(params.batchSize);

        // With that, we can properly try and verify.
        try insertionVerifier.verifyProof(
            params.insertionProof,
            params.commitments,
            params.commitmentPok,
            [
                uint256(params.inputHash),
                params.expectedEvaluation % SNARK_SCALAR_FIELD,
                uint256(kzgCommitmentHash),
                uint256(params.startIndex),
                params.preRoot,
                params.postRoot
            ]
        ) {
            // If it did verify, we need to update the contract's state. We set the currently valid
            // root to the root after the insertions.
            _latestRoot = params.postRoot;

            // We also need to add the previous root to the history, and set the timestamp at
            // which it was expired.
            rootHistory[params.preRoot] = uint128(block.timestamp);

            emit TreeChanged(params.preRoot, TreeChange.Insertion, params.postRoot);
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

    address constant PRECOMPILE_POINT_EVALUATION = address(0x0a);

    /// @notice Call the point evaluation precompiled contract.
    ///         Verify p(z) = y given commitment that corresponds to the polynomial p(x) and a KZG proof.
    ///         Also verify that the provided commitment matches the provided versioned_hash.
    /// @param versioned_hash Reference to a blob in the execution layer (obtained from the data storage or execution environment).
    /// @param x x-coordinate at which the blob is being evaluated.
    /// @param y y-coordinate at which the blob is being evaluated.
    /// @param commitment Commitment to the blob being evaluated (obtained from the KZG commitment scheme).
    /// @param kzgProof Proof associated with the commitment (obtained from the KZG proof generation).
    /// @return True on success, false otherwise.
    function evaluatePoint(
        bytes32 versioned_hash,
        bytes32 x,
        bytes32 y,
        uint128[3] calldata commitment,
        uint128[3] calldata kzgProof
    ) public view returns (bool) {
        bytes memory input = abi.encodePacked(
            versioned_hash,
            x,
            y,
            commitment[0],
            commitment[1],
            commitment[2],
            kzgProof[0],
            kzgProof[1],
            kzgProof[2]
        );
        (bool success,) = PRECOMPILE_POINT_EVALUATION.staticcall(input);
        return success;
    }

    /// @notice Converts input values to a KZG challenge.
    /// @dev The challenge is defined as a bytes32 value of a keccak256 hash of the concatenated inputs reduced by BN254 modulus.
    /// @param inputHash Hash of the input data calculated as described in the comment
    ///        to `calculateIdentityRegistrationInputHash()`.
    /// @param kzgCommitmentVersionedHash versioned hash of the KZG commitment.
    /// @return challenge The reduced keccak256 hash.
    function computeKzgChallenge(bytes32 inputHash, bytes32 kzgCommitmentVersionedHash)
        public
        pure
        returns (bytes32)
    {
        bytes memory inputBytes = abi.encodePacked(inputHash, kzgCommitmentVersionedHash);
        uint256 reducedHash = uint256(keccak256(inputBytes)) % SNARK_SCALAR_FIELD;
        return bytes32(reducedHash);
    }
}
