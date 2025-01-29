pragma solidity ^0.8.21;

import "./WorldIDIdentityManagerImplV2.sol";

/// @title WorldID Identity Manager Implementation Version 3
/// @author Worldcoin
/// @notice An implementation of a batch-based identity manager for the WorldID protocol.
/// @dev The manager is based on the principle of verifying externally-created Zero Knowledge Proofs
///      to perform the deletions.
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

    ///////////////////////////////////////////////////////////////////////////////
    ///                    SEMAPHORE PROOF VALIDATION LOGIC                     ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice A verifier for the semaphore protocol that supports compressed proofs and is backwards
    ///         compatible with the previous implementation. If a proof is compressed, the last 4 uints
    ///         will be 0. If this condition is met, we will call the semaphore compress proof function
    ///         instead.
    /// @dev Note that a double-signaling check is not included here, and should be carried by the
    ///      caller.
    ///
    /// @param root The of the Merkle tree
    /// @param signalHash A keccak256 hash of the Semaphore signal
    /// @param nullifierHash The nullifier hash
    /// @param externalNullifierHash A keccak256 hash of the external nullifier
    /// @param proof The zero-knowledge proof
    /// @custom:reverts string If the zero-knowledge proof cannot be verified for the public inputs.
    function verifyProof(
        uint256 root,
        uint256 signalHash,
        uint256 nullifierHash,
        uint256 externalNullifierHash,
        uint256[8] calldata proof
    ) public view virtual override onlyProxy onlyInitialized {
        // Check the preconditions on the inputs.
        requireValidRoot(root);
        uint256[4] memory input = [root, nullifierHash, signalHash, externalNullifierHash];
        if (proof[4] == 0 && proof[5] == 0 && proof[6] == 0 && proof[7] == 0) {
            uint256[4] memory compressedProof = [proof[0], proof[1], proof[2], proof[3]];
            semaphoreVerifier.verifyCompressedProof(compressedProof, input);
        } else {
            semaphoreVerifier.verifyProof(proof, input);
        }
    }
}
