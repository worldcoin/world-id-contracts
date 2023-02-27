// SPDX-License-Identifier: MIT
pragma solidity 0.8.4;

/// @title Tree Verifier Interface
/// @author Worldcoin
/// @notice An interface representing a merkle tree verifier.
interface ITreeVerifier {
    /// @notice Verifies the provided proof data for the provided public inputs.
    ///
    /// @param root The of the Merkle tree
    /// @param signalHash A keccak256 hash of the Semaphore signal
    /// @param nullifierHash The nullifier hash
    /// @param externalNullifierHash A keccak256 hash of the external nullifier
    /// @param proof The zero-knowledge proof
    ///
    /// @return _ True if the proof verifies successfully, false otherwise.
    /// @custom:reverts string If the proof elements are not < `PRIME_Q` or if the `input` is not
    ///                 less than `SNARK_SCALAR_FIELD`.
    function verifyProof(
        uint256 root,
        uint256 signalHash,
        uint256 nullifierHash,
        uint256 externalNullifierHash,
        uint256[8] calldata proof
    ) external view returns (bool);
}
