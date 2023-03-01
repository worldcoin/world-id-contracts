// SPDX-License-Identifier: MIT
pragma solidity 0.8.4;

/// @title Tree Verifier Interface
/// @author Worldcoin
/// @notice An interface representing a merkle tree verifier.
interface ITreeVerifier {
    /// @notice Verifies the provided proof data for the provided public inputs.
    ///
    /// @param a The first G1Point of the proof (ar).
    /// @param b The G2Point for the proof (bs).
    /// @param c The second G1Point of the proof (kr).
    /// @param input The public inputs to the function, reduced such that it is a member of the
    ///              field `Fr` where `r` is `SNARK_SCALAR_FIELD`.
    ///
    /// @return _ True if the proof verifies successfully, false otherwise.
    /// @custom:reverts string If the proof elements are not < `PRIME_Q` or if the `input` is not
    ///                 less than `SNARK_SCALAR_FIELD`.
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[1] memory input
    ) external view returns (bool);
}
