// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title Tree Verifier Interface
/// @author Worldcoin
/// @notice An interface representing a merkle tree verifier.
interface ITreeVerifier {
    /// @notice Verify an uncompressed Groth16 proof.
    /// @notice Reverts with InvalidProof if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was succesfully verified.
    /// @param proof the points (A, B, C) in EIP-197 format matching the output
    /// of compressProof.
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyProof(uint256[8] calldata proof, uint256[1] calldata input) external;
}
