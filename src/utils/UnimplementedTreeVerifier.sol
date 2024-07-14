// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {ITreeVerifier} from "../interfaces/ITreeVerifier.sol";

/// @title Unimplemented Tree Verifier
/// @author Worldcoin
/// @notice A tree verifier instance that will always revert.
/// @dev This verifier is used as the default implementation for the update and remove endpoints in
///      the WorldID identity manager. We do not currently have ZK circuit designs for these
///      endpoints, but having the contract portion already implemented makes it easier for the
///      future where those will work.
contract UnimplementedTreeVerifier is ITreeVerifier {
    /// @notice Thrown when an operation is not supported.
    error UnsupportedOperation();

    /// @notice Verify an uncompressed Groth16 proof.
    /// @notice Reverts with InvalidProof if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was succesfully verified.
    /// @custom:reverts UnsupportedOperation When called.
    function verifyProof(uint256[8] calldata, /*proof*/ uint256[1] calldata /*input*/ )
        external
        pure
    {
        revert UnsupportedOperation();
    }
}
