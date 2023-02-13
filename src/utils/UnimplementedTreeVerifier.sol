// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {ITreeVerifier} from "../interfaces/ITreeVerifier.sol";

/// @title Unimplemented Tree Verifier
/// @author Worldcoin
/// @notice A tree verifier instance that performs no operations.
contract UnimplementedTreeVerifier is ITreeVerifier {
    /// @notice Thrown when an operation is not supported.
    error UnsupportedOperation();

    /// @notice Exists to satisfy the interface.
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[1] memory input
    ) external pure returns (bool) {
        delete a;
        delete b;
        delete c;
        delete input;
        revert UnsupportedOperation();
    }
}
