//SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IBaseWorldID} from "./IBaseWorldID.sol";

/// @title WorldID Interface
/// @author Worldcoin
/// @notice The interface to the proof verification for WorldID.
interface IWorldID is IBaseWorldID {
    /// @notice Verifies a WorldID zero knowledge proof.
    /// @dev Note that a double-signaling check is not included here, and should be carried by the
    ///      caller.
    /// @dev It is highly recommended that the implementation is restricted to `view` if possible.
    ///
    /// @param root The of the Merkle tree
    /// @param signalHash A keccak256 hash of the Semaphore signal
    /// @param nullifierHash The nullifier hash
    /// @param externalNullifierHash A keccak256 hash of the external nullifier
    /// @param proof The zero-knowledge proof
    ///
    /// @custom:reverts string If the `proof` is invalid.
    function verifyProof(
        uint256 root,
        uint256 signalHash,
        uint256 nullifierHash,
        uint256 externalNullifierHash,
        uint256[8] calldata proof
    ) external;
}
