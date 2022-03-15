//SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

interface ISemaphore {
    /// @dev Wether no nullifier already exists and if the zero-knowledge proof is valid.
    /// @param signal The Semaphore signal
    /// @param root The root of the Merkle tree to check
    /// @param nullifierHash The nullifier hash
    /// @param externalNullifier The external nullifier
    /// @param proof The zero-knowledge proof
    function _isValidProof(
        string calldata signal,
        uint256 root,
        uint256 nullifierHash,
        uint256 externalNullifier,
        uint256[8] calldata proof
    ) external view returns (bool);

    /// @dev Returns the last root hash of a group.
    /// @param groupId Id of the group.
    /// @return Root hash of the group.
    function getRoot(uint256 groupId) external view returns (uint256);
}
