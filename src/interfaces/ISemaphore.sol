//SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {ISemaphoreGroups} from "semaphore/interfaces/ISemaphoreGroups.sol";

interface ISemaphore {
    /// @dev Returns true if no nullifier already exists and if the zero-knowledge proof is valid.
    /// Otherwise it returns false.
    /// @param signal: Semaphore signal.
    /// @param root: Root of the Merkle tree.
    /// @param nullifierHash: Nullifier hash.
    /// @param externalNullifier: External nullifier.
    /// @param proof: Zero-knowledge proof.
    function _isValidProof(
        string calldata signal,
        uint256 root,
        uint256 nullifierHash,
        uint256 externalNullifier,
        uint256[8] calldata proof
    ) external view returns (bool);

    /// @dev Stores the nullifier hash to prevent double-signaling.
    /// Attention! Remember to call it when you verify a proof if you
    /// need to prevent double-signaling.
    /// @param nullifierHash: Semaphore nullifier hash.
    function _saveNullifierHash(uint256 nullifierHash) external;

    // @dev See {ISemaphoreGroups-getRoot}.
    function getRoot(uint256 groupId)
        public
        view
        virtual
        override
        returns (uint256)
    {
        return groups[groupId].root;
    }
}
