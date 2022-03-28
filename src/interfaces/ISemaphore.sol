//SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

interface ISemaphore {
    /// @notice Wether the zero-knowledge proof is valid.
    /// @param root The of the Merkle tree
    /// @param groupId The id of the Semaphore group
    /// @param signalHash A keccak256 hash of the Semaphore signal
    /// @param nullifierHash The nullifier hash
    /// @param externalNullifierHash A keccak256 hash of the external nullifier
    /// @param proof The zero-knowledge proof
    /// @return Wether the proof is valid or not
    /// @dev  Note that a double-signaling check is not included here, and should be carried by the caller.
    function isValidProof(
        uint256 root,
        uint256 groupId,
        uint256 signalHash,
        uint256 nullifierHash,
        uint256 externalNullifierHash,
        uint256[8] calldata proof
    ) external view returns (bool);
}
