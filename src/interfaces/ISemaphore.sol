//SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

interface ISemaphore {
	/// @dev Wether no nullifier already exists and if the zero-knowledge proof is valid.
	/// @param groupId The id of the Semaphore group
	/// @param signal The Semaphore signal
	/// @param nullifierHash The nullifier hash
	/// @param externalNullifier The external nullifier
	/// @param proof The zero-knowledge proof
	function isValidProof(
		uint256 groupId,
		bytes32 signal,
		uint256 nullifierHash,
		uint256 externalNullifier,
		uint256[8] calldata proof
	) external view returns (bool);
}
