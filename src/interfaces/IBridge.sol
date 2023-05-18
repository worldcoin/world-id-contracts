// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IBridge {
    /// @notice Sends the latest Semaphore root to Optimism.
    /// @dev Calls this method on the L1 Proxy contract to relay the latest root to all supported networks
    /// @param root The latest Semaphore root.
    /// @param opGasLimit The gas limit for the Optimism transaction (how much gas to buy on Optimism with the message)
    function sendRootMultichain(uint256 root, uint32 opGasLimit) external;

    /// @notice Sets the root history expiry for OpWorldID (on Optimism) and PolygonWorldID (on Polygon)
    /// @param expiryTime The new root history expiry for OpWorldID and PolygonWorldID
    /// @dev gated by onlyWorldIDIdentityManager modifier
    /// @param opGasLimit The gas limit for the Optimism transaction (how much gas to buy on Optimism with the message)
    function setRootHistoryExpiry(uint256 expiryTime, uint32 opGasLimit) external;
}
