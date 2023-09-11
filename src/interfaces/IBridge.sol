// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IBridge {
    /// @notice Sends the latest Semaphore root to Optimism.
    /// @dev Calls this method on the L1 Proxy contract to relay the latest root to all supported networks
    /// @param root The latest Semaphore root.
    function sendRootMultichain(uint256 root) external;

    /// @notice Sets the root history expiry for OpWorldID (on Optimism) and PolygonWorldID (on Polygon)
    /// @param expiryTime The new root history expiry for OpWorldID and PolygonWorldID
    /// @dev gated by onlyWorldIDIdentityManager modifier
    function setRootHistoryExpiry(uint256 expiryTime) external;
}
