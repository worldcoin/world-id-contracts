pragma solidity ^0.8.15;

interface IBridge {
    /// @notice Sends the latest Semaphore root to Optimism.
    /// @dev Calls this method on the L1 Proxy contract to relay the latest root to all supported networks
    /// @param root The latest Semaphore root.
    function sendRootMultichain(uint256 root) external;
}
