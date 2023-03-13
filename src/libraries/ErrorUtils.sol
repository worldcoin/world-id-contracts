// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title WorldID Error Utils
/// @author Worldcoin
/// @notice A set of utilities for working with error data inside solidity.
library ErrorUtils {
    /// @notice Forwards a revert that was caught as bytes without changing the contents of the
    ///         error.
    ///
    /// @param errData The error data to forward unchanged.
    ///
    /// @custom:reverts bytes Unconditionally reverts with the provided `bytes`.
    function forwardErrorData(bytes memory errData) internal pure {
        uint256 errLength = errData.length;
        /// @solidity memory-safe-assembly
        assembly {
            revert(add(errData, 32), errLength)
        }
    }

    /// @notice Extracts the selector from the header of the error data.
    /// @dev This will do so unconditionally, so passing it data that is not an encoded error will
    ///      give you back garbage.
    ///
    /// @param data The `bytes` from which to obtain the selector.
    ///
    /// @return selector The selector extracted from `data`.
    ///
    /// @custom:reverts string If the length of `data` is too short to contain a selector.
    function getSelector(bytes memory data) internal pure returns (bytes4 selector) {
        if (data.length < 4) {
            revert("Data length too short to contain a selector.");
        }
        /// @solidity memory-safe-assembly
        assembly {
            // Arrays have their first 32 bytes storing their length, so we want to load the data
            // that comes _after_ that as the selector, relying on the natural truncation of the
            // target variable.
            selector := mload(add(data, 32))
        }
    }
}
