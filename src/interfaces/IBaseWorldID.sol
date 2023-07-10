//SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title Base WorldID interface
/// @author Worldcoin
/// @notice The interface providing basic types across various WorldID contracts.
interface IBaseWorldID {
    ///////////////////////////////////////////////////////////////////////////////
    ///                                  ERRORS                                 ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when attempting to validate a root that has expired.
    error ExpiredRoot();

    /// @notice Thrown when attempting to validate a root that has yet to be added to the root
    ///         history.
    error NonExistentRoot();
}
