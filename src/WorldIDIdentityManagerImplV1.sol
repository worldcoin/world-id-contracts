// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {OwnableUpgradeable} from "contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title WorldID Identity Manager Implementation Version 1
/// @author Worldcoin
/// @notice An implementation of a batch-based identity manager for the WorldID protocol.
/// @dev The manager is based on the principle of verifying externally-created Zero Knowledge Proofs
///      to perform the insertions.
/// @dev This is the implementation delegated to by a proxy. All updates to the implementation
///      should inherit from the latest version of the implementation. To this end, all functions
///      here should be marked virtual to enable updating logic.
contract WorldIDIdentityManagerImplV1 is OwnableUpgradeable, UUPSUpgradeable {
    ///////////////////////////////////////////////////////////////////////////////
    ///                    !!!!! DATA: DO NOT REORDER !!!!!                     ///
    ///////////////////////////////////////////////////////////////////////////////

    // To ensure compatibility between upgrades, it is exceedingly important that no reordering of
    // these variables takes place. If reordering happens, a storage clash will occur (effectively a
    // memory safety error).

    ///////////////////////////////////////////////////////////////////////////////
    ///                             INITIALIZATION                              ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Initializes the contract.
    /// @dev Must be called exactly once.
    ///
    /// @custom:reverts string If called more than once.
    function initialize() public virtual initializer {
        // First, ensure that all of the children are initialised.
        __delegate_init();

        // Now perform the implementation's init logic.
    }

    /// @notice Responsible for initialising all of the supertypes of this contract.
    /// @dev Must be called exactly once.
    /// @dev When adding new superclasses, ensure that any initialization that they need to perform
    ///      is accounted for here.
    ///
    /// @custom:reverts string If called more than once.
    function __delegate_init() internal virtual {
        __Ownable_init();
        __UUPSUpgradeable_init();
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                             AUTHENTICATION                              ///
    ///////////////////////////////////////////////////////////////////////////////

    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {
        // No body needed as `onlyOwner` handles it.
    }
}
