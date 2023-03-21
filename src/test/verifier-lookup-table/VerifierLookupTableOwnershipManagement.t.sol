// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {VerifierLookupTableTest} from "./VerifierLookupTableTest.sol";

import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

/// @title Verifier Lookup Table Ownership Management Tests
/// @notice Contains tests for the batch lookup table.
/// @author Worldcoin
contract BatchLookupTableOwnershipManagement is VerifierLookupTableTest {
    /// @notice Taken from OwnableUpgradable.sol
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @notice Checks that it is possible to get the owner, and that the owner is correctly
    ///         initialised.
    function testHasOwner() public {
        // Setup
        address expectedOwner = thisAddress;

        // Test
        address owner = lookupTable.owner();
        assertEq(owner, expectedOwner);
    }

    /// @notice Tests that it is possibel to transfer ownership of the contract.
    function testTransferOwner(address newOwner) public {
        // Setup
        vm.assume(newOwner != nullAddress);
        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(thisAddress, newOwner);

        // Test
        lookupTable.transferOwnership(newOwner);
        assertEq(lookupTable.owner(), newOwner);
    }

    /// @notice Ensures that it is impossible to transfer ownership without being the owner.
    function testCannotTransferOwnerIfNotOwner(address naughty, address newOwner) public {
        // Setup
        vm.assume(naughty != thisAddress && newOwner != nullAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        vm.prank(naughty);

        // Test
        lookupTable.transferOwnership(newOwner);
    }

    /// @notice Tests that it is possible to renounce ownership.
    function testRenounceOwnership() public {
        // Test
        lookupTable.renounceOwnership();
        assertEq(lookupTable.owner(), nullAddress);
    }

    /// @notice Ensures that ownership cannot be renounced by anybody other than the owner.
    function testCannotRenounceOwnershipIfNotOwner(address naughty) public {
        // Setup
        vm.assume(naughty != thisAddress && naughty != nullAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        vm.prank(naughty);

        // Test
        lookupTable.renounceOwnership();
    }
}
