// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {VerifierLookupTableTest} from "./VerifierLookupTableTest.sol";

import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

/// @title Verifier Lookup Table Ownership Management Tests
/// @notice Contains tests for the verifier lookup table.
/// @author Worldcoin
contract VerifierLookupTableOwnershipManagement is VerifierLookupTableTest {
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

    /// @notice Tests that it is possible to transfer ownership of the contract.
    function testTransferOwner(address newOwner) public {
        // Setup
        vm.assume(newOwner != nullAddress);

        // Test 1
        lookupTable.transferOwnership(newOwner);
        assertEq(lookupTable.pendingOwner(), newOwner);

        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(thisAddress, newOwner);

        // Test 2
        vm.prank(newOwner);
        lookupTable.acceptOwnership();
        assertEq(lookupTable.owner(), newOwner);
    }

    /// @notice Tests that only the pending owner can accept the ownership transfer.
    function testCannotAcceptOwnershipAsNonPendingOwner(address newOwner, address notNewOwner)
        public
    {
        // Setup
        vm.assume(newOwner != nullAddress);
        vm.assume(notNewOwner != newOwner);
        lookupTable.transferOwnership(newOwner);
        vm.expectRevert("Ownable2Step: caller is not the new owner");
        vm.prank(notNewOwner);

        // Test
        lookupTable.acceptOwnership();
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
    function testCannotRenounceOwnershipAsOwner() public {
        // Setup
        bytes memory errorData =
            abi.encodeWithSelector(VerifierLookupTable.CannotRenounceOwnership.selector);
        vm.expectRevert(errorData);

        // Test
        lookupTable.renounceOwnership();
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
