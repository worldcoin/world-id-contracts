// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {WorldIDRouterTest} from "./WorldIDRouterTest.sol";

import {CheckInitialized} from "../../utils/CheckInitialized.sol";
import {Ownable2StepUpgradeable} from "contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {OwnableUpgradeable} from "contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {WorldIDImpl} from "../../abstract/WorldIDImpl.sol";

import {WorldIDRouter as Router} from "../../WorldIDRouter.sol";
import {WorldIDRouterImplV1 as RouterImpl} from "../../WorldIDRouterImplV1.sol";

/// @title World ID Router Ownership Management Tests
/// @notice Contains tests for the WorldID router
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDRouterOwnershipManagement is WorldIDRouterTest {
    /// @notice Taken from OwnableUpgradable.sol
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @notice Checks that it is possible to get the owner, and that the owner is correctly
    ///         initialised.
    function testHasOwner() public {
        // Setup
        bytes memory callData = abi.encodeCall(OwnableUpgradeable.owner, ());
        bytes memory expectedReturn = abi.encode(address(this));

        // Test
        assertCallSucceedsOn(routerAddress, callData, expectedReturn);
    }

    /// @notice Tests that it is possible to transfer ownership of the contract.
    function testTransferOwner(address newOwner) public {
        // Setup
        vm.assume(newOwner != nullAddress);
        bytes memory transferCallData =
            abi.encodeCall(Ownable2StepUpgradeable.transferOwnership, (newOwner));
        bytes memory ownerCallData = abi.encodeCall(OwnableUpgradeable.owner, ());
        bytes memory pendingOwnerCallData = abi.encodeCall(Ownable2StepUpgradeable.pendingOwner, ());
        bytes memory acceptOwnerCallData =
            abi.encodeCall(Ownable2StepUpgradeable.acceptOwnership, ());

        // Test
        assertCallSucceedsOn(routerAddress, transferCallData, new bytes(0x0));
        assertCallSucceedsOn(routerAddress, pendingOwnerCallData, abi.encode(newOwner));
        assertCallSucceedsOn(routerAddress, ownerCallData, abi.encode(thisAddress));

        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(thisAddress, newOwner);

        vm.prank(newOwner);
        assertCallSucceedsOn(routerAddress, acceptOwnerCallData, new bytes(0x0));
        assertCallSucceedsOn(routerAddress, ownerCallData, abi.encode(newOwner));
    }

    /// @notice Tests that only the pending owner can accept the ownership transfer.
    function testCannotAcceptOwnershipAsNonPendingOwner(address newOwner, address notNewOwner)
        public
    {
        // Setup
        vm.assume(newOwner != nullAddress);
        vm.assume(notNewOwner != newOwner);
        bytes memory callData =
            abi.encodeCall(Ownable2StepUpgradeable.transferOwnership, (newOwner));
        bytes memory acceptCallData = abi.encodeCall(Ownable2StepUpgradeable.acceptOwnership, ());
        bytes memory expectedError = encodeStringRevert("Ownable2Step: caller is not the new owner");
        assertCallSucceedsOn(routerAddress, callData);
        vm.prank(notNewOwner);

        // Test
        assertCallFailsOn(routerAddress, acceptCallData, expectedError);
    }

    /// @notice Ensures that it is impossible to transfer ownership without being the owner.
    function testCannotTransferOwnerIfNotOwner(address naughty, address newOwner) public {
        // Setup
        vm.assume(naughty != thisAddress && newOwner != nullAddress);
        bytes memory callData = abi.encodeCall(OwnableUpgradeable.transferOwnership, (newOwner));
        bytes memory expectedReturn = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(naughty);

        // Test
        assertCallFailsOn(routerAddress, callData, expectedReturn);
    }

    /// @notice Tests that it is impossible to renounce ownership, even as the owner.
    function testCannotRenounceOwnershipAsOwner() public {
        // Setup
        bytes memory renounceData = abi.encodeCall(OwnableUpgradeable.renounceOwnership, ());
        bytes memory errorData =
            abi.encodeWithSelector(WorldIDImpl.CannotRenounceOwnership.selector);

        // Test
        assertCallFailsOn(routerAddress, renounceData, errorData);
    }

    /// @notice Ensures that ownership cannot be renounced by anybody other than the owner.
    function testCannotRenounceOwnershipIfNotOwner(address naughty) public {
        // Setup
        vm.assume(naughty != thisAddress && naughty != nullAddress);
        bytes memory callData = abi.encodeCall(OwnableUpgradeable.renounceOwnership, ());
        bytes memory returnData = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(naughty);

        // Test
        assertCallFailsOn(routerAddress, callData, returnData);
    }
}
