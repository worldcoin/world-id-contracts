// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";

import {CheckInitialized} from "../../utils/CheckInitialized.sol";
import {OwnableUpgradeable} from "contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Ownable2StepUpgradeable} from "contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {SemaphoreVerifier} from "semaphore/base/SemaphoreVerifier.sol";
import {SimpleVerifier, SimpleVerify} from "../mock/SimpleVerifier.sol";
import {UUPSUpgradeable} from "contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Verifier as TreeVerifier} from "src/test/InsertionTreeVerifier16.sol";
import {WorldIDIdentityManagerImplMock} from "../mock/WorldIDIdentityManagerImplMock.sol";
import {WorldIDImpl} from "../../abstract/WorldIDImpl.sol";

import {WorldIDIdentityManager as IdentityManager} from "../../WorldIDIdentityManager.sol";
import {WorldIDIdentityManagerImplV2 as ManagerImpl} from "../../WorldIDIdentityManagerImplV2.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImplV1} from "../../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Ownership Management Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerOwnershipManagement is WorldIDIdentityManagerTest {
    /// @notice Taken from OwnableUpgradable.sol
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @notice Taken from WorldIDIdentityManagementImplV1.sol
    event IdentityOperatorChanged(address indexed oldOperator, address indexed newOperator);

    /// @notice Checks that it is possible to get the owner, and that the owner is correctly
    ///         initialised.
    function testHasOwner() public {
        // Setup
        bytes memory callData = abi.encodeCall(OwnableUpgradeable.owner, ());
        bytes memory expectedReturn = abi.encode(address(this));

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, expectedReturn);
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
        assertCallSucceedsOn(identityManagerAddress, transferCallData, new bytes(0x0));
        assertCallSucceedsOn(identityManagerAddress, pendingOwnerCallData, abi.encode(newOwner));
        assertCallSucceedsOn(identityManagerAddress, ownerCallData, abi.encode(thisAddress));

        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(thisAddress, newOwner);

        vm.prank(newOwner);
        assertCallSucceedsOn(identityManagerAddress, acceptOwnerCallData, new bytes(0x0));
        assertCallSucceedsOn(identityManagerAddress, ownerCallData, abi.encode(newOwner));
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
        assertCallSucceedsOn(identityManagerAddress, callData);
        vm.prank(notNewOwner);

        // Test
        assertCallFailsOn(identityManagerAddress, acceptCallData, expectedError);
    }

    /// @notice Ensures that it is impossible to transfer ownership without being the owner.
    function testCannotTransferOwnerIfNotOwner(address naughty, address newOwner) public {
        // Setup
        vm.assume(naughty != thisAddress && newOwner != nullAddress);
        bytes memory callData =
            abi.encodeCall(Ownable2StepUpgradeable.transferOwnership, (newOwner));
        bytes memory expectedReturn = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(naughty);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedReturn);
    }

    /// @notice Tests that it is impossible to renounce ownership, even as the owner.
    function testCannotRenounceOwnershipAsOwner() public {
        // Setup
        bytes memory renounceData = abi.encodeCall(OwnableUpgradeable.renounceOwnership, ());
        bytes memory errorData =
            abi.encodeWithSelector(WorldIDImpl.CannotRenounceOwnership.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, renounceData, errorData);
    }

    /// @notice Ensures that ownership cannot be renounced by anybody other than the owner.
    function testCannotRenounceOwnershipIfNotOwner(address naughty) public {
        // Setup
        vm.assume(naughty != thisAddress && naughty != nullAddress);
        bytes memory callData = abi.encodeCall(OwnableUpgradeable.renounceOwnership, ());
        bytes memory returnData = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(naughty);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Enures that the contract has a notion of identity operator.
    function testHasIdentityOperator() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImplV1.identityOperator, ());
        bytes memory returnData = abi.encode(thisAddress);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Ensures that the identity operator address cannot be accessed unless it is done via
    ///         the proxy.
    function testCannotGetIdentityOperatorWithoutProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImplV2.identityOperator();
    }

    /// @notice Ensures that it is possible for the owner to set the address of the identity
    ///         operator.
    function testCanSetIdentityOperatorAsOwner(address newOperator) public {
        // Setup
        vm.assume(newOperator != thisAddress);
        bytes memory callData = abi.encodeCall(ManagerImplV1.setIdentityOperator, (newOperator));
        bytes memory returnData = abi.encode(thisAddress);
        bytes memory checkCallData1 = abi.encodeCall(ManagerImplV1.identityOperator, ());
        bytes memory checkCallReturn1 = abi.encode(newOperator);
        bytes memory checkCallData2 = abi.encodeCall(OwnableUpgradeable.owner, ());
        bytes memory checkCallReturn2 = abi.encode(thisAddress);
        vm.expectEmit(true, true, true, true);
        emit IdentityOperatorChanged(thisAddress, newOperator);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
        assertCallSucceedsOn(identityManagerAddress, checkCallData1, checkCallReturn1);
        assertCallSucceedsOn(identityManagerAddress, checkCallData2, checkCallReturn2);
    }

    /// @notice Ensures that it is not possible for a non-owner to set the address of the identity
    ///         operator
    function testCannotSetIdentityOperatorAsNonOwner(address newOperator, address naughty) public {
        // Setup
        vm.assume(naughty != nullAddress && naughty != thisAddress);
        bytes memory callData = abi.encodeCall(ManagerImplV1.setIdentityOperator, (newOperator));
        bytes memory errorData = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(naughty);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Ensures that it is not possible to set the identity operator address unless it is
    ///         done via the proxy.
    function testCannotSetIdentityOperatorWithoutProxy(address newOperator) public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImplV2.setIdentityOperator(newOperator);
    }
}
