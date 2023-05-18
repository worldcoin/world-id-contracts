// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {IBridge} from "../../interfaces/IBridge.sol";
import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";
import {TypeConverter as TC} from "../utils/TypeConverter.sol";
import {Verifier as TreeVerifier} from "../mock/TreeVerifier.sol";
import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

import {WorldIDIdentityManagerImplV1 as ManagerImpl} from "../../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager State Bridge Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerStateBridge is WorldIDIdentityManagerTest {
    /// @notice Taken from WorldIDIdentityManagerImplV1.sol
    event DependencyUpdated(
        ManagerImpl.Dependency indexed kind, address indexed oldAddress, address indexed newAddress
    );
    event StateBridgeStateChange(bool indexed isEnabled);

    /// @notice Tests that it is possible to upgrade `stateBridge` to a new implementation.
    function testCanUpgradeStateBridge(IBridge newStateBridge) public {
        // Setup
        address stateBridgeAddress = address(newStateBridge);
        vm.assume(stateBridgeAddress != nullAddress && stateBridgeAddress != thisAddress);
        bytes memory callData = abi.encodeCall(ManagerImpl.setStateBridge, (newStateBridge));
        vm.expectEmit(true, false, true, true);
        emit DependencyUpdated(ManagerImpl.Dependency.StateBridge, nullAddress, stateBridgeAddress);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, new bytes(0x0));
    }

    /// @notice Tests that it is possible to disable the `stateBridge`.
    function testCanDisableStateBridgeFunctionality() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImpl.disableStateBridge, ());
        (VerifierLookupTable insertVerifiers, VerifierLookupTable updateVerifiers) =
            makeVerifierLookupTables(TC.makeDynArray([40]));
        insertVerifiers.addVerifier(identityCommitmentsSize, new TreeVerifier());
        makeNewIdentityManager(
            treeDepth,
            preRoot,
            insertVerifiers,
            updateVerifiers,
            semaphoreVerifier,
            isStateBridgeEnabled,
            stateBridge
        );
        bytes memory registerCallData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (proof, preRoot, startIndex, identityCommitments, postRoot, opGasLimit)
        );
        bytes memory latestRootCallData = abi.encodeCall(ManagerImpl.latestRoot, ());
        bytes memory queryRootCallData = abi.encodeCall(ManagerImpl.queryRoot, (postRoot));

        // expect event that state root was sent to state bridge
        vm.expectEmit(true, true, true, true);
        emit StateRootSentMultichain(postRoot);
        vm.expectEmit(true, true, true, true);
        emit StateBridgeStateChange(false);

        // Test
        assertCallSucceedsOn(identityManagerAddress, registerCallData);
        assertCallSucceedsOn(identityManagerAddress, latestRootCallData, abi.encode(postRoot));
        assertCallSucceedsOn(
            identityManagerAddress,
            queryRootCallData,
            abi.encode(ManagerImpl.RootInfo(postRoot, 0, true))
        );
        assertCallSucceedsOn(identityManagerAddress, callData, new bytes(0x0));
    }

    /// @notice Tests that it is not possible to upgrade `stateBridge` to the 0x0 address.
    function testCannotUpgradeStateBridgeToZeroAddress() public {
        // address used to disable the state bridge functionality
        address zeroAddress = address(0x0);
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImpl.setStateBridge, (IBridge(zeroAddress)));

        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.InvalidStateBridgeAddress.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `setStateBridge` as a non-owner.
    function testCannotUpdateStateBridgeAsNonOwner(address nonManager) public {
        // Setup
        vm.assume(nonManager != address(this) && nonManager != address(0x0));

        bytes memory callData = abi.encodeCall(ManagerImpl.setStateBridge, (IBridge(address(0x1))));

        bytes memory errorData = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(nonManager);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Checks that the state bridge can be enabled if it is disabled.
    function testCanEnableStateBridgeIfDisabled() public {
        // Setup
        makeNewIdentityManager(
            treeDepth,
            preRoot,
            defaultInsertVerifiers,
            defaultUpdateVerifiers,
            semaphoreVerifier,
            false,
            stateBridge
        );
        bytes memory callData = abi.encodeCall(ManagerImpl.enableStateBridge, ());
        vm.expectEmit(true, true, true, true);
        emit StateBridgeStateChange(true);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, new bytes(0x0));
    }

    /// @notice Tests that it is impossible to enable the `stateBridge` if it is already
    ///         enabled.
    function testCannotEnableStateBridgeIfAlreadyEnabled() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImpl.enableStateBridge, ());

        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.StateBridgeAlreadyEnabled.selector);
        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that it is impossible to disabled the `stateBridge` if it is already
    ///         disabled.
    function testCannotDisableStateBridgeIfAlreadyDisabled() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImpl.disableStateBridge, ());

        // disable state bridge
        assertCallSucceedsOn(identityManagerAddress, callData, new bytes(0x0));

        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.StateBridgeAlreadyDisabled.selector);
        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }
}
