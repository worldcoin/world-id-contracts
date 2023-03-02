// SPDX-License-Identifier: MIT
pragma solidity 0.8.4;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {ITreeVerifier} from "../interfaces/ITreeVerifier.sol";
import {Verifier as TreeVerifier} from "./mock/TreeVerifier.sol";

import {WorldIDIdentityManagerImplV1 as ManagerImpl} from "../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager State Bridge Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerStateBridge is WorldIDIdentityManagerTest {
    /// @notice Tests that it is possible to upgrade `stateBridgeProxy` to a new implementation.
    function testCanUpgradeStateBridgeProxy(address newStateBridgeProxy) public {
        vm.assume(newStateBridgeProxy != address(0x0) && newStateBridgeProxy != address(this));
        // Setup
        bytes memory callData = abi.encodeWithSelector(
            ManagerImpl.setStateBridgeProxyAddress.selector, newStateBridgeProxy
        );

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, new bytes(0x0));
    }

    /// @notice Tests that it is possible to disable the `stateBridgeProxy`.
    function testCanDisableStateBridgeFunctionality() public {
        // Setup
        bytes memory callData = abi.encodeWithSelector(ManagerImpl.disableStateBridge.selector);
        ITreeVerifier actualVerifier = new TreeVerifier();
        makeNewIdentityManager(preRoot, actualVerifier, isStateBridgeEnabled, stateBridgeProxy);
        bytes memory registerCallData = abi.encodeWithSelector(
            ManagerImpl.registerIdentities.selector,
            proof,
            preRoot,
            startIndex,
            identityCommitments,
            postRoot
        );
        bytes memory latestRootCallData = abi.encodeWithSelector(ManagerImpl.latestRoot.selector);
        bytes memory queryRootCallData =
            abi.encodeWithSelector(ManagerImpl.queryRoot.selector, postRoot);

        // expect event that state root was sent to state bridge
        vm.expectEmit(true, true, true, true);
        emit StateRootSentMultichain(postRoot);

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

    /// @notice Tests that it is not possible to upgrade `stateBridgeProxy` to the 0x0 address.
    function testCannotUpgradeStateBridgeToZeroAddress() public {
        // address used to disable the state bridge functionality
        address zeroAddress = address(0x0);
        // Setup
        bytes memory callData =
            abi.encodeWithSelector(ManagerImpl.setStateBridgeProxyAddress.selector, zeroAddress);

        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.InvalidStateBridgeProxyAddress.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `setStateBridgeProxyAddress` as a non-owner.
    function testCannotUpdateStateBridgeAsNonOwner(address nonManager) public {
        // Setup
        vm.assume(nonManager != address(this) && nonManager != address(0x0));

        bytes memory callData =
            abi.encodeWithSelector(ManagerImpl.setStateBridgeProxyAddress.selector, address(0x1));

        bytes memory errorData = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(nonManager);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Checks that the state bridge can be enabled if it is disabled.
    function testCanEnableStateBridgeIfDisabled() public {
        // Setup
        makeNewIdentityManager(preRoot, verifier, false, stateBridgeProxy);
        bytes memory callData = abi.encodeWithSelector(ManagerImpl.enableStateBridge.selector);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, new bytes(0x0));
    }

    /// @notice Tests that it is impossible to enable the `stateBridgeProxy` if it is already
    ///         enabled.
    function testCannotEnableStateBridgeIfAlreadyEnabled() public {
        // Setup
        bytes memory callData = abi.encodeWithSelector(ManagerImpl.enableStateBridge.selector);

        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.StateBridgeAlreadyEnabled.selector);
        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that it is impossible to disabled the `stateBridgeProxy` if it is already
    ///         disabled.
    function testCannotDisableStateBridgeIfAlreadyDisabled() public {
        // Setup
        bytes memory callData = abi.encodeWithSelector(ManagerImpl.disableStateBridge.selector);

        // disable state bridge
        assertCallSucceedsOn(identityManagerAddress, callData, new bytes(0x0));

        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.StateBridgeAlreadyDisabled.selector);
        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }
}
