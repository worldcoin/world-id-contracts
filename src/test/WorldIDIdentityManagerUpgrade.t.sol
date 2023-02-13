// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {UUPSUpgradeable} from "contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {WorldIDIdentityManagerImplMock} from "./mock/WorldIDIdentityManagerImplMock.sol";

import {WorldIDIdentityManagerImplV1 as ManagerImpl} from "../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Upgrade Test
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerUpdate is WorldIDIdentityManagerTest {
    /// @notice Tests that it is possible to upgrade to a new implementation.
    function testCanUpgradeImplementationWithoutCall() public {
        // Setup
        WorldIDIdentityManagerImplMock mockUpgrade = new WorldIDIdentityManagerImplMock();
        bytes memory upgradeCall = abi.encodeCall(UUPSUpgradeable.upgradeTo, (address(mockUpgrade)));

        // Test
        assertCallSucceedsOn(identityManagerAddress, upgradeCall, new bytes(0x0));
    }

    /// @notice Tests that it is possible to upgrade to a new implementation and call a function on
    ///         that new implementation in the same transaction.
    function testCanUpgradeImplementationWithCall() public {
        // Setup
        WorldIDIdentityManagerImplMock mockUpgrade = new WorldIDIdentityManagerImplMock();
        bytes memory initCall = abi.encodeCall(WorldIDIdentityManagerImplMock.initialize, (320));
        bytes memory upgradeCall =
            abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (address(mockUpgrade), initCall));

        // Test
        assertCallSucceedsOn(identityManagerAddress, upgradeCall, new bytes(0x0));
    }

    /// @notice Tests that an upgrade cannot be performed by anybody other than the manager.
    function testCannotUpgradeUnlessManager(address naughty) public {
        // Setup
        vm.assume(naughty != address(this) && naughty != address(0x0));
        WorldIDIdentityManagerImplMock mockUpgrade = new WorldIDIdentityManagerImplMock();
        bytes memory initCall = abi.encodeCall(WorldIDIdentityManagerImplMock.initialize, (320));
        bytes memory upgradeCall =
            abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (address(mockUpgrade), initCall));
        vm.prank(naughty);

        // Test
        assertCallFailsOn(
            identityManagerAddress,
            upgradeCall,
            encodeStringRevert("Ownable: caller is not the owner")
        );
    }

    /// @notice Tests that an upgrade cannot be performed unless done through the proxy.
    function testCannotUpgradeWithoutProxy() public {
        // Setup
        WorldIDIdentityManagerImplMock mockUpgrade = new WorldIDIdentityManagerImplMock();
        address mockUpgradeAddress = address(mockUpgrade);
        bytes memory initCall = abi.encodeCall(
            ManagerImpl.initialize, (initialRoot, verifier, isStateBridgeEnabled, stateBridgeProxy)
        );
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.upgradeToAndCall(mockUpgradeAddress, initCall);
    }
}
