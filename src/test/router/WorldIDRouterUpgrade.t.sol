// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {WorldIDRouterTest} from "./WorldIDRouterTest.sol";

import {IWorldID} from "../../interfaces/IWorldID.sol";

import {UUPSUpgradeable} from "contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {WorldIDRouterImplMock} from "../mock/WorldIDRouterImplMock.sol";

import {WorldIDRouterImplV1 as RouterImpl} from "../../WorldIDRouterImplV1.sol";

/// @title World ID Router Upgrade Tests
/// @notice Contains tests for the WorldID router
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDRouterUpgrade is WorldIDRouterTest {
    /// @notice Tests that it is possible to upgrade to a new implementation.
    function testCanUpgradeImplementationWithoutCall() public {
        // Setup
        WorldIDRouterImplMock mockUpgrade = new WorldIDRouterImplMock();
        bytes memory upgradeCall = abi.encodeCall(UUPSUpgradeable.upgradeTo, (address(mockUpgrade)));

        // Test
        assertCallSucceedsOn(routerAddress, upgradeCall, new bytes(0x0));
    }

    /// @notice Tests that it is possible to upgrade to a new implementation and call a function on
    ///         that new implementation in the same transaction.
    function testCanUpgradeImplementationWithCall() public {
        // Setup
        WorldIDRouterImplMock mockUpgrade = new WorldIDRouterImplMock();
        bytes memory initCall = abi.encodeCall(WorldIDRouterImplMock.initialize, (320));
        bytes memory upgradeCall =
            abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (address(mockUpgrade), initCall));

        // Test
        assertCallSucceedsOn(routerAddress, upgradeCall, new bytes(0x0));
    }

    /// @notice Tests that an upgrade cannot be performed by anybody other than the manager.
    function testCannotUpgradeUnlessManager(address naughty) public {
        // Setup
        vm.assume(naughty != address(this) && naughty != address(0x0));
        WorldIDRouterImplMock mockUpgrade = new WorldIDRouterImplMock();
        bytes memory initCall = abi.encodeCall(WorldIDRouterImplMock.initialize, (320));
        bytes memory upgradeCall =
            abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (address(mockUpgrade), initCall));
        vm.prank(naughty);

        // Test
        assertCallFailsOn(
            routerAddress, upgradeCall, encodeStringRevert("Ownable: caller is not the owner")
        );
    }

    /// @notice Tests that an upgrade cannot be performed unless done through the proxy.
    function testCannotUpgradeWithoutProxy(IWorldID dummy) public {
        // Setup
        WorldIDRouterImplMock mockUpgrade = new WorldIDRouterImplMock();
        address mockUpgradeAddress = address(mockUpgrade);
        bytes memory initCall = abi.encodeCall(RouterImpl.initialize, (dummy));
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        routerImpl.upgradeToAndCall(mockUpgradeAddress, initCall);
    }
}
