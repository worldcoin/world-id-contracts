// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {WorldIDRouterTest} from "./WorldIDRouterTest.sol";

import {CheckInitialized} from "../../utils/CheckInitialized.sol";
import {IWorldID} from "../../interfaces/IWorldID.sol";

import {WorldIDRouter as Router} from "../../WorldIDRouter.sol";
import {WorldIDRouterImplV1 as RouterImpl} from "../../WorldIDRouterImplV1.sol";

/// @title World ID Router Uninit Tests
/// @notice Contains tests for the WorldID router
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDRouterUninit is WorldIDRouterTest {
    /// @notice Ensures that a group cannot be added while the contract is not initialised.
    function testCannotAddGroupWhileUninit(IWorldID target) public {
        // Setup
        makeUninitRouter();
        bytes memory callData = abi.encodeCall(RouterImpl.addGroup, (target));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(routerAddress, callData, expectedError);
    }

    /// @notice Ensures that the group number cannot be queried while the contract is not
    ///         initialized.
    function testCannotGetGroupCountWhileUninit() public {
        // Setup
        makeUninitRouter();
        bytes memory callData = abi.encodeCall(RouterImpl.groupCount, ());
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(routerAddress, callData, expectedError);
    }

    /// @notice Ensures that routes cannot be queried while the contract is not initialized.
    function testCannotGetRouteForWhileUninit(uint256 groupId) public {
        // Setup
        makeUninitRouter();
        bytes memory callData = abi.encodeCall(RouterImpl.routeFor, (groupId));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(routerAddress, callData, expectedError);
    }

    /// @notice Ensures that routes cannot be updated while the contract is not initialized.
    function testCannotUpdateGroupWhileUninit(uint256 groupId, IWorldID newTarget) public {
        // Setup
        makeUninitRouter();
        bytes memory callData = abi.encodeCall(RouterImpl.updateGroup, (groupId, newTarget));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(routerAddress, callData, expectedError);
    }

    /// @notice Ensures that routes cannot be disabled while the contract is not initialized.
    function testCannotDisableGroupWhileUninit(uint256 groupId) public {
        // Setup
        makeUninitRouter();
        bytes memory callData = abi.encodeCall(RouterImpl.disableGroup, (groupId));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(routerAddress, callData, expectedError);
    }
}
