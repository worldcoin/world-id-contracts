// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {WorldIDRouterTest} from "./WorldIDRouterTest.sol";

import {IWorldID} from "../../interfaces/IWorldID.sol";

import {WorldIDRouter as Router} from "../../WorldIDRouter.sol";
import {WorldIDRouterImplV1 as RouterImpl} from "../../WorldIDRouterImplV1.sol";

/// @title World ID Router Routing Tests
/// @notice Contains tests for the WorldID router
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDRouterRouting is WorldIDRouterTest {
    // Taken from WorldIDRouterImplV1.sol
    event GroupAdded(uint256 indexed groupId, address indexed identityManager);
    event GroupUpdated(
        uint256 indexed groupId,
        address indexed oldIdentityManager,
        address indexed newIdentityManager
    );
    event GroupDisabled(uint256 indexed groupId);

    ///////////////////////////////////////////////////////////////////////////////
    ///                          GROUP ROUTING TESTS                            ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Checks that it is possible to get a route for a group that exists.
    function testCanGetRouteForValidGroup(uint8 groupId, address targetAddress, address caller)
        public
    {
        // Setup
        vm.assume(caller != nullAddress);
        vm.assume(targetAddress != nullAddress);

        IWorldID targetManager = IWorldID(targetAddress);
        for (uint256 i = 1; i <= groupId; ++i) {
            IWorldID target = nullManager;
            if (i == groupId) {
                target = IWorldID(targetAddress);
            }
            bytes memory setupCallData = abi.encodeCall(RouterImpl.addGroup, (i, target));
            assertCallSucceedsOn(routerAddress, setupCallData);
        }
        bytes memory callData = abi.encodeCall(RouterImpl.routeFor, (groupId));
        IWorldID expectedReturnAddress = targetManager;
        if (groupId == 0) {
            expectedReturnAddress = thisWorldID;
        }
        bytes memory expectedReturn = abi.encode(expectedReturnAddress);
        vm.prank(caller);

        // Test
        assertCallSucceedsOn(routerAddress, callData, expectedReturn);
    }

    /// @notice Ensures that requesting a route reverts if the request is made for a non-existent
    ///         group.
    function testShouldRevertOnRouteRequestForMissingGroup(uint256 groupId) public {
        // Setup
        vm.assume(groupId > 0);
        bytes memory callData = abi.encodeCall(RouterImpl.routeFor, (groupId));
        bytes memory expectedError =
            abi.encodeWithSelector(RouterImpl.NoSuchGroup.selector, groupId);

        // Test
        assertCallFailsOn(routerAddress, callData, expectedError);
    }

    /// @notice Ensures that it reverts when a group has been disabled.
    function testShouldRevertOnDisabledGroup(uint8 groupId) public {
        // Setup
        vm.assume(groupId != 0);
        for (uint256 i = 1; i <= groupId; ++i) {
            bytes memory setupCallData = abi.encodeCall(RouterImpl.addGroup, (i, nullManager));
            assertCallSucceedsOn(routerAddress, setupCallData);
        }
        bytes memory callData = abi.encodeCall(RouterImpl.routeFor, (groupId));
        bytes memory expectedError = abi.encodeWithSelector(RouterImpl.GroupIsDisabled.selector);

        // Test
        assertCallFailsOn(routerAddress, callData, expectedError);
    }

    /// @notice Ensures that it is impossible to get a route except from via the proxy.
    function testcannotGetRouteUnlessViaProxy(uint256 groupId) public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        routerImpl.routeFor(groupId);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                           GROUP ADDING TESTS                            ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures that groups can be added to the router.
    function testCanAddGroup(IWorldID target) public {
        // Setup
        vm.assume(target != nullManager);
        bytes memory callData = abi.encodeCall(RouterImpl.addGroup, (1, target));
        bytes memory checkCallData = abi.encodeCall(RouterImpl.routeFor, (1));
        bytes memory expectedCheckReturn = abi.encode(target);

        vm.expectEmit(true, true, true, true);
        emit GroupAdded(1, address(target));

        // Test
        assertCallSucceedsOn(routerAddress, callData);
        assertCallSucceedsOn(routerAddress, checkCallData, expectedCheckReturn);
    }

    /// @notice Ensures that duplicate groups cannot be added.
    function testCannotAddDuplicateGroup(IWorldID addr) public {
        // Setup
        bytes memory callData = abi.encodeCall(RouterImpl.addGroup, (0, addr));
        bytes memory expectedError = abi.encodeWithSelector(RouterImpl.DuplicateGroup.selector, 0);

        // Test
        assertCallFailsOn(routerAddress, callData, expectedError);
    }

    /// @notice Ensures that groups can't be added unless they are done in sequence.
    function testCannotAddGroupUnlessNumbersSequential(uint256 groupNumber, IWorldID addr) public {
        // Setup
        vm.assume(groupNumber > 1);
        bytes memory callData = abi.encodeCall(RouterImpl.addGroup, (groupNumber, addr));
        bytes memory expectedError =
            abi.encodeWithSelector(RouterImpl.NonSequentialGroup.selector, groupNumber);

        // Test
        assertCallFailsOn(routerAddress, callData, expectedError);
    }

    /// @notice Ensures that groups can't be added except by the owner.
    function testCannotAddGroupUnlessOwner(address naughty, IWorldID worldID) public {
        // Setup
        vm.assume(naughty != thisAddress && naughty != nullAddress);
        bytes memory callData = abi.encodeCall(RouterImpl.addGroup, (0, worldID));
        bytes memory expectedError = encodeStringRevert("Ownable: caller is not the owner");

        vm.prank(naughty);

        // Test
        assertCallFailsOn(routerAddress, callData, expectedError);
    }

    /// @notice Ensures that a group cannot be added unless via the proxy.
    function testCannotAddGroupUnlessViaProxy(IWorldID group) public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        routerImpl.addGroup(0, group);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                          GROUP UPDATING TESTS                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures that it is possible to update the routing for a group.
    function testCanUpdateGroup(uint8 groupId, IWorldID newTarget) public {
        // Setup
        vm.assume(newTarget != nullManager);
        for (uint256 i = 1; i <= groupId; ++i) {
            bytes memory setupCallData = abi.encodeCall(RouterImpl.addGroup, (i, nullManager));
            assertCallSucceedsOn(routerAddress, setupCallData);
        }
        bytes memory callData =
            abi.encodeCall(RouterImpl.updateGroup, (uint256(groupId), newTarget));
        IWorldID returnAddress = nullManager;
        if (groupId == 0) {
            returnAddress = thisWorldID;
        }
        bytes memory expectedReturn = abi.encode(returnAddress);
        bytes memory checkCallData = abi.encodeCall(RouterImpl.routeFor, (uint256(groupId)));
        bytes memory checkExpectedReturn = abi.encode(newTarget);

        vm.expectEmit(true, true, true, true);
        emit GroupUpdated(uint256(groupId), address(returnAddress), address(newTarget));

        // Test
        assertCallSucceedsOn(routerAddress, callData, expectedReturn);
        assertCallSucceedsOn(routerAddress, checkCallData, checkExpectedReturn);
    }

    /// @notice Ensures that it is not possible to update a group that does not exist.
    function testShouldRevertOnUpdatingNonexistentGroup(uint256 groupId, IWorldID newTarget)
        public
    {
        // Setup
        vm.assume(groupId != 0);
        bytes memory callData = abi.encodeCall(RouterImpl.updateGroup, (groupId, newTarget));
        bytes memory expectedError =
            abi.encodeWithSelector(RouterImpl.NoSuchGroup.selector, groupId);

        // Test
        assertCallFailsOn(routerAddress, callData, expectedError);
    }

    /// @notice Ensures that a group cannot be updated except by the owner.
    function testCannotUpdateGroupUnlessOwner(address naughty) public {
        // Setup
        vm.assume(naughty != thisAddress);
        bytes memory callData = abi.encodeCall(RouterImpl.updateGroup, (0, nullManager));
        bytes memory expectedError = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(naughty);

        // Test
        assertCallFailsOn(routerAddress, callData, expectedError);
    }

    /// @notice Ensures that a group cannot be updated except via the proxy.
    function testCannotUpdateGroupUnlessViaProxy(uint256 groupId, IWorldID newTarget) public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        routerImpl.updateGroup(groupId, newTarget);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                           GROUP DISABLE TESTS                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures that it is possible to disable routing for a group.
    function testCanDisableGroup(uint8 groupId, IWorldID newTarget) public {
        // Setup
        vm.assume(newTarget != nullManager);
        for (uint256 i = 1; i <= groupId; ++i) {
            bytes memory setupCallData = abi.encodeCall(RouterImpl.addGroup, (i, newTarget));
            assertCallSucceedsOn(routerAddress, setupCallData);
        }
        bytes memory callData = abi.encodeCall(RouterImpl.disableGroup, (uint256(groupId)));
        IWorldID returnAddress = newTarget;
        if (groupId == 0) {
            returnAddress = thisWorldID;
        }
        bytes memory expectedReturn = abi.encode(returnAddress);
        bytes memory checkCallData = abi.encodeCall(RouterImpl.routeFor, (uint256(groupId)));
        bytes memory checkExpectedError =
            abi.encodeWithSelector(RouterImpl.GroupIsDisabled.selector);

        vm.expectEmit(true, true, true, true);
        emit GroupDisabled(groupId);

        // Test
        assertCallSucceedsOn(routerAddress, callData, expectedReturn);
        assertCallFailsOn(routerAddress, checkCallData, checkExpectedError);
    }

    /// @notice Ensures that it is not possible to disable a group that does not exist.
    function testShouldRevertOnDisablingNonexistentGroup(uint256 groupId) public {
        // Setup
        vm.assume(groupId != 0);
        bytes memory callData = abi.encodeCall(RouterImpl.disableGroup, (groupId));
        bytes memory expectedError =
            abi.encodeWithSelector(RouterImpl.NoSuchGroup.selector, groupId);

        // Test
        assertCallFailsOn(routerAddress, callData, expectedError);
    }

    /// @notice Ensures that a group cannot be disabled except by the owner.
    function testCannotDisableGroupUnlessOwner(address naughty) public {
        // Setup
        vm.assume(naughty != thisAddress);
        bytes memory callData = abi.encodeCall(RouterImpl.disableGroup, (0));
        bytes memory expectedError = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(naughty);

        // Test
        assertCallFailsOn(routerAddress, callData, expectedError);
    }

    /// @notice Ensures that a group cannot be disabled except via the proxy.
    function testCannotDisableGroupUnlessViaProxy(uint256 groupId) public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        routerImpl.disableGroup(groupId);
    }
}
