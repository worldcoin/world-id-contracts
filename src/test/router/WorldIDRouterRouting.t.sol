// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {WorldIDRouterTest} from "./WorldIDRouterTest.sol";

import {WorldIDRouter as Router} from "../../WorldIDRouter.sol";
import {WorldIDRouterImplV1 as RouterImpl} from "../../WorldIDRouterImplV1.sol";

/// @title World ID Router Routing Tests
/// @notice Contains tests for the WorldID router
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDRouterRouting is WorldIDRouterTest {
    ///////////////////////////////////////////////////////////////////////////////
    ///                           GROUP ADDING TESTS                            ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures that groups can be added to the router.
    function testCanAddGroup(address target) public {
        // Setup
        bytes memory callData = abi.encodeCall(RouterImpl.addGroup, (1, target));

        // Test
        assertCallSucceedsOn(routerAddress, callData);
    }

    /// @notice Ensures that duplicate groups cannot be added.
    function testCannotAddDuplicateGroup(address addr) public {
        // Setup
        bytes memory callData = abi.encodeCall(RouterImpl.addGroup, (0, addr));
        bytes memory expectedError = abi.encodeWithSelector(RouterImpl.DuplicateGroup.selector, 0);

        // Test
        assertCallFailsOn(routerAddress, callData, expectedError);
    }

    /// @notice Ensures that groups can't be added unless they are done in sequence.
    function testCannotAddGroupUnlessNumbersSequential(uint256 groupNumber, address addr) public {
        // Setup
        vm.assume(groupNumber > 1);
        bytes memory callData = abi.encodeCall(RouterImpl.addGroup, (groupNumber, addr));
        bytes memory expectedError =
            abi.encodeWithSelector(RouterImpl.NonSequentialGroup.selector, groupNumber);

        // Test
        assertCallFailsOn(routerAddress, callData, expectedError);
    }

    /// @notice Ensures that groups can't be added except by the owner.
    function testCannotAddGroupUnlessOwner(address naughty) public {
        // Setup
        vm.assume(naughty != thisAddress && naughty != nullAddress);
        bytes memory callData = abi.encodeCall(RouterImpl.addGroup, (0, naughty));
        bytes memory expectedError = encodeStringRevert("Ownable: caller is not the owner");

        vm.prank(naughty);

        // Test
        assertCallFailsOn(routerAddress, callData, expectedError);
    }

    /// @notice Ensures that a group cannot be added unless via the proxy.
    function testCannotAddGroupUnlessViaProxy(address group) public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        routerImpl.addGroup(0, group);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                          GROUP UPDATING TESTS                           ///
    ///////////////////////////////////////////////////////////////////////////////
}
