// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {WorldIDRouterTest} from "./WorldIDRouterTest.sol";

import {WorldIDRouter as Router} from "../../WorldIDRouter.sol";
import {WorldIDRouterImplV1 as RouterImpl} from "../../WorldIDRouterImplV1.sol";

/// @title World ID Router Data Querying Tests
/// @notice Contains tests for the WorldID router
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDRouterDataQuery is WorldIDRouterTest {
    /// @notice Checks that it is possible to get the group count from the router.
    function testCanGetGroupCount() public {
        // Setup
        bytes memory callData = abi.encodeCall(RouterImpl.groupCount, ());
        bytes memory expectedReturn = abi.encode(1);

        // Test
        assertCallSucceedsOn(routerAddress, callData, expectedReturn);
    }

    /// @notice Ensures that it is not possible to get the group count unless via the proxy.
    function testCannotGetGroupCountUnlessViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        routerImpl.groupCount();
    }
}
