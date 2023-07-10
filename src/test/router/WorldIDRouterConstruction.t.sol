// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {WorldIDRouterTest} from "./WorldIDRouterTest.sol";

import {IWorldID} from "../../interfaces/IWorldID.sol";

import {WorldIDRouter as Router} from "../../WorldIDRouter.sol";
import {WorldIDRouterImplV1 as RouterImpl} from "../../WorldIDRouterImplV1.sol";

/// @title World ID Router Construction Tests
/// @notice Contains tests for the WorldID router
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDRouterConstruction is WorldIDRouterTest {
    /// @notice Taken from Initializable.sol
    event Initialized(uint8 version);

    /// @notice Tests if it is possible to construct a router without a delegate.
    function testCanConstructRouterWithNoDelegate() public {
        // Setup
        address dummy = address(this);
        bytes memory data = new bytes(0x0);

        // Test
        router = new Router(dummy, data);
    }

    /// @notice Tests that it is possible to properly construct and initialise a router.
    function testCanConstructRouterWithDelegate(IWorldID dummy) public {
        // Setup
        vm.expectEmit(true, true, true, true);
        emit Initialized(1);
        routerImpl = new RouterImpl();
        bytes memory callData = abi.encodeCall(RouterImpl.initialize, (dummy));

        // Test
        router = new Router(address(routerImpl), callData);
    }
}
