// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {WorldIDRouterTest} from "./WorldIDRouterTest.sol";

import {SimpleStateBridge} from "../mock/SimpleStateBridge.sol";
import {IWorldID} from "../../interfaces/IWorldID.sol";

import {WorldIDRouter as Router} from "../../WorldIDRouter.sol";
import {WorldIDRouterImplV1 as RouterImpl} from "../../WorldIDRouterImplV1.sol";

/// @title World ID Router State Bridge Tests
/// @notice Contains tests for the WorldID router that ensure that it works with a state bridge.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDRouterStateBridge is WorldIDRouterTest {
    /// @notice Ensures that the state bridge can be used as a group target.
    function testCanAddStateBridgeAsGroup(uint8 groupId, address caller) public {
        // Setup
        vm.assume(caller != nullAddress);
        vm.assume(groupId > 0);
        SimpleStateBridge stateBridge = new SimpleStateBridge();
        for (uint256 i = 1; i <= groupId; ++i) {
            IWorldID target = nullManager;
            if (i == groupId) {
                target = stateBridge;
            }
            bytes memory setupCallData = abi.encodeCall(RouterImpl.addGroup, (target));
            assertCallSucceedsOn(routerAddress, setupCallData);
        }
        bytes memory callData = abi.encodeCall(RouterImpl.routeFor, (groupId));
        bytes memory expectedReturn = abi.encode(stateBridge);
        vm.prank(caller);

        // Test
        assertCallSucceedsOn(routerAddress, callData, expectedReturn);
    }

    /// @notice Ensures that a state bridge can be used as the target when updating a group.
    function testCanUpdateStateBridgeAsGroup(uint8 groupId) public {
        // Setup
        SimpleStateBridge stateBridge = new SimpleStateBridge();
        for (uint256 i = 1; i <= groupId; ++i) {
            bytes memory setupCallData = abi.encodeCall(RouterImpl.addGroup, (nullManager));
            assertCallSucceedsOn(routerAddress, setupCallData);
        }
        IWorldID returnAddress = nullManager;
        if (groupId == 0) {
            returnAddress = thisWorldID;
        }
        bytes memory callData =
            abi.encodeCall(RouterImpl.updateGroup, (uint256(groupId), stateBridge));
        bytes memory expectedReturn = abi.encode(returnAddress);
        bytes memory checkCallData = abi.encodeCall(RouterImpl.routeFor, (uint256(groupId)));
        bytes memory checkExpectedReturn = abi.encode(stateBridge);

        // Test
        assertCallSucceedsOn(routerAddress, callData, expectedReturn);
        assertCallSucceedsOn(routerAddress, checkCallData, checkExpectedReturn);
    }

    // Taken from `SimpleStateBridge.sol`.
    event ProofVerified(uint256 indexed root);

    /// @notice Ensures that the state bridge is a valid proxy target for `verifyProof`.
    function testCanProxyVerifyProofForStateBridge(
        uint8 groupId,
        uint256 root,
        uint256 signalHash,
        uint256 nullifierHash,
        uint256 externalNullifierHash,
        uint256[8] calldata proof
    ) public {
        // Setup
        SimpleStateBridge stateBridge = new SimpleStateBridge();
        for (uint256 i = 1; i <= groupId; ++i) {
            bytes memory setupCallData = abi.encodeCall(RouterImpl.addGroup, (nullManager));
            assertCallSucceedsOn(routerAddress, setupCallData);
        }
        bytes memory finalSetupCallData =
            abi.encodeCall(RouterImpl.updateGroup, (groupId, stateBridge));
        assertCallSucceedsOn(routerAddress, finalSetupCallData);

        bytes memory callData = abi.encodeCall(
            RouterImpl.verifyProof,
            (root, uint256(groupId), signalHash, nullifierHash, externalNullifierHash, proof)
        );

        bool shouldSucceed = proof[0] % 2 == 0;

        bytes memory errorData = new bytes(0);
        if (!shouldSucceed) {
            errorData = abi.encodeWithSelector(SimpleStateBridge.ProofNotVerified.selector);
        }

        // Test
        if (shouldSucceed) {
            assertCallSucceedsOn(routerAddress, callData);
        } else {
            assertCallFailsOn(routerAddress, callData, errorData);
        }
    }
}
