// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {SimpleVerify} from "./mock/SimpleVerifier.sol";

import {WorldIDIdentityManagerImplV1 as ManagerImpl} from "../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Data Querying Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerDataQuery is WorldIDIdentityManagerTest {
    /// @notice Tests whether it is possible to query accurate information about the current root.
    function testQueryCurrentRoot(uint128 newPreRoot) public {
        // Setup
        makeNewIdentityManager(newPreRoot, verifier, isStateBridgeEnabled, stateBridgeProxy);
        bytes memory callData = abi.encodeCall(ManagerImpl.queryRoot, newPreRoot);
        bytes memory returnData = abi.encode(ManagerImpl.RootInfo(newPreRoot, 0, true));

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Tests whether it is possible to query accurate information about an arbitrary root.
    function testQueryOlderRoot(
        uint128[8] memory prf,
        uint32 newStartIndex,
        uint128 newPreRoot,
        uint128 newPostRoot,
        uint128[] memory identities
    ) public {
        // Setup
        vm.assume(SimpleVerify.isValidInput(uint256(prf[0])));
        vm.assume(newPreRoot != newPostRoot);
        makeNewIdentityManager(newPreRoot, verifier, isStateBridgeEnabled, stateBridgeProxy);
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareInsertIdentitiesTestCase(identities, prf);
        bytes memory registerCallData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (actualProof, newPreRoot, newStartIndex, preparedIdents, newPostRoot)
        );

        // expect event that state root was sent to state bridge
        vm.expectEmit(true, true, true, true);
        emit StateRootSentMultichain(newPostRoot);

        assertCallSucceedsOn(identityManagerAddress, registerCallData);
        bytes memory queryCallData = abi.encodeCall(ManagerImpl.queryRoot, (newPreRoot));
        bytes memory returnData =
            abi.encode(ManagerImpl.RootInfo(newPreRoot, uint128(block.timestamp), true));

        // Test
        assertCallSucceedsOn(identityManagerAddress, queryCallData, returnData);
    }

    /// @notice Tests whether it is possible to query accurate information about an expired root.
    function testQueryExpiredRoot(
        uint128[8] memory prf,
        uint32 newStartIndex,
        uint128 newPreRoot,
        uint128 newPostRoot,
        uint128[] memory identities
    ) public {
        // Setup
        vm.assume(newPreRoot != newPostRoot);
        vm.assume(SimpleVerify.isValidInput(uint256(prf[0])));
        makeNewIdentityManager(newPreRoot, verifier, isStateBridgeEnabled, stateBridgeProxy);
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareInsertIdentitiesTestCase(identities, prf);
        uint256 originalTimestamp = block.timestamp;
        bytes memory registerCallData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (actualProof, newPreRoot, newStartIndex, preparedIdents, newPostRoot)
        );

        // expect event that state root was sent to state bridge
        vm.expectEmit(true, true, true, true);
        emit StateRootSentMultichain(newPostRoot);

        assertCallSucceedsOn(identityManagerAddress, registerCallData);
        bytes memory queryCallData = abi.encodeCall(ManagerImpl.queryRoot, (newPreRoot));
        bytes memory returnData =
            abi.encode(ManagerImpl.RootInfo(newPreRoot, uint128(originalTimestamp), false));
        vm.warp(originalTimestamp + 2 hours); // Force preRoot to expire

        // Test
        assertCallSucceedsOn(identityManagerAddress, queryCallData, returnData);

        // Cleanup
        vm.warp(originalTimestamp);
    }

    /// @notice Checks that we get `NO_SUCH_ROOT` back when we query for information about an
    ///         invalid root.
    function testQueryInvalidRoot(uint256 badRoot) public {
        // Setup
        vm.assume(badRoot != initialRoot);
        bytes memory callData = abi.encodeCall(ManagerImpl.queryRoot, badRoot);
        bytes memory returnData = abi.encode(managerImpl.NO_SUCH_ROOT());

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Checks that the root can only be queried if behind the proxy.
    function testCannotQueryRootIfNotViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.queryRoot(initialRoot);
    }

    /// @notice Checks that it is possible to get the latest root from the contract.
    function testCanGetLatestRoot(uint256 actualRoot) public {
        // Setup
        makeNewIdentityManager(actualRoot, verifier, isStateBridgeEnabled, stateBridgeProxy);
        bytes memory callData = abi.encodeCall(ManagerImpl.latestRoot, ());
        bytes memory returnData = abi.encode(actualRoot);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Checks that the latest root can only be obtained if behind the proxy.
    function testCannotGetLatestRootIfNotViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.latestRoot();
    }
}
