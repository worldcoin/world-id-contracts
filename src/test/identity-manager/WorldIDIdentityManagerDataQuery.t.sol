// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {SemaphoreTreeDepthValidator} from "../../utils/SemaphoreTreeDepthValidator.sol";
import {SimpleVerify} from "../mock/SimpleVerifier.sol";
import {TypeConverter as TC} from "../utils/TypeConverter.sol";
import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

import {WorldIDIdentityManagerImplV2 as ManagerImpl} from "../../WorldIDIdentityManagerImplV2.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImplV1} from "../../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Data Querying Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerDataQuery is WorldIDIdentityManagerTest {
    /// @notice Tests whether it is possible to query accurate information about the current root.
    function testQueryCurrentRoot(uint128 newPreRoot) public {
        // Setup
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            defaultInsertVerifiers,
            defaultDeletionVerifiers,
            defaultUpdateVerifiers,
            semaphoreVerifier
        );
        bytes memory callData = abi.encodeCall(ManagerImplV1.queryRoot, newPreRoot);
        bytes memory returnData = abi.encode(ManagerImplV1.RootInfo(newPreRoot, 0, true));

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
        vm.assume(identities.length <= 1000);
        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(TC.makeDynArray([identities.length]));
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareInsertIdentitiesTestCase(identities, prf);
        bytes memory registerCallData = abi.encodeCall(
            ManagerImplV1.registerIdentities,
            (actualProof, newPreRoot, newStartIndex, preparedIdents, newPostRoot)
        );

        assertCallSucceedsOn(identityManagerAddress, registerCallData);
        bytes memory queryCallData = abi.encodeCall(ManagerImplV1.queryRoot, (newPreRoot));
        bytes memory returnData =
            abi.encode(ManagerImplV1.RootInfo(newPreRoot, uint128(block.timestamp), true));

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
        vm.assume(identities.length <= 1000);
        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(TC.makeDynArray([identities.length]));
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareInsertIdentitiesTestCase(identities, prf);
        uint256 originalTimestamp = block.timestamp;
        bytes memory registerCallData = abi.encodeCall(
            ManagerImplV1.registerIdentities,
            (actualProof, newPreRoot, newStartIndex, preparedIdents, newPostRoot)
        );

        assertCallSucceedsOn(identityManagerAddress, registerCallData);
        bytes memory queryCallData = abi.encodeCall(ManagerImplV1.queryRoot, (newPreRoot));
        bytes memory returnData =
            abi.encode(ManagerImplV1.RootInfo(newPreRoot, uint128(originalTimestamp), false));
        vm.warp(originalTimestamp + 2 hours); // Force insertionPreRoot to expire

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
        bytes memory callData = abi.encodeCall(ManagerImplV1.queryRoot, badRoot);
        bytes memory returnData = abi.encode(managerImplV2.NO_SUCH_ROOT());

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Checks that the root can only be queried if behind the proxy.
    function testCannotQueryRootIfNotViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImplV2.queryRoot(initialRoot);
    }

    /// @notice Checks that it is possible to get the latest root from the contract.
    function testCanGetLatestRoot(uint256 actualRoot) public {
        // Setup
        makeNewIdentityManager(
            treeDepth,
            actualRoot,
            defaultInsertVerifiers,
            defaultDeletionVerifiers,
            defaultUpdateVerifiers,
            semaphoreVerifier
        );
        bytes memory callData = abi.encodeCall(ManagerImplV1.latestRoot, ());
        bytes memory returnData = abi.encode(actualRoot);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Checks that the latest root can only be obtained if behind the proxy.
    function testCannotGetLatestRootIfNotViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImplV2.latestRoot();
    }

    /// @notice Checks that it is possible to get the tree depth the contract was initialized with.
    function testCanGetTreeDepth(uint8 actualTreeDepth) public {
        // Setup
        vm.assume(SemaphoreTreeDepthValidator.validate(actualTreeDepth));
        makeNewIdentityManager(
            actualTreeDepth,
            insertionPreRoot,
            defaultInsertVerifiers,
            defaultDeletionVerifiers,
            defaultUpdateVerifiers,
            semaphoreVerifier
        );
        bytes memory callData = abi.encodeCall(ManagerImplV1.getTreeDepth, ());
        bytes memory returnData = abi.encode(actualTreeDepth);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }
}
