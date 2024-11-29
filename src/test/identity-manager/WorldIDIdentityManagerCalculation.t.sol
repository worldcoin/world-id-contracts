// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {WorldIDIdentityManagerImplV2 as ManagerImpl} from "../../WorldIDIdentityManagerImplV2.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImplV1} from "../../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Calculation Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerCalculation is WorldIDIdentityManagerTest {
    /// @notice Tests whether it is possible to correctly calculate the `inputHash` to the merkle
    ///         tree verifier.
    function testCalculateIdentityRegistrationInputHashFromParametersOnKnownInput() public {
        // Setup
        bytes memory callData = abi.encodeCall(
            ManagerImplV1.calculateIdentityRegistrationInputHash,
            (startIndex, insertionPreRoot, insertionPostRoot, identityCommitments)
        );
        bytes memory returnData = abi.encode(insertionInputHash);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Checks that the input hash can only be calculated if behind the proxy.
    function testCannotCalculateIdentityRegistrationInputHashIfNotViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImplV2.calculateIdentityRegistrationInputHash(
            startIndex, insertionPreRoot, insertionPostRoot, identityCommitments
        );
    }

    /// @notice Tests whether it is possible to correctly calculate the `inputHash` to the merkle
    ///         tree verifier.
    function testCalculateIdentityDeletionInputHashFromParametersOnKnownInput() public {
        // Setup
        bytes memory callData = abi.encodeCall(
            ManagerImpl.calculateIdentityDeletionInputHash,
            (packedDeletionIndices, deletionPreRoot, deletionPostRoot, deletionBatchSize)
        );
        bytes memory returnData = abi.encode(deletionInputHash);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Checks that the input hash can only be calculated if behind the proxy.
    function testCannotCalculateIdentityDeletionInputHashIfNotViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImplV2.calculateIdentityDeletionInputHash(
            packedDeletionIndices, deletionPreRoot, deletionPostRoot, deletionBatchSize
        );
    }
}
