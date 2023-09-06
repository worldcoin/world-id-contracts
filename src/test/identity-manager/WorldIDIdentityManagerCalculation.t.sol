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
        managerImpl.calculateIdentityRegistrationInputHash(
            startIndex, insertionPreRoot, insertionPostRoot, identityCommitments
        );
    }

    /// @notice Tests whether it is possible to correctly calculate the `inputHash` to the merkle
    ///         tree verifier.
    function testCalculateIdentityDeletionInputHashFromParametersOnKnownInput() public {
        // Setup
        bytes memory callData = abi.encodeCall(
            ManagerImpl.calculateIdentityDeletionInputHash,
            (packedDeletionIndices, insertionPreRoot, insertionPostRoot, deletionBatchSize)
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
        managerImpl.calculateIdentityDeletionInputHash(
            packedDeletionIndices, deletionPreRoot, deletionPostRoot, deletionBatchSize
        );
    }

    /// @notice Check whether it's possible to caculate the identity update input hash.
    function testCanCalculateIdentityUpdateInputHash(
        uint256 insertionPreRoot,
        uint256 insertionPostRoot,
        uint32 startIndex1,
        uint32 startIndex2,
        uint256 oldIdent1,
        uint256 oldIdent2,
        uint256 newIdent1,
        uint256 newIdent2
    ) public {
        // Setup
        uint32[] memory leafIndices = new uint32[](2);
        leafIndices[0] = startIndex1;
        leafIndices[1] = startIndex2;

        uint256[] memory oldIdents = new uint256[](2);
        oldIdents[0] = oldIdent1;
        oldIdents[1] = oldIdent2;

        uint256[] memory newIdents = new uint256[](2);
        newIdents[0] = newIdent1;
        newIdents[1] = newIdent2;

        bytes32 expectedResult = keccak256(
            abi.encodePacked(
                insertionPreRoot,
                insertionPostRoot,
                uint256(startIndex1),
                uint256(startIndex2),
                oldIdent1,
                oldIdent2,
                newIdent1,
                newIdent2
            )
        );
        bytes memory callData = abi.encodeCall(
            ManagerImplV1.calculateIdentityUpdateInputHash,
            (insertionPreRoot, insertionPostRoot, leafIndices, oldIdents, newIdents)
        );
        bytes memory expectedReturn = abi.encode(expectedResult);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, expectedReturn);
    }

    /// @notice Ensures that the identity update hash can only be calculated when called via the
    ///         proxy.
    function testCannotCalculateIdentityUpdateHashIfNotViaProxy(
        uint256 insertionPreRoot,
        uint256 insertionPostRoot,
        uint32[] memory leafIndices,
        uint256[] memory oldIdents,
        uint256[] memory newIdents
    ) public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.calculateIdentityUpdateInputHash(
            insertionPreRoot, insertionPostRoot, leafIndices, oldIdents, newIdents
        );
    }
}
