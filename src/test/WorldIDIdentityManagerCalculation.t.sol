// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {WorldIDIdentityManagerImplV1 as ManagerImpl} from "../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Calculation Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerCalculation is WorldIDIdentityManagerTest {
    /// @notice Tests whether it is possible to correctly calculate the `inputHash` to the merkle
    ///         tree verifier.
    function testCalculateInputHashFromParametersOnKnownInput() public {
        // Setup
        bytes memory callData = abi.encodeCall(
            ManagerImpl.calculateTreeVerifierInputHash,
            (startIndex, preRoot, postRoot, identityCommitments)
        );
        bytes memory returnData = abi.encode(inputHash);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Checks that the input hash can only be calculated if behind the proxy.
    function testCannotCalculateInputHashIfNotViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.calculateTreeVerifierInputHash(
            startIndex, preRoot, postRoot, identityCommitments
        );
    }

    /// @notice Tests whether it is possible to check whether values are in reduced form.
    function testCanCheckValueIsInReducedForm(uint256 value) public {
        // Setup
        vm.assume(value < SNARK_SCALAR_FIELD);
        bytes memory callData = abi.encodeCall(ManagerImpl.isInputInReducedForm, (value));
        bytes memory returnData = abi.encode(true);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Tests whether it is possible to detect un-reduced values.
    function testCanCheckValueIsNotInReducedForm(uint256 value) public {
        // Setup
        vm.assume(value >= SNARK_SCALAR_FIELD);
        bytes memory callData = abi.encodeCall(ManagerImpl.isInputInReducedForm, (value));
        bytes memory returnData = abi.encode(false);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Checks that reduced form checking can only be done from behind a proxy.
    function testCannotCheckValidIsInReducedFormIfNotViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.isInputInReducedForm(preRoot);
    }
}
