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
    function testCalculateIdentityRegistrationInputHashFromParametersOnKnownInput() public {
        // Setup
        bytes memory callData = abi.encodeCall(
            ManagerImpl.calculateIdentityRegistrationInputHash,
            (startIndex, preRoot, postRoot, identityCommitments)
        );
        bytes memory returnData = abi.encode(inputHash);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Checks that the input hash can only be calculated if behind the proxy.
    function testCannotCalculateIdentityRegistrationInputHashIfNotViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.calculateIdentityRegistrationInputHash(
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

    /// @notice Check whether it's possible to caculate the identity update input hash.
    function testCanCalculateIdentityUpdateInputHash(
        uint256 preRoot,
        uint256 postRoot,
        uint32 startIndex1,
        uint32 startIndex2,
        uint256 oldIdent1,
        uint256 oldIdent2,
        uint256 newIdent1,
        uint256 newIdent2
    ) public {
        // Setup
        ManagerImpl.IdentityUpdate memory ident1 =
            ManagerImpl.IdentityUpdate(startIndex1, oldIdent1, newIdent1);
        ManagerImpl.IdentityUpdate memory ident2 =
            ManagerImpl.IdentityUpdate(startIndex2, oldIdent2, newIdent2);
        ManagerImpl.IdentityUpdate[] memory newIdents = new ManagerImpl.IdentityUpdate[](2);
        newIdents[0] = ident1;
        newIdents[1] = ident2;
        bytes32 expectedResult = keccak256(
            abi.encodePacked(
                preRoot,
                postRoot,
                startIndex1,
                oldIdent1,
                newIdent1,
                startIndex2,
                oldIdent2,
                newIdent2
            )
        );
        bytes memory callData = abi.encodeCall(
            ManagerImpl.calculateIdentityUpdateInputHash, (preRoot, postRoot, newIdents)
        );
        bytes memory expectedReturn = abi.encode(expectedResult);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, expectedReturn);
    }

    function testCannotCalculateIdentityUpdateHashIfNotViaProxy(
        uint256 preRoot,
        uint256 postRoot,
        uint32 startIndex1,
        uint32 startIndex2,
        uint256 oldIdent1,
        uint256 oldIdent2,
        uint256 newIdent1,
        uint256 newIdent2
    ) public {
        // Setup
        ManagerImpl.IdentityUpdate memory ident1 =
            ManagerImpl.IdentityUpdate(startIndex1, oldIdent1, newIdent1);
        ManagerImpl.IdentityUpdate memory ident2 =
            ManagerImpl.IdentityUpdate(startIndex2, oldIdent2, newIdent2);
        ManagerImpl.IdentityUpdate[] memory newIdents = new ManagerImpl.IdentityUpdate[](2);
        newIdents[0] = ident1;
        newIdents[1] = ident2;
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.calculateIdentityUpdateInputHash(preRoot, postRoot, newIdents);
    }
}
