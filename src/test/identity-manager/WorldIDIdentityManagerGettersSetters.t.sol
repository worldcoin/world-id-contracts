// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {SemaphoreVerifier} from "src/SemaphoreVerifier.sol";
import {SimpleVerifier, SimpleVerify} from "../mock/SimpleVerifier.sol";
import {TypeConverter as TC} from "../utils/TypeConverter.sol";
import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

import {WorldIDIdentityManagerImplV2 as ManagerImpl} from "../../WorldIDIdentityManagerImplV2.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImplV1} from "../../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Getter and Setter Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerGettersSetters is WorldIDIdentityManagerTest {
    /// @notice Taken from WorldIDIdentityManagerImplV1.sol
    event DependencyUpdated(
        ManagerImpl.Dependency indexed kind, address indexed oldAddress, address indexed newAddress
    );
    event RootHistoryExpirySet(uint256 indexed oldExpiryTime, uint256 indexed newExpiryTime);

    /// @notice Checks that it is possible to get the address of the contract currently being used
    ///         to verify identity registration proofs.
    function testCanGetRegisterIdentitiesVerifierLookupTableAddress() public {
        // Setup
        bytes memory callData =
            abi.encodeCall(ManagerImplV1.getRegisterIdentitiesVerifierLookupTableAddress, ());
        bytes memory expectedReturn = abi.encode(address(defaultInsertVerifiers));

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, expectedReturn);
    }

    /// @notice Ensures that it is not possible to get the address of the verifier lookup table for
    ///         identity registration unless called via the proxy.
    function testCannotGetRegisterIdentitiesVerifierLookupTableAddressUnlessViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImplV2.getRegisterIdentitiesVerifierLookupTableAddress();
    }

    /// @notice Checks that it is possible to set the lookup table currently being used to verify
    ///         identity registration proofs.
    function testCanSetRegisterIdentitiesVerifierLookupTable() public {
        // Setup
        (VerifierLookupTable insertionVerifiers,,,) =
            makeVerifierLookupTables(TC.makeDynArray([40]));
        address newVerifiersAddress = address(insertionVerifiers);
        bytes memory callData = abi.encodeCall(
            ManagerImplV1.setRegisterIdentitiesVerifierLookupTable, (insertionVerifiers)
        );
        bytes memory checkCallData =
            abi.encodeCall(ManagerImplV1.getRegisterIdentitiesVerifierLookupTableAddress, ());
        bytes memory expectedReturn = abi.encode(newVerifiersAddress);
        vm.expectEmit(true, false, true, true);
        emit DependencyUpdated(
            ManagerImplV1.Dependency.InsertionVerifierLookupTable, nullAddress, newVerifiersAddress
        );

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
        assertCallSucceedsOn(identityManagerAddress, checkCallData, expectedReturn);
    }

    /// @notice Checks that the register identities lookup table cannot be set except by the owner.
    function testCannotSetRegisterIdentitiesVerifierLookupTableUnlessOwner(address notOwner)
        public
    {
        // Setup
        vm.assume(notOwner != address(this) && notOwner != address(0x0));
        (VerifierLookupTable insertionVerifiers,,,) =
            makeVerifierLookupTables(TC.makeDynArray([40]));
        bytes memory callData = abi.encodeCall(
            ManagerImplV1.setRegisterIdentitiesVerifierLookupTable, (insertionVerifiers)
        );
        bytes memory errorData = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(notOwner);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Ensures that it is not possible to set the address of the verifier lookup table for
    ///         identity registration unless called via the proxy.
    function testCannotSetRegisterIdentitiesVerifierLookupTableUnlessViaProxy() public {
        // Setup
        (VerifierLookupTable insertionVerifiers,,,) =
            makeVerifierLookupTables(TC.makeDynArray([40]));
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImplV2.setRegisterIdentitiesVerifierLookupTable(insertionVerifiers);
    }

    /// @notice Checks that it is possible to get the address of the contract currently being used
    ///         to verify identity deletion proofs.
    function testCanGetDeleteIdentitiesVerifierLookupTableAddress() public {
        // Setup
        bytes memory callData =
            abi.encodeCall(ManagerImpl.getDeleteIdentitiesVerifierLookupTableAddress, ());
        bytes memory expectedReturn = abi.encode(address(defaultDeletionVerifiers));

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, expectedReturn);
    }

    /// @notice Ensures that it is not possible to get the address of the verifier lookup table for
    ///         identity deletion unless called via the proxy.
    function testCannotGetDeleteIdentitiesVerifierLookupTableAddressUnlessViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImplV2.getDeleteIdentitiesVerifierLookupTableAddress();
    }

    /// @notice Checks that it is possible to set the lookup table currently being used to verify
    ///         identity deletion proofs.
    function testCanSetDeleteIdentitiesVerifierLookupTable() public {
        // Setup
        (,, VerifierLookupTable deletionVerifiers,) =
            makeVerifierLookupTables(TC.makeDynArray([40]));
        address newVerifiersAddress = address(deletionVerifiers);
        bytes memory callData =
            abi.encodeCall(ManagerImpl.setDeleteIdentitiesVerifierLookupTable, (deletionVerifiers));
        bytes memory checkCallData =
            abi.encodeCall(ManagerImpl.getDeleteIdentitiesVerifierLookupTableAddress, ());
        bytes memory expectedReturn = abi.encode(newVerifiersAddress);
        vm.expectEmit(true, false, true, true);
        emit DependencyUpdated(
            ManagerImplV1.Dependency.DeletionVerifierLookupTable, nullAddress, newVerifiersAddress
        );

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
        assertCallSucceedsOn(identityManagerAddress, checkCallData, expectedReturn);
    }

    /// @notice Checks that the delete identities lookup table cannot be set except by the owner.
    function testCannotSetDeleteIdentitiesVerifierLookupTableUnlessOwner(address notOwner) public {
        // Setup
        vm.assume(notOwner != address(this) && notOwner != address(0x0));
        (,, VerifierLookupTable deletionVerifiers,) =
            makeVerifierLookupTables(TC.makeDynArray([40]));
        bytes memory callData = abi.encodeCall(
            ManagerImplV1.setRegisterIdentitiesVerifierLookupTable, (deletionVerifiers)
        );
        bytes memory errorData = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(notOwner);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Ensures that it is not possible to set the address of the verifier lookup table for
    ///         identity deletion unless called via the proxy.
    function testCannotSetDeleteIdentitiesVerifierLookupTableUnlessViaProxy() public {
        // Setup
        (,, VerifierLookupTable deletionVerifiers,) =
            makeVerifierLookupTables(TC.makeDynArray([40]));
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImplV2.setDeleteIdentitiesVerifierLookupTable(deletionVerifiers);
    }

    /// @notice Ensures that we can get the address of the semaphore verifier.
    function testCanGetSemaphoreVerifierAddress() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImplV1.getSemaphoreVerifierAddress, ());

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
    }

    /// @notice Ensures that it is not possible to get the address of the verifier for semaphore
    ///         proofs unless called via the proxy.
    function testCannotGetSemaphoreVerifierAddressUnlessViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImplV2.getSemaphoreVerifierAddress();
    }

    /// @notice Checks that it is possible to set the contract currently being used to verify
    ///         semaphore proofs.
    function testCanSetSemaphoreVerifier() public {
        // Setup
        SemaphoreVerifier newVerifier = new SemaphoreVerifier();
        address newVerifierAddress = address(newVerifier);
        bytes memory callData = abi.encodeCall(ManagerImplV1.setSemaphoreVerifier, (newVerifier));
        bytes memory checkCallData = abi.encodeCall(ManagerImplV1.getSemaphoreVerifierAddress, ());
        bytes memory expectedReturn = abi.encode(newVerifierAddress);
        vm.expectEmit(true, false, true, true);
        emit DependencyUpdated(
            ManagerImplV1.Dependency.SemaphoreVerifier, nullAddress, newVerifierAddress
        );

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
        assertCallSucceedsOn(identityManagerAddress, checkCallData, expectedReturn);
    }

    /// @notice Checks that the semaphore verifier cannot be set except by the owner.
    function testCannotSetSemaphoreVerifierUnlessOwner(address notOwner) public {
        // Setup
        vm.assume(notOwner != address(this) && notOwner != address(0x0));
        SemaphoreVerifier newVerifier = new SemaphoreVerifier();
        bytes memory callData = abi.encodeCall(ManagerImplV1.setSemaphoreVerifier, (newVerifier));
        bytes memory errorData = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(notOwner);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Ensures that it is not possible to set the address of the verifier for semaphore
    ///         proofs unless called via the proxy.
    function testCannotSetSemaphoreVerifierAddressUnlessViaProxy() public {
        // Setup
        SemaphoreVerifier newVerifier = new SemaphoreVerifier();
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImplV2.setSemaphoreVerifier(newVerifier);
    }

    /// @notice Ensures that it's possible to get the root history expiry time.
    function testCanGetRootHistoryExpiry() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImplV1.getRootHistoryExpiry, ());
        bytes memory result = abi.encode(uint256(1 hours));

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, result);
    }

    /// @notice Ensures that it is impossible to get the root history except via the proxy.
    function testCannotGetRootHistoryExpiryUnlessViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImplV2.getRootHistoryExpiry();
    }

    /// @notice Ensures that it is possible to set the root history expiry time.
    function testCanSetRootHistoryExpiry(uint256 newExpiry) public {
        // Setup
        vm.assume(newExpiry != 0 && newExpiry != 1 hours);
        bytes memory callData = abi.encodeCall(ManagerImplV1.setRootHistoryExpiry, (newExpiry));
        bytes memory checkCallData = abi.encodeCall(ManagerImplV1.getRootHistoryExpiry, ());
        bytes memory expectedReturn = abi.encode(newExpiry);
        vm.expectEmit(true, true, true, true);
        emit RootHistoryExpirySet(1 hours, newExpiry);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
        assertCallSucceedsOn(identityManagerAddress, checkCallData, expectedReturn);
    }

    /// @notice Ensures that the root history expiry time can't be set to zero.
    function testCannotSetRootHistoryExpiryToZero() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImplV1.setRootHistoryExpiry, (0));
        bytes memory expectedError = encodeStringRevert("Expiry time cannot be zero.");

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that the semaphore verifier cannot be set except by the owner.
    function testCannotSetRootHistoryExpiryUnlessOwner(address notOwner) public {
        // Setup
        vm.assume(notOwner != address(this) && notOwner != address(0x0));
        SemaphoreVerifier newVerifier = new SemaphoreVerifier();
        bytes memory callData = abi.encodeCall(ManagerImplV1.setSemaphoreVerifier, (newVerifier));
        bytes memory errorData = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(notOwner);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    function testCannotSetRootHistoryExpiryUnlessViaProxy(uint256 newExpiry) public {
        // Setup
        vm.assume(newExpiry != 0);
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImplV2.setRootHistoryExpiry(newExpiry);
    }
}
