// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";
import {SemaphoreVerifier} from "semaphore/base/SemaphoreVerifier.sol";
import {SimpleVerifier, SimpleVerify} from "../mock/SimpleVerifier.sol";
import {TypeConverter as TC} from "../utils/TypeConverter.sol";
import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

import {WorldIDIdentityManagerImplV1 as ManagerImpl} from "../../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Getter and Setter Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerGettersSetters is WorldIDIdentityManagerTest {
    /// @notice Checks that it is possible to get the address of the contract currently being used
    ///         to verify identity registration proofs.
    function testCanGetRegisterIdentitiesVerifierLookupTableAddress() public {
        // Setup
        bytes memory callData =
            abi.encodeCall(ManagerImpl.getRegisterIdentitiesVerifierLookupTableAddress, ());
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
        managerImpl.getRegisterIdentitiesVerifierLookupTableAddress();
    }

    /// @notice Checks that it is possible to set the lookup table currently being used to verify
    ///         identity registration proofs.
    function testCanSetRegisterIdentitiesVerifierLookupTable() public {
        // Setup
        (VerifierLookupTable insertionVerifiers,) = makeVerifierLookupTables(TC.makeDynArray([40]));
        address newVerifiersAddress = address(insertionVerifiers);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.setRegisterIdentitiesVerifierLookupTable, (insertionVerifiers)
        );
        bytes memory checkCallData =
            abi.encodeCall(ManagerImpl.getRegisterIdentitiesVerifierLookupTableAddress, ());
        bytes memory expectedReturn = abi.encode(newVerifiersAddress);

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
        (VerifierLookupTable insertionVerifiers,) = makeVerifierLookupTables(TC.makeDynArray([40]));
        bytes memory callData = abi.encodeCall(
            ManagerImpl.setRegisterIdentitiesVerifierLookupTable, (insertionVerifiers)
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
        (VerifierLookupTable insertionVerifiers,) = makeVerifierLookupTables(TC.makeDynArray([40]));
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.setRegisterIdentitiesVerifierLookupTable(insertionVerifiers);
    }

    /// @notice Checks that it is possible to get the address of the lookup table currently being
    ///         used to verify identity update proofs.
    function testCanGetIdentityUpdateVerifierLookupTableAddress() public {
        // Setup
        bytes memory callData =
            abi.encodeCall(ManagerImpl.getIdentityUpdateVerifierLookupTableAddress, ());
        bytes memory expectedReturn = abi.encode(defaultUpdateVerifiers);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, expectedReturn);
    }

    /// @notice Ensures that it is not possible to get the address of the verifier lookup table for
    ///         identity updates unless called via the proxy.
    function testCannotGetIdentityUpdateVerifierLookupTableAddressUnlessViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.getIdentityUpdateVerifierLookupTableAddress();
    }

    /// @notice Checks that it is possible to set the lookup table currently being used to verify
    ///         identity update proofs.
    function testCanSetIdentityUpdateVerifierLookupTable() public {
        // Setup
        (, VerifierLookupTable updateVerifiers) = makeVerifierLookupTables(TC.makeDynArray([40]));
        address newVerifierAddress = address(updateVerifiers);
        bytes memory callData =
            abi.encodeCall(ManagerImpl.setIdentityUpdateVerifierLookupTable, (updateVerifiers));
        bytes memory checkCallData =
            abi.encodeCall(ManagerImpl.getIdentityUpdateVerifierLookupTableAddress, ());
        bytes memory expectedReturn = abi.encode(newVerifierAddress);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
        assertCallSucceedsOn(identityManagerAddress, checkCallData, expectedReturn);
    }

    /// @notice Checks that the identity update verifier lookup table cannot be set except by the
    ///         owner.
    function testCannotSetIdentityUpdateVerifierLookupTableUnlessOwner(address notOwner) public {
        // Setup
        vm.assume(notOwner != address(this) && notOwner != address(0x0));
        (, VerifierLookupTable updateVerifiers) = makeVerifierLookupTables(TC.makeDynArray([40]));
        bytes memory callData =
            abi.encodeCall(ManagerImpl.setIdentityUpdateVerifierLookupTable, (updateVerifiers));
        bytes memory errorData = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(notOwner);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Ensures that it is not possible to set the address of the verifier lookup table for
    ///         identity removal unless called via the proxy.
    function testCannotSetIdentityUpdateVerifierLookupTableUnlessViaProxy() public {
        // Setup
        (, VerifierLookupTable updateVerifiers) = makeVerifierLookupTables(TC.makeDynArray([40]));
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.setIdentityUpdateVerifierLookupTable(updateVerifiers);
    }

    /// @notice Ensures that we can get the address of the semaphore verifier.
    function testCanGetSemaphoreVerifierAddress() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImpl.getSemaphoreVerifierAddress, ());

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
    }

    /// @notice Ensures that it is not possible to get the address of the verifier for semaphore
    ///         proofs unless called via the proxy.
    function testCannotGetSemaphoreVerifierAddressUnlessViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.getSemaphoreVerifierAddress();
    }

    /// @notice Checks that it is possible to set the contract currently being used to verify
    ///         semaphore proofs.
    function testCanSetSemaphoreVerifier() public {
        // Setup
        SemaphoreVerifier newVerifier = new SemaphoreVerifier();
        address newVerifierAddress = address(newVerifier);
        bytes memory callData = abi.encodeCall(ManagerImpl.setSemaphoreVerifier, (newVerifier));
        bytes memory checkCallData = abi.encodeCall(ManagerImpl.getSemaphoreVerifierAddress, ());
        bytes memory expectedReturn = abi.encode(newVerifierAddress);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
        assertCallSucceedsOn(identityManagerAddress, checkCallData, expectedReturn);
    }

    /// @notice Checks that the semaphore verifier cannot be set except by the owner.
    function testCannotSetSemaphoreVerifierUnlessOwner(address notOwner) public {
        // Setup
        vm.assume(notOwner != address(this) && notOwner != address(0x0));
        SemaphoreVerifier newVerifier = new SemaphoreVerifier();
        bytes memory callData = abi.encodeCall(ManagerImpl.setSemaphoreVerifier, (newVerifier));
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
        managerImpl.setSemaphoreVerifier(newVerifier);
    }

    /// @notice Ensures that it's possible to get the root history expiry time.
    function testCanGetRootHistoryExpiry() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImpl.getRootHistoryExpiry, ());
        bytes memory result = abi.encode(uint256(1 hours));

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, result);
    }

    /// @notice Ensures that it is impossible to get the root history except via the proxy.
    function testCannotGetRootHistoryExpiryUnlessViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.getRootHistoryExpiry();
    }

    /// @notice Ensures that it is possible to set the root history expiry time.
    function testCanSetRootHistoryExpiry(uint256 newExpiry) public {
        // Setup
        vm.assume(newExpiry != 0 && newExpiry != 1 hours);
        bytes memory callData = abi.encodeCall(ManagerImpl.setRootHistoryExpiry, (newExpiry));
        bytes memory checkCallData = abi.encodeCall(ManagerImpl.getRootHistoryExpiry, ());
        bytes memory expectedReturn = abi.encode(newExpiry);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
        assertCallSucceedsOn(identityManagerAddress, checkCallData, expectedReturn);
    }

    /// @notice Ensures that the root history expiry time can't be set to zero.
    function testCannotSetRootHistoryExpiryToZero() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImpl.setRootHistoryExpiry, (0));
        bytes memory expectedError = encodeStringRevert("Expiry time cannot be zero.");

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that the semaphore verifier cannot be set except by the owner.
    function testCannotSetRootHistoryExpiryUnlessOwner(address notOwner) public {
        // Setup
        vm.assume(notOwner != address(this) && notOwner != address(0x0));
        SemaphoreVerifier newVerifier = new SemaphoreVerifier();
        bytes memory callData = abi.encodeCall(ManagerImpl.setSemaphoreVerifier, (newVerifier));
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
        managerImpl.setRootHistoryExpiry(newExpiry);
    }
}
