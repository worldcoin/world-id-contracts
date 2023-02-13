// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {ITreeVerifier} from "../interfaces/ITreeVerifier.sol";
import {SimpleVerifier, SimpleVerify} from "./mock/SimpleVerifier.sol";
import {Verifier as SemaphoreVerifier} from "semaphore/base/Verifier.sol";

import {WorldIDIdentityManagerImplV1 as ManagerImpl} from "../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Getter and Setter Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerGettersSetters is WorldIDIdentityManagerTest {
    /// @notice Checks that it is possible to get the address of the contract currently being used
    ///         to verify identity registration proofs.
    function testCanGetRegisterIdentitiesVerifierAddress() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImpl.getRegisterIdentitiesVerifierAddress, ());
        bytes memory expectedReturn = abi.encode(address(verifier));

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, expectedReturn);
    }

    /// @notice Ensures that it is not possible to get the address of the verifier for identity
    ///         registration unless called via the proxy.
    function testCannotGetRegisterIdentitiesVerifierAddressUnlessViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.getRegisterIdentitiesVerifierAddress();
    }

    /// @notice Checks that it is possible to set the contract currently being used to verify
    ///         identity registration proofs.
    function testCanSetRegisterIdentitiesVerifier() public {
        // Setup
        ITreeVerifier newVerifier = new SimpleVerifier();
        address newVerifierAddress = address(newVerifier);
        bytes memory callData =
            abi.encodeCall(ManagerImpl.setRegisterIdentitiesVerifier, (newVerifier));
        bytes memory checkCallData =
            abi.encodeCall(ManagerImpl.getRegisterIdentitiesVerifierAddress, ());
        bytes memory expectedReturn = abi.encode(newVerifierAddress);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
        assertCallSucceedsOn(identityManagerAddress, checkCallData, expectedReturn);
    }

    /// @notice Checks that the register identities verifier cannot be set except by the owner.
    function testCannotSetRegisterIdentitiesVerifierUnlessOwner(address notOwner) public {
        // Setup
        vm.assume(notOwner != address(this) && notOwner != address(0x0));
        ITreeVerifier newVerifier = new SimpleVerifier();
        bytes memory callData =
            abi.encodeCall(ManagerImpl.setRegisterIdentitiesVerifier, (newVerifier));
        bytes memory errorData = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(notOwner);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Ensures that it is not possible to set the address of the verifier for identity
    ///         registration unless called via the proxy.
    function testCannotSetRegisterIdentitiesVerifierUnlessViaProxy() public {
        // Setup
        ITreeVerifier newVerifier = new SimpleVerifier();
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.setRegisterIdentitiesVerifier(newVerifier);
    }

    /// @notice Checks that it is possible to get the address of the contract currently being used
    ///         to verify identity removal proofs.
    function testCanGetIdentityRemovalVerifierAddress() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImpl.getIdentityRemovalVerifierAddress, ());

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
    }

    /// @notice Ensures that it is not possible to get the address of the verifier for identity
    ///         removal unless called via the proxy.
    function testCannotGetIdentityRemovalVerifierAddressUnlessViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.getIdentityRemovalVerifierAddress();
    }

    /// @notice Checks that it is possible to set the contract currently being used to verify
    ///         identity removal proofs.
    function testCanSetIdentityRemovalVerifier() public {
        // Setup
        ITreeVerifier newVerifier = new SimpleVerifier();
        address newVerifierAddress = address(newVerifier);
        bytes memory callData =
            abi.encodeCall(ManagerImpl.setIdentityRemovalVerifier, (newVerifier));
        bytes memory checkCallData =
            abi.encodeCall(ManagerImpl.getIdentityRemovalVerifierAddress, ());
        bytes memory expectedReturn = abi.encode(newVerifierAddress);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
        assertCallSucceedsOn(identityManagerAddress, checkCallData, expectedReturn);
    }

    /// @notice Checks that the identity removal verifier cannot be set except by the owner.
    function testCannotSetIdentityRemovalVerifierUnlessOwner(address notOwner) public {
        // Setup
        vm.assume(notOwner != address(this) && notOwner != address(0x0));
        ITreeVerifier newVerifier = new SimpleVerifier();
        bytes memory callData =
            abi.encodeCall(ManagerImpl.setIdentityRemovalVerifier, (newVerifier));
        bytes memory errorData = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(notOwner);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Ensures that it is not possible to set the address of the verifier for identity
    ///         removal unless called via the proxy.
    function testCannotSetIdentityRemovalVerifierUnlessViaProxy() public {
        // Setup
        ITreeVerifier newVerifier = new SimpleVerifier();
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.setIdentityRemovalVerifier(newVerifier);
    }

    /// @notice Checks that it is possible to get the address of the contract currently being used
    ///         to verify identity update proofs.
    function testCanGetIdentityUpdateVerifierAddress() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImpl.getIdentityUpdateVerifierAddress, ());

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
    }

    /// @notice Ensures that it is not possible to get the address of the verifier for identity
    ///         updates unless called via the proxy.
    function testCannotGetIdentityUpdateVerifierAddressUnlessViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.getIdentityUpdateVerifierAddress();
    }

    /// @notice Checks that it is possible to set the contract currently being used to verify
    ///         identity update proofs.
    function testCanSetIdentityUpdateVerifier() public {
        // Setup
        ITreeVerifier newVerifier = new SimpleVerifier();
        address newVerifierAddress = address(newVerifier);
        bytes memory callData = abi.encodeCall(ManagerImpl.setIdentityUpdateVerifier, (newVerifier));
        bytes memory checkCallData =
            abi.encodeCall(ManagerImpl.getIdentityUpdateVerifierAddress, ());
        bytes memory expectedReturn = abi.encode(newVerifierAddress);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
        assertCallSucceedsOn(identityManagerAddress, checkCallData, expectedReturn);
    }

    /// @notice Checks that the identity update verifier cannot be set except by the owner.
    function testCannotSetIdentityUpdateVerifierUnlessOwner(address notOwner) public {
        // Setup
        vm.assume(notOwner != address(this) && notOwner != address(0x0));
        ITreeVerifier newVerifier = new SimpleVerifier();
        bytes memory callData = abi.encodeCall(ManagerImpl.setIdentityUpdateVerifier, (newVerifier));
        bytes memory errorData = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(notOwner);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Ensures that it is not possible to set the address of the verifier for identity
    ///         removal unless called via the proxy.
    function testCannotSetIdentityUpdateVerifierUnlessViaProxy() public {
        // Setup
        ITreeVerifier newVerifier = new SimpleVerifier();
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.setIdentityUpdateVerifier(newVerifier);
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
}
