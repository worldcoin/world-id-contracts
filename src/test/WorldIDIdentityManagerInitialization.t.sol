// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {WorldIDIdentityManager as IdentityManager} from "../WorldIDIdentityManager.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImpl} from "../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Initialization Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerInitialization is WorldIDIdentityManagerTest {
    /// @notice Taken from Initializable.sol
    event Initialized(uint8 version);

    /// @notice Checks that it is possible to initialise the contract.
    function testInitialisation() public {
        // Setup
        delete identityManager;
        delete managerImpl;

        managerImpl = new ManagerImpl();
        managerImplAddress = address(managerImpl);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.initialize, (initialRoot, verifier, isStateBridgeEnabled, stateBridgeProxy)
        );

        vm.expectEmit(true, true, true, true);
        emit Initialized(1);

        // Test
        identityManager = new IdentityManager(managerImplAddress, callData);
    }

    /// @notice Checks that it is not possible to initialise the contract more than once.
    function testInitializationOnlyOnce() public {
        // Setup
        bytes memory callData = abi.encodeCall(
            ManagerImpl.initialize, (initialRoot, verifier, isStateBridgeEnabled, stateBridgeProxy)
        );
        bytes memory expectedReturn =
            encodeStringRevert("Initializable: contract is already initialized");

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedReturn);
    }

    /// @notice Checks that it is impossible to initialize the delegate on its own.
    function testCannotInitializeTheDelegate() public {
        // Setup
        ManagerImpl localImpl = new ManagerImpl();
        vm.expectRevert("Initializable: contract is already initialized");

        // Test
        localImpl.initialize(initialRoot, verifier, isStateBridgeEnabled, stateBridgeProxy);
    }
}
