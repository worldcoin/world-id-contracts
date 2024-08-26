// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {UUPSUpgradeable} from "contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {WorldIDIdentityManager as IdentityManager} from "../../WorldIDIdentityManager.sol";
import {WorldIDIdentityManagerImplV2 as ManagerImpl} from "../../WorldIDIdentityManagerImplV2.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImplV1} from "../../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Initialization Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerInitialization is WorldIDIdentityManagerTest {
    /// @notice Taken from Initializable.sol
    event Initialized(uint8 version);

    event WorldIDIdentityManagerImplV2Initialized();

    /// @notice Checks that it is possible to initialise the contract.
    function testInitialisation() public {
        // Setup
        delete identityManager;
        delete managerImplV2;
        delete managerImplV1;

        bytes memory V1CallData = abi.encodeCall(
            ManagerImplV1.initialize,
            (
                treeDepth,
                initialRoot,
                defaultInsertVerifiers,
                defaultUpdateVerifiers,
                semaphoreVerifier
            )
        );

        managerImplV1 = new ManagerImplV1();
        managerImplV2Address = address(managerImplV2);

        vm.expectEmit(true, true, true, true);
        emit Initialized(1);

        identityManager = new IdentityManager(managerImplV1Address, V1CallData);
        identityManagerAddress = address(identityManager);

        // creates Manager Impl V2, which will be used for tests
        managerImplV2 = new ManagerImpl();
        managerImplV2Address = address(managerImplV2);

        bytes memory initCallV2 =
            abi.encodeCall(ManagerImpl.initializeV2, (defaultDeletionVerifiers));
        bytes memory upgradeCall = abi.encodeCall(
            UUPSUpgradeable.upgradeToAndCall, (address(managerImplV2Address), initCallV2)
        );

        vm.expectEmit(true, true, true, true);
        emit WorldIDIdentityManagerImplV2Initialized();

        vm.expectEmit(true, true, true, true);
        emit Initialized(2);
        // Test
        assertCallSucceedsOn(identityManagerAddress, upgradeCall, new bytes(0x0));
    }

    /// @notice Checks that it is possible to initialise the contract.
    function testInitialisation2() public {
        // Setup
        delete identityManager;
        delete managerImplV2;
        delete managerImplV1;

        bytes memory V1CallData = abi.encodeCall(
            ManagerImplV1.initialize,
            (
                treeDepth,
                initialRoot,
                defaultInsertVerifiers,
                defaultUpdateVerifiers,
                semaphoreVerifier
            )
        );

        // creates Manager Impl V2, which will be used for tests
        managerImplV2 = new ManagerImpl();
        managerImplV2Address = address(managerImplV2);

        vm.expectEmit(true, true, true, true);
        emit Initialized(1);
        identityManager = new IdentityManager(managerImplV2Address, V1CallData);
        identityManagerAddress = address(identityManager);

        bytes memory initCallV2 =
            abi.encodeCall(ManagerImpl.initializeV2, (defaultDeletionVerifiers));

        // can't expectEmit Initialized 2 due to the low-level call wrapper, but the trace
        // shows Initialized(2) is emitted
        assertCallSucceedsOn(identityManagerAddress, initCallV2, new bytes(0x0));
    }

    /// @notice Checks that it is not possible to initialise the contract more than once.
    function testInitializationOnlyOnce() public {
        // Setup
        bytes memory callData = abi.encodeCall(
            ManagerImplV1.initialize,
            (
                treeDepth,
                initialRoot,
                defaultInsertVerifiers,
                defaultUpdateVerifiers,
                semaphoreVerifier
            )
        );
        bytes memory expectedReturn =
            encodeStringRevert("Initializable: contract is already initialized");

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedReturn);

        callData = abi.encodeCall(ManagerImpl.initializeV2, (defaultDeletionVerifiers));

        assertCallFailsOn(identityManagerAddress, callData, expectedReturn);
    }

    /// @notice Checks that it is impossible to initialize the delegate on its own.
    function testCannotInitializeTheDelegate() public {
        // Setup
        ManagerImplV1 localImpl = new ManagerImpl();
        vm.expectRevert("Initializable: contract is already initialized");

        // Test
        localImpl.initialize(
            treeDepth,
            initialRoot,
            defaultInsertVerifiers,
            defaultUpdateVerifiers,
            semaphoreVerifier
        );
    }

    /// @notice Checks that it is impossible to initialize the contract with unsupported tree depth.
    function testCannotPassUnsupportedTreeDepth() public {
        // Setup
        delete identityManager;
        delete managerImplV2;

        managerImplV2 = new ManagerImpl();
        managerImplV2Address = address(managerImplV2);
        uint8 unsupportedDepth = 15;

        bytes memory callData = abi.encodeCall(
            ManagerImplV1.initialize,
            (
                unsupportedDepth,
                initialRoot,
                defaultInsertVerifiers,
                defaultUpdateVerifiers,
                semaphoreVerifier
            )
        );

        vm.expectRevert(abi.encodeWithSelector(ManagerImplV1.UnsupportedTreeDepth.selector, 15));

        // Test
        identityManager = new IdentityManager(managerImplV2Address, callData);
    }
}
