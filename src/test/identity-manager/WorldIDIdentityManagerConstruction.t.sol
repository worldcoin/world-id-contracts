// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {UUPSUpgradeable} from "contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {WorldIDIdentityManager as IdentityManager} from "../../WorldIDIdentityManager.sol";
import {WorldIDIdentityManagerImplV2 as ManagerImpl} from "../../WorldIDIdentityManagerImplV2.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImplV1} from "../../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Construction Tests
/// @notice Contains tests for the WorldID identity manager
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerConstruction is WorldIDIdentityManagerTest {
    /// @notice Taken from Initializable.sol
    event Initialized(uint8 version);

    /// @notice Tests if it is possible to construct an identity manager without a delegate.
    function testCanConstructIdentityManagerWithNoDelegate() public {
        // Setup
        address dummy = address(this);
        bytes memory data = new bytes(0x0);

        // Test
        identityManager = new IdentityManager(dummy, data);
    }

    /// @notice Tests that it is possible to properly construct and initialise an identity manager.
    function testCanConstructIdentityManagerWithDelegate() public {
        // Setup
        vm.expectEmit(true, true, true, true);
        emit Initialized(1);
        managerImplV1 = new ManagerImplV1();
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

        // Test
        identityManager = new IdentityManager(address(managerImplV2), callData);

        identityManagerAddress = address(identityManager);

        // creates Manager Impl V2, which will be used for tests
        managerImplV2 = new ManagerImpl();
        managerImplV2Address = address(managerImplV2);

        bytes memory initCallV2 =
            abi.encodeCall(ManagerImpl.initializeV2, (defaultDeletionVerifiers));
        bytes memory upgradeCall = abi.encodeCall(
            UUPSUpgradeable.upgradeToAndCall, (address(managerImplV2Address), initCallV2)
        );

        // Test
        assertCallSucceedsOn(identityManagerAddress, upgradeCall, new bytes(0x0));
    }
}
