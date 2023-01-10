// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {Vm} from "forge-std/Vm.sol";
import {Test} from "forge-std/Test.sol";

import {ITreeVerifier} from "../interfaces/ITreeVerifier.sol";
import {SimpleVerifier, SimpleVerify} from "./mock/SimpleVerifier.sol";
import {UUPSUpgradeable} from "contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {WorldIDIdentityManagerImplMock} from "./mock/WorldIDIdentityManagerImplMock.sol";

import {WorldIDIdentityManager} from "../WorldIDIdentityManager.sol";
import {WorldIDIdentityManagerImplV1} from "../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Test.
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
contract WorldIDIdentityManagerTest is Test {
    ///////////////////////////////////////////////////////////////////////////////
    ///                                TEST DATA                                ///
    ///////////////////////////////////////////////////////////////////////////////

    Vm internal hevm = Vm(HEVM_ADDRESS);

    WorldIDIdentityManager identityManager;
    WorldIDIdentityManagerImplV1 managerImpl;

    ITreeVerifier verifier = new SimpleVerifier();
    uint256 initialRoot = 0x0;

    address identityManagerAddress = address(identityManager);
    address managerImplAddress = address(managerImpl);

    ///////////////////////////////////////////////////////////////////////////////
    ///                            TEST ORCHESTRATION                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice This function runs before every single test.
    /// @dev It is run before every single iteration of a property-based fuzzing test.
    function setUp() public {
        managerImpl = new WorldIDIdentityManagerImplV1();
        bytes memory callData =
            abi.encodeCall(WorldIDIdentityManagerImplV1.initialize, (initialRoot, verifier));
        identityManager = new WorldIDIdentityManager(address(managerImpl), callData);

        hevm.label(address(this), "Sender");
        hevm.label(identityManagerAddress, "IdentityManager");
        hevm.label(managerImplAddress, "ManagerImplementation");
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                            CONSTRUCTION TESTS                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Taken from Initializable.sol
    event Initialized(uint8 version);

    /// @notice Tests if it is possible to construct an identity manager without a delegate.
    function testCanConstructIdentityManagerWithNoDelegate() public {
        // Setup
        address dummy = address(this);
        bytes memory data = new bytes(0x0);

        // Test
        identityManager = new WorldIDIdentityManager(dummy, data);
    }

    /// @notice Tests that it is possible to properly construct and initialise
    function testCanConstructIdentityManagerWithDelegate() public {
        // Setup
        vm.expectEmit(true, true, true, true);
        emit Initialized(1);
        managerImpl = new WorldIDIdentityManagerImplV1();
        bytes memory callData =
            abi.encodeCall(WorldIDIdentityManagerImplV1.initialize, (initialRoot, verifier));

        // Test
        identityManager = new WorldIDIdentityManager(address(managerImpl), callData);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                               UPGRADE TESTS                             ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Tests that it is possible to upgrade to a new implementation.
    function testCanUpgradeImplementationWithoutCall() public {
        // Setup
        WorldIDIdentityManagerImplMock mockUpgrade = new WorldIDIdentityManagerImplMock();
        bytes memory upgradeCall = abi.encodeCall(UUPSUpgradeable.upgradeTo, (address(mockUpgrade)));

        // Test
        (bool success, bytes memory returnData) = identityManagerAddress.call(upgradeCall);
        assert(success);
        assertEq(returnData, new bytes(0x0));
    }

    /// @notice Tests that it is possible to upgrade to a new implementation and call a function on
    ///         that new implementation in the same transaction.
    function testCanUpgradeImplementationWithCall() public {
        // Setup
        WorldIDIdentityManagerImplMock mockUpgrade = new WorldIDIdentityManagerImplMock();
        bytes memory initCall =
            abi.encodeCall(WorldIDIdentityManagerImplV1.initialize, (initialRoot, verifier));
        bytes memory upgradeCall =
            abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (address(mockUpgrade), initCall));

        // Test
        (bool success, bytes memory returnData) = identityManagerAddress.call(upgradeCall);
        assert(success);
        assertEq(returnData, new bytes(0x0));
    }

    /// @notice Tests that an upgrade cannot be performed by anybody other than the manager.
    function testCannotUpgradeUnlessManager(address naughty) public {
        // Setup
        vm.assume(naughty != address(this) || naughty != address(0x0));
        WorldIDIdentityManagerImplMock mockUpgrade = new WorldIDIdentityManagerImplMock();
        bytes memory initCall =
            abi.encodeCall(WorldIDIdentityManagerImplV1.initialize, (initialRoot, verifier));
        bytes memory upgradeCall =
            abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (address(mockUpgrade), initCall));
        vm.prank(naughty);
        vm.expectRevert("Ownable: caller is not the owner");

        // Test
        (bool success, bytes memory returnData) = identityManagerAddress.call(upgradeCall);
        assert(!success);
        delete returnData;
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                            FUNCTIONALITY TESTS                          ///
    ///////////////////////////////////////////////////////////////////////////////

    // Note Comprehensive functionality tests are located in WorldIDIdentityManagerImplV1.sol. These
    // tests are purely to ensure that we can call all of the necessary functions properly through
    // the proxy.

    // TODO [Ara] `testCanCall*` tests
}
