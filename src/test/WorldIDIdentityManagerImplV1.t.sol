// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {Vm} from "forge-std/Vm.sol";
import {Test} from "forge-std/Test.sol";

import {Semaphore, ITreeVerifier} from "../Semaphore.sol";
import {Verifier as TreeVerifier} from "./mock/TreeVerifier.sol";
import {SimpleVerifier, SimpleVerify} from "./mock/SimpleVerifier.sol";

import {WorldIDIdentityManagerImplV1} from "../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Test.
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
contract WorldIDIdentityManagerImplV1Test is Test {
    ///////////////////////////////////////////////////////////////////////////////
    ///                                TEST DATA                                ///
    ///////////////////////////////////////////////////////////////////////////////

    Vm internal hevm = Vm(HEVM_ADDRESS);
    address thisAddress;
    address nullAddress = address(0x0);

    ITreeVerifier verifier = new TreeVerifier();
    uint256 initialRoot = 0x0;

    WorldIDIdentityManagerImplV1 identityManager;

    ///////////////////////////////////////////////////////////////////////////////
    ///                            TEST ORCHESTRATION                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice This function runs before every single test.
    /// @dev It is run before every single iteration of a property-based fuzzing test.
    function setUp() public {
        thisAddress = address(this);

        identityManager = new WorldIDIdentityManagerImplV1();
        identityManager.initialize(initialRoot, verifier);

        hevm.label(address(this), "Sender");
        hevm.label(address(identityManager), "IdentityManager");
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                           INITIALIZATION TESTS                          ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Taken from Initializable.sol
    event Initialized(uint8 version);

    /// @notice Checks that it is possible to initialise the contract.
    function testInitialisation() public {
        // Setup
        identityManager = new WorldIDIdentityManagerImplV1();
        vm.expectEmit(true, true, true, true);
        emit Initialized(1);

        // Test
        identityManager.initialize(initialRoot, verifier);
    }

    /// @notice Checks that it is not possible to initialise the contract more than once.
    function testInitializationOnlyOnce() public {
        // Setup
        vm.expectRevert("Initializable: contract is already initialized");

        // Test
        identityManager.initialize(initialRoot, verifier);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                        OWNERSHIP MANAGEMENT TESTS                       ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Taken from OwnableUpgradable.sol
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @notice Checks that it is possible to get the owner and that the owner is
    ///         correctly initialised.
    function testHasOwner() public {
        assertEq(identityManager.owner(), address(this));
    }

    /// @notice Tests that it is possible to transfer ownership of the contract.
    function testTransferOwner(address newOwner) public {
        // Setup
        vm.assume(newOwner != nullAddress);
        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(address(this), newOwner);

        // Test
        identityManager.transferOwnership(newOwner);
        assertEq(identityManager.owner(), newOwner);
    }

    /// @notice Ensures that it is impossible to transfer ownership without being the owner.
    function testCannotTransferOwnerIfNotOwner(address naughty, address newOwner) public {
        // Setup
        vm.assume(naughty != thisAddress);
        vm.prank(naughty);
        vm.expectRevert("Ownable: caller is not the owner");

        // Test
        identityManager.transferOwnership(newOwner);
    }

    /// @notice Tests that it is possible to renounce ownership.
    function testRenounceOwnership() public {
        // Test
        identityManager.renounceOwnership();
        assertEq(identityManager.owner(), nullAddress);
    }
}
