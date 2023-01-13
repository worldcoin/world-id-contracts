// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {Vm} from "forge-std/Vm.sol";
import {Test} from "forge-std/Test.sol";

import "forge-std/console.sol";

import {ITreeVerifier} from "../interfaces/ITreeVerifier.sol";
import {OwnableUpgradeable} from "contracts-upgradeable/access/OwnableUpgradeable.sol";
import {SimpleVerifier, SimpleVerify} from "./mock/SimpleVerifier.sol";
import {UUPSUpgradeable} from "contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {UUPSUpgradeable} from "contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {WorldIDIdentityManagerImplMock} from "./mock/WorldIDIdentityManagerImplMock.sol";

import {WorldIDIdentityManager as IdentityManager} from "../WorldIDIdentityManager.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImpl} from "../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Test.
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
contract WorldIDIdentityManagerTest is Test {
    ///////////////////////////////////////////////////////////////////////////////
    ///                                TEST DATA                                ///
    ///////////////////////////////////////////////////////////////////////////////

    Vm internal hevm = Vm(HEVM_ADDRESS);

    IdentityManager identityManager;
    ManagerImpl managerImpl;

    ITreeVerifier verifier = new SimpleVerifier();
    uint256 initialRoot = 0x0;

    address identityManagerAddress;
    address managerImplAddress;

    ///////////////////////////////////////////////////////////////////////////////
    ///                            TEST ORCHESTRATION                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice This function runs before every single test.
    /// @dev It is run before every single iteration of a property-based fuzzing test.
    function setUp() public {
        managerImpl = new ManagerImpl();
        managerImplAddress = address(managerImpl);

        bytes memory callData = abi.encodeCall(ManagerImpl.initialize, (initialRoot, verifier));

        identityManager = new IdentityManager(managerImplAddress, callData);
        identityManagerAddress = address(identityManager);

        hevm.label(address(this), "Sender");
        hevm.label(identityManagerAddress, "IdentityManager");
        hevm.label(managerImplAddress, "ManagerImplementation");
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                              TEST UTILITIES                             ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Asserts that making the external call using `callData` on `identityManager`
    ///         succeeds.
    ///
    /// @param callData The ABI-encoded call to a function.
    function assertCallSucceedsOnIdentityManager(bytes memory callData) public {
        (bool status, bytes memory returnData) = identityManagerAddress.call(callData);
        assert(status);
        delete returnData;
    }

    /// @notice Asserts that making the external call using `callData` on `identityManager`
    ///         succeeds.
    ///
    /// @param callData The ABI-encoded call to a function.
    /// @param expectedReturnData The expected return data from the function.
    function assertCallSucceedsOnIdentityManager(
        bytes memory callData,
        bytes memory expectedReturnData
    ) public {
        (bool status, bytes memory returnData) = identityManagerAddress.call(callData);
        assert(status);
        assertEq(expectedReturnData, returnData);
    }

    /// @notice Asserts that making the external call using `callData` on `identityManager`
    ///         fails.
    ///
    /// @param callData The ABI-encoded call to a function.
    function assertCallFailsOnIdentityManager(bytes memory callData) public {
        (bool status, bytes memory returnData) = identityManagerAddress.call(callData);
        assert(!status);
        delete returnData;
    }

    /// @notice Asserts that making the external call using `callData` on `identityManager`
    ///         fails.
    ///
    /// @param callData The ABI-encoded call to a function.
    /// @param expectedReturnData The expected return data from the function.
    function assertCallFailsOnIdentityManager(
        bytes memory callData,
        bytes memory expectedReturnData
    ) public {
        (bool status, bytes memory returnData) = identityManagerAddress.call(callData);
        assert(!status);
        assertEq(expectedReturnData, returnData);
    }

    /// @notice Performs the low-level encoding of the `revert(string)` call's return data.
    /// @dev Equivalent to `abi.encodeWithSignature("Error(string)", reason)`.
    ///
    /// @param reason The string reason for the revert.
    ///
    /// @return data The ABI encoding of the revert.
    function encodeStringRevert(string memory reason) public pure returns (bytes memory data) {
        return abi.encodeWithSignature("Error(string)", reason);
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
        identityManager = new IdentityManager(dummy, data);
    }

    /// @notice Tests that it is possible to properly construct and initialise
    function testCanConstructIdentityManagerWithDelegate() public {
        // Setup
        vm.expectEmit(true, true, true, true);
        emit Initialized(1);
        managerImpl = new ManagerImpl();
        bytes memory callData = abi.encodeCall(ManagerImpl.initialize, (initialRoot, verifier));

        // Test
        identityManager = new IdentityManager(address(managerImpl), callData);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                           INITIALIZATION TESTS                          ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Checks that it is possible to initialise the contract.
    function testInitialisation() public {
        // Setup
        // identityManager = new IdentityManager();
        // managerImpl = new ManagerImpl();
        // vm.expectEmit(true, true, true, true);
        // emit Initialized(1);

        // Test
        // identityManager.initialize(initialRoot, verifier);
    }

    /// @notice Checks that it is not possible to initialise the contract more than once.
    function testInitializationOnlyOnce() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImpl.initialize, (initialRoot, verifier));
        bytes memory expectedReturn =
            encodeStringRevert("Initializable: contract is already initialized");

        // Test
        assertCallFailsOnIdentityManager(callData, expectedReturn);
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
        assertCallSucceedsOnIdentityManager(upgradeCall, new bytes(0x0));
    }

    /// @notice Tests that it is possible to upgrade to a new implementation and call a function on
    ///         that new implementation in the same transaction.
    function testCanUpgradeImplementationWithCall() public {
        // Setup
        WorldIDIdentityManagerImplMock mockUpgrade = new WorldIDIdentityManagerImplMock();
        bytes memory initCall = abi.encodeCall(WorldIDIdentityManagerImplMock.initializeV2, (320));
        bytes memory upgradeCall =
            abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (address(mockUpgrade), initCall));

        // Test
        assertCallSucceedsOnIdentityManager(upgradeCall, new bytes(0x0));
    }

    /// @notice Tests that an upgrade cannot be performed by anybody other than the manager.
    function testCannotUpgradeUnlessManager(address naughty) public {
        // Setup
        vm.assume(naughty != address(this) || naughty != address(0x0));
        WorldIDIdentityManagerImplMock mockUpgrade = new WorldIDIdentityManagerImplMock();
        bytes memory initCall = abi.encodeCall(ManagerImpl.initialize, (initialRoot, verifier));
        bytes memory upgradeCall =
            abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (address(mockUpgrade), initCall));
        vm.prank(naughty);

        // Test
        assertCallFailsOnIdentityManager(
            upgradeCall, encodeStringRevert("Ownable: caller is not the owner")
        );
    }

    // TODO [Ara] testCannotUpgradeWithoutProxy

    ///////////////////////////////////////////////////////////////////////////////
    ///                            FUNCTIONALITY TESTS                          ///
    ///////////////////////////////////////////////////////////////////////////////

    // Note Comprehensive functionality tests are located in WorldIDIdentityManagerImplV1.sol. These
    // tests are purely to ensure that we can call all of the necessary functions properly through
    // the proxy, and to act as documentation for how to encode calls to said functions.

    // TODO [Ara] `testCanCall*` tests

    /// @notice Checks that it is possible to call `owner()`.
    function testCanCallOwner() public {
        // Setup
        bytes memory callData = abi.encodeCall(OwnableUpgradeable.owner, ());

        // Test
        assertCallSucceedsOnIdentityManager(callData);
    }

    /// @notice Checks that it is possible to call `transferOwnership()`.
    function testCanCallTransferOwnership() public {
        // Setup
        address newOwner = address(0x0ddba11);
        bytes memory callData = abi.encodeCall(OwnableUpgradeable.transferOwnership, (newOwner));

        // Test
        assertCallSucceedsOnIdentityManager(callData);
    }

    /// @notice Checks that it is possible to call `renounceOwnership`.
    function testCanCallRenounceOwnership() public {
        // Setup
        bytes memory callData = abi.encodeCall(OwnableUpgradeable.renounceOwnership, ());

        // Test
        assertCallSucceedsOnIdentityManager(callData);
    }

    /// @notice Checks that it is possible to call `NO_SUCH_ROOT`.
    function testCanCallNoSuchRoot() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImpl.NO_SUCH_ROOT, ());

        // Test
        assertCallSucceedsOnIdentityManager(callData);
    }

    /// @notice Checks that it is possible to call `registerIdentities`.
    function testCanCallRegisterIdentities() public {
        // Setup
        uint32 startIndex = 0;
        uint256 preRoot = 0;
        uint256 postRoot = 1;
        uint256[] memory identityCommitments;
        identityCommitments = new uint256[](3);
        identityCommitments[0] = 0x1;
        identityCommitments[1] = 0x2;
        identityCommitments[2] = 0x3;
        uint256[8] memory proof = [uint256(0x2), 0x4, 0x6, 0x8, 0x10, 0x1, 0x3, 0x5];

        bytes memory callData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (proof, preRoot, startIndex, identityCommitments, postRoot)
        );

        // Test
        assertCallSucceedsOnIdentityManager(callData);
    }

    /// @notice Checks that it is possible to call `calculateTreeVerifierInputHash`.
    function testCanCallCalculateTreeVerifierInputHash() public {
        // Setup
        uint32 startIndex = 0;
        uint256 preRoot = 0;
        uint256 postRoot = 1;
        uint256[] memory identityCommitments;
        identityCommitments = new uint256[](3);
        identityCommitments[0] = 0x1;
        identityCommitments[1] = 0x2;
        identityCommitments[2] = 0x3;

        bytes memory callData = abi.encodeCall(
            ManagerImpl.calculateTreeVerifierInputHash,
            (startIndex, preRoot, postRoot, identityCommitments)
        );

        // Test
        assertCallSucceedsOnIdentityManager(callData);
    }

    /// @notice Checks that it is possible to call `queryRoot`.
    function testCanCallQueryRoot() public {
        // Setup
        uint256 root = 0xc0ffee;
        bytes memory callData = abi.encodeCall(ManagerImpl.queryRoot, (root));

        // Test
        assertCallSucceedsOnIdentityManager(callData);
    }

    /// @notice Checks that it is possible to call `isInputInReducedForm`.
    function testIsInputInReducedForm() public {
        // Setup
        uint256 inputNumber = 0xc0ffee;
        bytes memory callData = abi.encodeCall(ManagerImpl.isInputInReducedForm, (inputNumber));

        // Test
        assertCallSucceedsOnIdentityManager(callData);
    }

    /// @notice Checks that it is possible to call `checkValidRoot`.
    function testCanCallCheckValidRoot() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImpl.checkValidRoot, (initialRoot));

        // Test
        assertCallSucceedsOnIdentityManager(callData);
    }
}
