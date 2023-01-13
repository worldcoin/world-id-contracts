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

    uint256 slotCounter = 0;

    // All hardcoded test data taken from `src/test/data/TestParams.json`. This will be dynamically
    // generated at some point in the future.
    bytes32 constant inputHash = 0x7d7f77c56064e1f8577de14bba99eff85599ab0e76d0caeadd1ad61674b8a9c3;
    uint32 constant startIndex = 0;
    uint256 constant preRoot = 0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238;
    uint256 constant postRoot = 0x5c1e52b41a571293b30efacd2afdb7173b20cfaf1f646c4ac9f96eb75848270;
    uint256[] identityCommitments;
    uint256[8] proof;

    // Needed for testing things.
    uint256 constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

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

    /// @notice Moves through the slots in the identity commitments array _without_ resetting
    ///         between runs.
    function rotateSlot() public returns (uint256) {
        uint256 currentSlot = slotCounter;
        slotCounter = (slotCounter + 1) % (identityCommitments.length - 1);
        return currentSlot;
    }

    /// @notice Shallow clones an array.
    ///
    /// @param arr The array to clone.
    ///
    /// @return out The clone of `arr`.
    function cloneArray(uint256[] memory arr) public pure returns (uint256[] memory out) {
        out = new uint256[](arr.length);
        for (uint256 i = 0; i < arr.length; ++i) {
            out[i] = arr[i];
        }
        return out;
    }

    /// @notice Prepares a verifier test case.
    /// @dev This is useful to make property-based fuzz testing work better by requiring less
    ///      constraints on the generated input.
    ///
    /// @param idents The generated identity commitments to convert.
    /// @param prf The generated proof terms to convert.
    ///
    /// @return preparedIdents The conversion of `idents` to the proper type.
    /// @return actualProof The conversion of `pft` to the proper type.
    function prepareVerifierTestCase(uint128[] memory idents, uint128[8] memory prf)
        public
        returns (uint256[] memory preparedIdents, uint256[8] memory actualProof)
    {
        for (uint256 i = 0; i < idents.length; ++i) {
            vm.assume(idents[i] != 0x0);
        }
        preparedIdents = new uint256[](idents.length);
        for (uint256 i = 0; i < idents.length; ++i) {
            preparedIdents[i] = uint256(idents[i]);
        }

        actualProof = [uint256(prf[0]), prf[1], prf[2], prf[3], prf[4], prf[5], prf[6], prf[7]];
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
        delete identityManager;
        delete managerImpl;

        managerImpl = new ManagerImpl();
        managerImplAddress = address(managerImpl);
        bytes memory callData = abi.encodeCall(ManagerImpl.initialize, (initialRoot, verifier));

        vm.expectEmit(true, true, true, true);
        emit Initialized(1);

        // Test
        identityManager = new IdentityManager(managerImplAddress, callData);
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
        uint32 newStartIndex = 0;
        uint256 newPreRoot = 0;
        uint256 newPostRoot = 1;
        uint256[] memory identities;
        identities = new uint256[](3);
        identities[0] = 0x1;
        identities[1] = 0x2;
        identities[2] = 0x3;
        uint256[8] memory newProof = [uint256(0x2), 0x4, 0x6, 0x8, 0x10, 0x1, 0x3, 0x5];

        bytes memory callData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (newProof, newPreRoot, newStartIndex, identities, newPostRoot)
        );

        // Test
        assertCallSucceedsOnIdentityManager(callData);
    }

    /// @notice Checks that it is possible to call `calculateTreeVerifierInputHash`.
    function testCanCallCalculateTreeVerifierInputHash() public {
        // Setup
        uint32 newStartIndex = 0;
        uint256 newPreRoot = 0;
        uint256 newPostRoot = 1;
        uint256[] memory identities;
        identities = new uint256[](3);
        identities[0] = 0x1;
        identities[1] = 0x2;
        identities[2] = 0x3;

        bytes memory callData = abi.encodeCall(
            ManagerImpl.calculateTreeVerifierInputHash,
            (newStartIndex, newPreRoot, newPostRoot, identities)
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
