// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {Vm} from "forge-std/Vm.sol";
import {Test} from "forge-std/Test.sol";

import "forge-std/console.sol";

import {ITreeVerifier} from "../interfaces/ITreeVerifier.sol";
import {OwnableUpgradeable} from "contracts-upgradeable/access/OwnableUpgradeable.sol";
import {SimpleStateBridge} from "./mock/SimpleStateBridge.sol";
import {SimpleVerifier, SimpleVerify} from "./mock/SimpleVerifier.sol";
import {UUPSUpgradeable} from "contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Verifier as SemaphoreVerifier} from "semaphore/base/Verifier.sol";
import {Verifier as TreeVerifier} from "./mock/TreeVerifier.sol";
import {WorldIDIdentityManagerImplMock} from "./mock/WorldIDIdentityManagerImplMock.sol";
import {CheckInitialized} from "../utils/CheckInitialized.sol";

import {WorldIDIdentityManager as IdentityManager} from "../WorldIDIdentityManager.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImpl} from "../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Test.
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerTest is Test {
    ///////////////////////////////////////////////////////////////////////////////
    ///                                TEST DATA                                ///
    ///////////////////////////////////////////////////////////////////////////////

    Vm internal hevm = Vm(HEVM_ADDRESS);

    IdentityManager identityManager;
    ManagerImpl managerImpl;

    ITreeVerifier verifier;
    uint256 initialRoot = 0x0;

    address identityManagerAddress;
    address managerImplAddress;

    uint256 slotCounter = 0;

    address nullAddress = address(0x0);
    address thisAddress = address(this);

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

    // StateBridgeProxy mock
    SimpleStateBridge stateBridge;
    address public stateBridgeProxy;
    bool isStateBridgeEnabled = true;

    event StateRootSentMultichain(uint256 indexed root);

    ///////////////////////////////////////////////////////////////////////////////
    ///                            TEST ORCHESTRATION                           ///
    ///////////////////////////////////////////////////////////////////////////////

    constructor() {
        // Make the identity commitments.
        identityCommitments = new uint256[](3);
        identityCommitments[0] = 0x1;
        identityCommitments[1] = 0x2;
        identityCommitments[2] = 0x3;

        // Create the proof term.
        proof = [
            0x2a45bf326884bbf13c821a5e4f30690a391156cccf80a2922fb24250111dd7eb,
            0x23a7376a159513e6d0e22d43fcdca9d0c8a5c54a73b59fce6962a41e71355894,
            0x21b9fc7c2d1f76c2e1a972b00f18728a57a34d7e4ae040811bf1626132ff3658,
            0x2a7c3c660190a33ab92cd84e4b2540e49ea80bdc766eb3aeec49806a78071c75,
            0x2fc9a52a7f4bcc29faab28a8d8ec126b4fe604a7b41e7d2b3efe92422951d706,
            0x110740f0b21fb329de682dffc95a5ede11c11c6328606fe254b6ba469b15f68,
            0x23115ff1573808639f19724479b195b7894a45c9868242ad2a416767359c6c78,
            0x23f3fa30273c7f38e360496e7f9790450096d4a9592e1fe6e0a996cb05b8fb28
        ];
    }

    /// @notice This function runs before every single test.
    /// @dev It is run before every single iteration of a property-based fuzzing test.
    function setUp() public {
        verifier = new SimpleVerifier();
        stateBridge = new SimpleStateBridge();
        stateBridgeProxy = address(stateBridge);
        makeNewIdentityManager(initialRoot, verifier, isStateBridgeEnabled, stateBridgeProxy);

        hevm.label(address(this), "Sender");
        hevm.label(identityManagerAddress, "IdentityManager");
        hevm.label(managerImplAddress, "ManagerImplementation");
        hevm.label(stateBridgeProxy, "StateBridgeProxy");
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                              TEST UTILITIES                             ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Initialises a new identity manager using the provided information.
    /// @dev It is initialised in the globals.
    ///
    /// @param actualPreRoot The pre-root to use.
    /// @param actualVerifier The verifier instance to use.
    /// @param enableStateBridge Whether or not the new identity manager should have the state
    ///        bridge enabled.
    /// @param actualStateBridgeProxy The address of the state bridge.
    function makeNewIdentityManager(
        uint256 actualPreRoot,
        ITreeVerifier actualVerifier,
        bool enableStateBridge,
        address actualStateBridgeProxy
    ) public {
        managerImpl = new ManagerImpl();
        managerImplAddress = address(managerImpl);

        bytes memory initCallData = abi.encodeCall(
            ManagerImpl.initialize,
            (actualPreRoot, actualVerifier, enableStateBridge, actualStateBridgeProxy)
        );

        identityManager = new IdentityManager(managerImplAddress, initCallData);
        identityManagerAddress = address(identityManager);
    }

    /// @notice Creates a new identity manager without initializing the delegate.
    /// @dev Uses the global variables.
    function makeUninitIdentityManager() public {
        managerImpl = new ManagerImpl();
        managerImplAddress = address(managerImpl);
        identityManager = new IdentityManager(managerImplAddress, new bytes(0x0));
        identityManagerAddress = address(identityManager);
    }

    /// @notice Asserts that making the external call using `callData` on `identityManager`
    ///         succeeds.
    ///
    /// @param target The target at which to make the call.
    /// @param callData The ABI-encoded call to a function.
    function assertCallSucceedsOn(address target, bytes memory callData) public {
        (bool status,) = target.call(callData);
        assert(status);
    }

    /// @notice Asserts that making the external call using `callData` on `identityManager`
    ///         succeeds.
    ///
    /// @param target The target at which to make the call.
    /// @param callData The ABI-encoded call to a function.
    /// @param expectedReturnData The expected return data from the function.
    function assertCallSucceedsOn(
        address target,
        bytes memory callData,
        bytes memory expectedReturnData
    ) public {
        (bool status, bytes memory returnData) = target.call(callData);
        assert(status);
        assertEq(expectedReturnData, returnData);
    }

    /// @notice Asserts that making the external call using `callData` on `identityManager`
    ///         fails.
    ///
    /// @param target The target at which to make the call.
    /// @param callData The ABI-encoded call to a function.
    function assertCallFailsOn(address target, bytes memory callData) public {
        (bool status,) = target.call(callData);
        assert(!status);
    }

    /// @notice Asserts that making the external call using `callData` on `identityManager`
    ///         fails.
    ///
    /// @param target The target at which to make the call.
    /// @param callData The ABI-encoded call to a function.
    /// @param expectedReturnData The expected return data from the function.
    function assertCallFailsOn(
        address target,
        bytes memory callData,
        bytes memory expectedReturnData
    ) public {
        (bool status, bytes memory returnData) = target.call(callData);
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
        bytes memory callData = abi.encodeCall(
            ManagerImpl.initialize, (initialRoot, verifier, isStateBridgeEnabled, stateBridgeProxy)
        );

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

    ///////////////////////////////////////////////////////////////////////////////
    ///                               UPGRADE TESTS                             ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Tests that it is possible to upgrade to a new implementation.
    function testCanUpgradeImplementationWithoutCall() public {
        // Setup
        WorldIDIdentityManagerImplMock mockUpgrade = new WorldIDIdentityManagerImplMock();
        bytes memory upgradeCall = abi.encodeCall(UUPSUpgradeable.upgradeTo, (address(mockUpgrade)));

        // Test
        assertCallSucceedsOn(identityManagerAddress, upgradeCall, new bytes(0x0));
    }

    /// @notice Tests that it is possible to upgrade to a new implementation and call a function on
    ///         that new implementation in the same transaction.
    function testCanUpgradeImplementationWithCall() public {
        // Setup
        WorldIDIdentityManagerImplMock mockUpgrade = new WorldIDIdentityManagerImplMock();
        bytes memory initCall = abi.encodeCall(WorldIDIdentityManagerImplMock.initialize, (320));
        bytes memory upgradeCall =
            abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (address(mockUpgrade), initCall));

        // Test
        assertCallSucceedsOn(identityManagerAddress, upgradeCall, new bytes(0x0));
    }

    /// @notice Tests that an upgrade cannot be performed by anybody other than the manager.
    function testCannotUpgradeUnlessManager(address naughty) public {
        // Setup
        vm.assume(naughty != address(this) && naughty != address(0x0));
        WorldIDIdentityManagerImplMock mockUpgrade = new WorldIDIdentityManagerImplMock();
        bytes memory initCall = abi.encodeCall(WorldIDIdentityManagerImplMock.initialize, (320));
        bytes memory upgradeCall =
            abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (address(mockUpgrade), initCall));
        vm.prank(naughty);

        // Test
        assertCallFailsOn(
            identityManagerAddress,
            upgradeCall,
            encodeStringRevert("Ownable: caller is not the owner")
        );
    }

    /// @notice Tests that an upgrade cannot be performed unless done through the proxy.
    function testCannotUpgradeWithoutProxy() public {
        // Setup
        WorldIDIdentityManagerImplMock mockUpgrade = new WorldIDIdentityManagerImplMock();
        address mockUpgradeAddress = address(mockUpgrade);
        bytes memory initCall = abi.encodeCall(
            ManagerImpl.initialize, (initialRoot, verifier, isStateBridgeEnabled, stateBridgeProxy)
        );
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.upgradeToAndCall(mockUpgradeAddress, initCall);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                               STATE BRIDGE                              ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Tests that it is possible to upgrade `stateBridgeProxy` to a new implementation.
    function testCanUpgradeStateBridgeProxy(address newStateBridgeProxy) public {
        vm.assume(newStateBridgeProxy != address(0x0) && newStateBridgeProxy != address(this));
        // Setup
        bytes memory callData =
            abi.encodeCall(ManagerImpl.setStateBridgeProxyAddress, (newStateBridgeProxy));

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, new bytes(0x0));
    }

    /// @notice Tests that it is possible to disable the `stateBridgeProxy`.
    function testCanDisableStateBridgeFunctionality() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImpl.disableStateBridge, ());

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, new bytes(0x0));

        // Registering an identity after disabling the state bridge should not fail
        testRegisterIdentitiesWithCorrectInputsFromKnown();
    }

    /// @notice Tests that it is not possible to upgrade `stateBridgeProxy` to the 0x0 address.
    function testCannotUpgradeStateBridgeToZeroAddress() public {
        // address used to disable the state bridge functionality
        address zeroAddress = address(0x0);
        // Setup
        bytes memory callData =
            abi.encodeCall(ManagerImpl.setStateBridgeProxyAddress, (zeroAddress));

        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.InvalidStateBridgeProxyAddress.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `setStateBridgeProxyAddress` as a non-owner.
    function testCannotUpdateStateBridgeAsNonOwner(address nonManager) public {
        // Setup
        vm.assume(nonManager != address(this) && nonManager != address(0x0));

        bytes memory callData =
            abi.encodeCall(ManagerImpl.setStateBridgeProxyAddress, (address(0x1)));

        bytes memory errorData = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(nonManager);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Checks that the state bridge can be enabled if it is disabled.
    function testCanEnableStateBridgeIfDisabled() public {
        // Setup
        makeNewIdentityManager(preRoot, verifier, false, stateBridgeProxy);
        bytes memory callData = abi.encodeCall(ManagerImpl.enableStateBridge, ());

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, new bytes(0x0));
    }

    /// @notice Tests that it is impossible to enable the `stateBridgeProxy` if it is already
    ///         enabled.
    function testCannotEnableStateBridgeIfAlreadyEnabled() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImpl.enableStateBridge, ());

        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.StateBridgeAlreadyEnabled.selector);
        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that it is impossible to disabled the `stateBridgeProxy` if it is already
    ///         disabled.
    function testCannotDisableStateBridgeIfAlreadyDisabled() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImpl.disableStateBridge, ());

        // disable state bridge
        assertCallSucceedsOn(identityManagerAddress, callData, new bytes(0x0));

        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.StateBridgeAlreadyDisabled.selector);
        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                        OWNERSHIP MANAGEMENT TESTS                       ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Taken from OwnableUpgradable.sol
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @notice Checks that it is possible to get the owner, and that the owner is correctly
    ///         initialised.
    function testHasOwner() public {
        // Setup
        bytes memory callData = abi.encodeCall(OwnableUpgradeable.owner, ());
        bytes memory expectedReturn = abi.encode(address(this));

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, expectedReturn);
    }

    /// @notice Tests that it is possible to transfer ownership of the contract.
    function testTransferOwner(address newOwner) public {
        // Setup
        vm.assume(newOwner != nullAddress);
        bytes memory transferCallData =
            abi.encodeCall(OwnableUpgradeable.transferOwnership, (newOwner));
        bytes memory ownerCallData = abi.encodeCall(OwnableUpgradeable.owner, ());
        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(thisAddress, newOwner);

        // Test
        assertCallSucceedsOn(identityManagerAddress, transferCallData, new bytes(0x0));
        assertCallSucceedsOn(identityManagerAddress, ownerCallData, abi.encode(newOwner));
    }

    /// @notice Ensures that it is impossible to transfer ownership without being the owner.
    function testCannotTransferOwnerIfNotOwner(address naughty, address newOwner) public {
        // Setup
        vm.assume(naughty != thisAddress && newOwner != nullAddress);
        bytes memory callData = abi.encodeCall(OwnableUpgradeable.transferOwnership, (newOwner));
        bytes memory expectedReturn = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(naughty);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedReturn);
    }

    /// @notice Tests that it is possible to renounce ownership.
    function testRenounceOwnership() public {
        // Setup
        bytes memory renounceData = abi.encodeCall(OwnableUpgradeable.renounceOwnership, ());
        bytes memory ownerData = abi.encodeCall(OwnableUpgradeable.owner, ());

        // Test
        assertCallSucceedsOn(identityManagerAddress, renounceData);
        assertCallSucceedsOn(identityManagerAddress, ownerData, abi.encode(nullAddress));
    }

    /// @notice Ensures that ownership cannot be renounced by anybody other than the owner.
    function testCannotRenounceOwnershipIfNotOwner(address naughty) public {
        // Setup
        vm.assume(naughty != thisAddress && naughty != nullAddress);
        bytes memory callData = abi.encodeCall(OwnableUpgradeable.renounceOwnership, ());
        bytes memory returnData = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(naughty);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, returnData);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                         IDENTITY MANAGEMENT TESTS                       ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Checks that the proof validates properly with the correct inputs.
    function testRegisterIdentitiesWithCorrectInputsFromKnown() public {
        // Setup
        ITreeVerifier actualVerifier = new TreeVerifier();
        makeNewIdentityManager(preRoot, actualVerifier, isStateBridgeEnabled, stateBridgeProxy);
        bytes memory registerCallData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (proof, preRoot, startIndex, identityCommitments, postRoot)
        );
        bytes memory latestRootCallData = abi.encodeCall(ManagerImpl.latestRoot, ());
        bytes memory queryRootCallData = abi.encodeCall(ManagerImpl.queryRoot, (postRoot));

        // expect event that state root was sent to state bridge
        vm.expectEmit(true, true, true, true);
        emit StateRootSentMultichain(postRoot);

        // Test
        assertCallSucceedsOn(identityManagerAddress, registerCallData);
        assertCallSucceedsOn(identityManagerAddress, latestRootCallData, abi.encode(postRoot));
        assertCallSucceedsOn(
            identityManagerAddress,
            queryRootCallData,
            abi.encode(ManagerImpl.RootInfo(postRoot, 0, true))
        );
    }

    /// @notice Checks that the proof validates properly with correct inputs.
    function testRegisterIdentitiesWithCorrectInputs(
        uint128[8] memory prf,
        uint32 newStartIndex,
        uint128 newPreRoot,
        uint128 newPostRoot,
        uint128[] memory identities
    ) public {
        // Setup
        vm.assume(SimpleVerify.isValidInput(uint256(prf[0])));
        vm.assume(newPreRoot != newPostRoot);
        makeNewIdentityManager(newPreRoot, verifier, isStateBridgeEnabled, stateBridgeProxy);
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareVerifierTestCase(identities, prf);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (actualProof, newPreRoot, newStartIndex, preparedIdents, newPostRoot)
        );

        // expect event that state root was sent to state bridge
        vm.expectEmit(true, true, true, true);
        emit StateRootSentMultichain(newPostRoot);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
    }

    /// @notice Checks that it reverts if the provided proof is incorrect for the public inputs.
    function testCannotRegisterIdentitiesWithIncorrectInputs(
        uint128[8] memory prf,
        uint32 newStartIndex,
        uint128 newPreRoot,
        uint128 newPostRoot,
        uint128[] memory identities
    ) public {
        // Setup
        vm.assume(!SimpleVerify.isValidInput(uint256(prf[0])));
        vm.assume(newPreRoot != newPostRoot);
        makeNewIdentityManager(newPreRoot, verifier, isStateBridgeEnabled, stateBridgeProxy);
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareVerifierTestCase(identities, prf);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (actualProof, newPreRoot, newStartIndex, preparedIdents, newPostRoot)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.ProofValidationFailure.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it reverts if the provided start index is incorrect.
    function testCannotRegisterIdentitiesIfStartIndexIncorrect(uint32 newStartIndex) public {
        // Setup
        vm.assume(newStartIndex != startIndex);
        ITreeVerifier actualVerifier = new TreeVerifier();
        makeNewIdentityManager(preRoot, actualVerifier, isStateBridgeEnabled, stateBridgeProxy);
        bytes memory registerCallData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (proof, preRoot, newStartIndex, identityCommitments, postRoot)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.ProofValidationFailure.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, registerCallData, expectedError);
    }

    /// @notice Checks that it reverts if the provided set of identities is incorrect.
    function testCannotRegisterIdentitiesIfIdentitiesIncorrect(uint256 identity) public {
        // Setup
        uint256 invalidSlot = rotateSlot();
        vm.assume(
            identity != identityCommitments[invalidSlot] && identity < SNARK_SCALAR_FIELD
                && identity != 0x0
        );
        uint256[] memory identities = cloneArray(identityCommitments);
        identities[invalidSlot] = identity;
        ITreeVerifier actualVerifier = new TreeVerifier();
        makeNewIdentityManager(preRoot, actualVerifier, isStateBridgeEnabled, stateBridgeProxy);
        bytes memory registerCallData = abi.encodeCall(
            ManagerImpl.registerIdentities, (proof, preRoot, startIndex, identities, postRoot)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.ProofValidationFailure.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, registerCallData, expectedError);
    }

    /// @notice Checks that it reverts if the provided post root is incorrect.
    function testCannotRegisterIdentitiesIfPostRootIncorrect(uint256 newPostRoot) public {
        // Setup
        vm.assume(newPostRoot != postRoot && newPostRoot < SNARK_SCALAR_FIELD);
        managerImpl = new ManagerImpl();
        managerImplAddress = address(managerImpl);
        ITreeVerifier actualVerifier = new TreeVerifier();

        bytes memory callData = abi.encodeCall(
            ManagerImpl.initialize,
            (preRoot, actualVerifier, isStateBridgeEnabled, stateBridgeProxy)
        );

        identityManager = new IdentityManager(managerImplAddress, callData);
        identityManagerAddress = address(identityManager);
        bytes memory registerCallData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (proof, preRoot, startIndex, identityCommitments, newPostRoot)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.ProofValidationFailure.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, registerCallData, expectedError);
    }

    /// @notice Tests that it reverts if an attempt is made to register identities as a non-manager.
    function testCannotRegisterIdentitiesAsNonManager(address nonManager) public {
        // Setup
        vm.assume(nonManager != address(this) && nonManager != address(0x0));
        bytes memory callData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (proof, preRoot, startIndex, identityCommitments, postRoot)
        );
        bytes memory errorData = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(nonManager);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Tests that it reverts if an attempt is made to register identities with an outdated
    ///         root.
    function testCannotRegisterIdentitiesWithOutdatedRoot(
        uint256 currentPreRoot,
        uint256 actualRoot
    ) public {
        // Setup
        vm.assume(
            currentPreRoot != actualRoot && currentPreRoot < SNARK_SCALAR_FIELD
                && actualRoot < SNARK_SCALAR_FIELD
        );
        makeNewIdentityManager(
            uint256(currentPreRoot), verifier, isStateBridgeEnabled, stateBridgeProxy
        );
        bytes memory callData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (proof, actualRoot, startIndex, identityCommitments, postRoot)
        );
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImpl.NotLatestRoot.selector, actualRoot, uint256(currentPreRoot)
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that it reverts if an attempt is made to register identity commitments
    ///         containing an invalid identity.
    function testCannotRegisterIdentitiesWithInvalidIdentities(
        uint8 identitiesLength,
        uint8 invalidPosition
    ) public {
        // Setup
        vm.assume(identitiesLength != 0);
        vm.assume(invalidPosition < (identitiesLength - 1));
        uint256[] memory invalidCommitments = new uint256[](identitiesLength);

        for (uint256 i = 0; i < identitiesLength; ++i) {
            invalidCommitments[i] = i + 1;
        }
        invalidCommitments[invalidPosition] = 0x0;

        bytes memory callData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (proof, initialRoot, startIndex, invalidCommitments, postRoot)
        );
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImpl.InvalidCommitment.selector, uint256(invalidPosition + 1)
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that runs of zeroes are accepted by the `registerIdentities` function as valid
    ///         arrays of identity commitments.
    function testRegisterIdentitiesWithRunsOfZeroes(uint8 identitiesLength, uint8 zeroPosition)
        public
    {
        // Setup
        vm.assume(identitiesLength != 0);
        vm.assume(zeroPosition < identitiesLength && zeroPosition > 0);
        uint256[] memory identities = new uint256[](identitiesLength);

        for (uint256 i = 0; i < zeroPosition; ++i) {
            identities[i] = i + 1;
        }
        for (uint256 i = zeroPosition; i < identitiesLength; ++i) {
            identities[i] = 0x0;
        }

        bytes memory callData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            ([uint256(2), 1, 3, 4, 5, 6, 7, 9], initialRoot, startIndex, identities, postRoot)
        );

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, new bytes(0));
    }

    // TODO [Ara] Function to check that runs of zeroes are valid.

    /// @notice Tests that it reverts if an attempt is made to register identity commitments that
    ///         are not in reduced form.
    function testCannotRegisterIdentitiesWithUnreducedIdentities(uint128 i) public {
        // Setup
        uint256 position = rotateSlot();
        uint256[] memory unreducedCommitments = new uint256[](identityCommitments.length);
        unreducedCommitments[position] = SNARK_SCALAR_FIELD + i;
        bytes memory callData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (proof, initialRoot, startIndex, unreducedCommitments, postRoot)
        );
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImpl.UnreducedElement.selector,
            ManagerImpl.UnreducedElementType.IdentityCommitment,
            SNARK_SCALAR_FIELD + i
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that it reverts if an attempt is made to register new identities with a pre
    ///         root that is not in reduced form.
    function testCannotRegisterIdentitiesWithUnreducedPreRoot(uint128 i) public {
        // Setup
        uint256 newPreRoot = SNARK_SCALAR_FIELD + i;
        bytes memory callData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (proof, newPreRoot, startIndex, identityCommitments, postRoot)
        );
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImpl.UnreducedElement.selector,
            ManagerImpl.UnreducedElementType.PreRoot,
            newPreRoot
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that it reverts if an attempt is made to register identities with a postRoot
    ///         that is not in reduced form.
    function testCannotRegisterIdentitiesWithUnreducedPostRoot(uint128 i) public {
        // Setup
        uint256 newPostRoot = SNARK_SCALAR_FIELD + i;
        bytes memory callData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (proof, initialRoot, startIndex, identityCommitments, newPostRoot)
        );
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImpl.UnreducedElement.selector,
            ManagerImpl.UnreducedElementType.PostRoot,
            newPostRoot
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that it reverts if an attempt is made to violate type safety and register with
    ///         a startIndex that is not type safe within the bounds of `type(uint32).max` and hence
    ///         within `SNARK_SCALAR_FIELD`.
    function testCannotRegisterIdentitiesWithUnreducedStartIndex(uint256 i) public {
        // Setup
        vm.assume(i > type(uint32).max);
        bytes4 functionSelector = ManagerImpl.registerIdentities.selector;
        // Have to encode with selector as otherwise it's typechecked.
        bytes memory callData = abi.encodeWithSelector(
            functionSelector, proof, preRoot, i, identityCommitments, postRoot
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData);
    }

    /// @notice Tests that identities can only be registered through the proxy.
    function testCannotRegisterIdentitiesIfNotViaProxy() public {
        // Setup
        address expectedOwner = managerImpl.owner();
        vm.expectRevert("Function must be called through delegatecall");
        vm.prank(expectedOwner);

        // Test
        managerImpl.registerIdentities(
            proof, initialRoot, startIndex, identityCommitments, postRoot
        );
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                            DATA QUERYING TESTS                          ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Tests whether it is possible to query accurate information about the current root.
    function testQueryCurrentRoot(uint128 newPreRoot) public {
        // Setup
        makeNewIdentityManager(newPreRoot, verifier, isStateBridgeEnabled, stateBridgeProxy);
        bytes memory callData = abi.encodeCall(ManagerImpl.queryRoot, newPreRoot);
        bytes memory returnData = abi.encode(ManagerImpl.RootInfo(newPreRoot, 0, true));

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Tests whether it is possible to query accurate information about an arbitrary root.
    function testQueryOlderRoot(
        uint128[8] memory prf,
        uint32 newStartIndex,
        uint128 newPreRoot,
        uint128 newPostRoot,
        uint128[] memory identities
    ) public {
        // Setup
        vm.assume(SimpleVerify.isValidInput(uint256(prf[0])));
        vm.assume(newPreRoot != newPostRoot);
        makeNewIdentityManager(newPreRoot, verifier, isStateBridgeEnabled, stateBridgeProxy);
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareVerifierTestCase(identities, prf);
        bytes memory registerCallData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (actualProof, newPreRoot, newStartIndex, preparedIdents, newPostRoot)
        );

        // expect event that state root was sent to state bridge
        vm.expectEmit(true, true, true, true);
        emit StateRootSentMultichain(newPostRoot);

        assertCallSucceedsOn(identityManagerAddress, registerCallData);
        bytes memory queryCallData = abi.encodeCall(ManagerImpl.queryRoot, (newPreRoot));
        bytes memory returnData =
            abi.encode(ManagerImpl.RootInfo(newPreRoot, uint128(block.timestamp), true));

        // Test
        assertCallSucceedsOn(identityManagerAddress, queryCallData, returnData);
    }

    /// @notice Tests whether it is possible to query accurate information about an expired root.
    function testQueryExpiredRoot(
        uint128[8] memory prf,
        uint32 newStartIndex,
        uint128 newPreRoot,
        uint128 newPostRoot,
        uint128[] memory identities
    ) public {
        // Setup
        vm.assume(newPreRoot != newPostRoot);
        vm.assume(SimpleVerify.isValidInput(uint256(prf[0])));
        makeNewIdentityManager(newPreRoot, verifier, isStateBridgeEnabled, stateBridgeProxy);
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareVerifierTestCase(identities, prf);
        uint256 originalTimestamp = block.timestamp;
        bytes memory registerCallData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (actualProof, newPreRoot, newStartIndex, preparedIdents, newPostRoot)
        );

        // expect event that state root was sent to state bridge
        vm.expectEmit(true, true, true, true);
        emit StateRootSentMultichain(newPostRoot);

        assertCallSucceedsOn(identityManagerAddress, registerCallData);
        bytes memory queryCallData = abi.encodeCall(ManagerImpl.queryRoot, (newPreRoot));
        bytes memory returnData =
            abi.encode(ManagerImpl.RootInfo(newPreRoot, uint128(originalTimestamp), false));
        vm.warp(originalTimestamp + 2 hours); // Force preRoot to expire

        // Test
        assertCallSucceedsOn(identityManagerAddress, queryCallData, returnData);

        // Cleanup
        vm.warp(originalTimestamp);
    }

    /// @notice Checks that we get `NO_SUCH_ROOT` back when we query for information about an
    ///         invalid root.
    function testQueryInvalidRoot(uint256 badRoot) public {
        // Setup
        vm.assume(badRoot != initialRoot);
        bytes memory callData = abi.encodeCall(ManagerImpl.queryRoot, badRoot);
        bytes memory returnData = abi.encode(managerImpl.NO_SUCH_ROOT());

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Checks that the root can only be queried if behind the proxy.
    function testCannotQueryRootIfNotViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.queryRoot(initialRoot);
    }

    /// @notice Checks that it is possible to get the latest root from the contract.
    function testCanGetLatestRoot(uint256 actualRoot) public {
        // Setup
        makeNewIdentityManager(actualRoot, verifier, isStateBridgeEnabled, stateBridgeProxy);
        bytes memory callData = abi.encodeCall(ManagerImpl.latestRoot, ());
        bytes memory returnData = abi.encode(actualRoot);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Checks that the latest root can only be obtained if behind the proxy.
    function testCannotGetLatestRootIfNotViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.latestRoot();
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                             CALCULATION TESTS                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Tests whether it is possible to correctly calculate the `inputHash` to the merkle
    ///         tree verifier.
    function testCalculateInputHashFromParametersOnKnownInput() public {
        // Setup
        bytes memory callData = abi.encodeCall(
            ManagerImpl.calculateTreeVerifierInputHash,
            (startIndex, preRoot, postRoot, identityCommitments)
        );
        bytes memory returnData = abi.encode(inputHash);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Checks that the input hash can only be calculated if behind the proxy.
    function testCannotCalculateInputHashIfNotViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.calculateTreeVerifierInputHash(
            startIndex, preRoot, postRoot, identityCommitments
        );
    }

    /// @notice Tests whether it is possible to check whether values are in reduced form.
    function testCanCheckValueIsInReducedForm(uint256 value) public {
        // Setup
        vm.assume(value < SNARK_SCALAR_FIELD);
        bytes memory callData = abi.encodeCall(ManagerImpl.isInputInReducedForm, (value));
        bytes memory returnData = abi.encode(true);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Tests whether it is possible to detect un-reduced values.
    function testCanCheckValueIsNotInReducedForm(uint256 value) public {
        // Setup
        vm.assume(value >= SNARK_SCALAR_FIELD);
        bytes memory callData = abi.encodeCall(ManagerImpl.isInputInReducedForm, (value));
        bytes memory returnData = abi.encode(false);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, returnData);
    }

    /// @notice Checks that reduced form checking can only be done from behind a proxy.
    function testCannotCheckValidIsInReducedFormIfNotViaProxy() public {
        // Setup
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.isInputInReducedForm(preRoot);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                            SETTERS AND GETTERS                          ///
    ///////////////////////////////////////////////////////////////////////////////

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

    ///////////////////////////////////////////////////////////////////////////////
    ///                                UNINIT TEST                              ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Checks that it is impossible to call `registerIdentities` while the contract is not
    ///         initialised.
    function testShouldNotCallRegisterIdentitiesWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (proof, preRoot, startIndex, identityCommitments, postRoot)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `calculateTreeVerifierInputHash` while the
    ///         contract is not initialised.
    function testShouldNotCallCalculateInputHash() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(
            ManagerImpl.calculateTreeVerifierInputHash,
            (startIndex, preRoot, postRoot, identityCommitments)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `latestRoot` while the contract is not
    ///         initialised.
    function testShouldNotCallLatestRootWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(ManagerImpl.latestRoot, ());
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `queryRoot` while the contract is not
    ///         initialised.
    function testShouldNotCallQueryRootWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(ManagerImpl.queryRoot, (preRoot));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `isInputInReducedForm` while the contract is
    ///         not initialised.
    function testShouldNotCallIsInputInReducedFormWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(ManagerImpl.isInputInReducedForm, (preRoot));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `checkValidRoot` while the contract is not
    ///         initialised.
    function testShouldNotCallCheckValidRootWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(ManagerImpl.checkValidRoot, (preRoot));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `getRegisterIdentitiesVerifierAddress` while
    ///         the contract is not initialized.
    function testShouldNotCallgetRegisterIdentitiesVerifierAddressWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(ManagerImpl.getRegisterIdentitiesVerifierAddress, ());
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `setRegisterIdentitiesVerifier` while the
    ///        contract is not initialized.
    function testShouldNotCallSetRegisterIdentitiesVerifierWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        ITreeVerifier newVerifier = new SimpleVerifier();
        bytes memory callData =
            abi.encodeCall(ManagerImpl.setRegisterIdentitiesVerifier, (newVerifier));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `getIdentityRemovalVerifierAddress` while
    ///         the contract is not initialized.
    function testShouldNotCallGetIdentityRemovalVerifierAddressWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(ManagerImpl.getIdentityRemovalVerifierAddress, ());
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `setIdentityRemovalVerifier` while the
    ///        contract is not initialized.
    function testShouldNotCallSetIdentityRemovalVerifierWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        ITreeVerifier newVerifier = new SimpleVerifier();
        bytes memory callData =
            abi.encodeCall(ManagerImpl.setIdentityRemovalVerifier, (newVerifier));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `getIdentityUpdateVerifierAddress` while
    ///         the contract is not initialized.
    function testShouldNotCallGetIdentityUpdateVerifierAddressWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(ManagerImpl.getIdentityUpdateVerifierAddress, ());
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `setIdentityUpdateVerifier` while the
    ///        contract is not initialized.
    function testShouldNotCallSetIdentityUpdateVerifierWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        ITreeVerifier newVerifier = new SimpleVerifier();
        bytes memory callData = abi.encodeCall(ManagerImpl.setIdentityUpdateVerifier, (newVerifier));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `getSemaphoreVerifierAddress` while the
    ///         contract is not initialized.
    function testShouldNotCallGetSemaphoreVerifierAddressWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(ManagerImpl.getSemaphoreVerifierAddress, ());
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `setSemaphoreVerifier` while the contract is
    ///         not initialized.
    function testShouldNotCallSetSemaphoreVerifierWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        SemaphoreVerifier newVerifier = new SemaphoreVerifier();
        bytes memory callData = abi.encodeCall(ManagerImpl.setSemaphoreVerifier, (newVerifier));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }
}
