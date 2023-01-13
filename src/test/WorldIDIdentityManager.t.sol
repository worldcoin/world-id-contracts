// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {Vm} from "forge-std/Vm.sol";
import {Test} from "forge-std/Test.sol";

import "forge-std/console.sol";

import {ITreeVerifier} from "../interfaces/ITreeVerifier.sol";
import {OwnableUpgradeable} from "contracts-upgradeable/access/OwnableUpgradeable.sol";
import {SimpleVerifier, SimpleVerify} from "./mock/SimpleVerifier.sol";
import {Verifier as TreeVerifier} from "./mock/TreeVerifier.sol";
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
        assertCallFailsOn(identityManagerAddress, callData, expectedReturn);
    }

    // TODO [Ara] testCanOnlyInitializeIfViaProxy

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
        bytes memory initCall = abi.encodeCall(WorldIDIdentityManagerImplMock.initializeV2, (320));
        bytes memory upgradeCall =
            abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (address(mockUpgrade), initCall));

        // Test
        assertCallSucceedsOn(identityManagerAddress, upgradeCall, new bytes(0x0));
    }

    /// @notice Tests that an upgrade cannot be performed by anybody other than the manager.
    function testCannotUpgradeUnlessManager(address naughty) public {
        // Setup
        vm.assume(naughty != address(this) || naughty != address(0x0));
        WorldIDIdentityManagerImplMock mockUpgrade = new WorldIDIdentityManagerImplMock();
        bytes memory initCall = abi.encodeCall(WorldIDIdentityManagerImplMock.initializeV2, (320));
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
        bytes memory initCall = abi.encodeCall(ManagerImpl.initialize, (initialRoot, verifier));
        vm.expectRevert("Function must be called through delegatecall");

        // Test
        managerImpl.upgradeToAndCall(mockUpgradeAddress, initCall);
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
        vm.assume(naughty != thisAddress);
        vm.assume(newOwner != nullAddress);
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
        managerImpl = new ManagerImpl();
        managerImplAddress = address(managerImpl);
        ITreeVerifier actualVerifier = new TreeVerifier();

        bytes memory callData = abi.encodeCall(ManagerImpl.initialize, (preRoot, actualVerifier));

        identityManager = new IdentityManager(managerImplAddress, callData);
        identityManagerAddress = address(identityManager);
        bytes memory registerCallData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (proof, preRoot, startIndex, identityCommitments, postRoot)
        );
        bytes memory latestRootCallData = abi.encodeCall(ManagerImpl.latestRoot, ());
        bytes memory queryRootCallData = abi.encodeCall(ManagerImpl.queryRoot, (postRoot));

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
        ManagerImpl localManagerImpl = new ManagerImpl();
        bytes memory initCall = abi.encodeCall(ManagerImpl.initialize, (newPreRoot, verifier));
        IdentityManager localManager = new IdentityManager(address(localManagerImpl), initCall);
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareVerifierTestCase(identities, prf);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (actualProof, newPreRoot, newStartIndex, preparedIdents, newPostRoot)
        );

        // Test
        assertCallSucceedsOn(address(localManager), callData);
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
        ManagerImpl localManagerImpl = new ManagerImpl();
        bytes memory initCall = abi.encodeCall(ManagerImpl.initialize, (newPreRoot, verifier));
        IdentityManager localManager = new IdentityManager(address(localManagerImpl), initCall);
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareVerifierTestCase(identities, prf);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.registerIdentities,
            (actualProof, newPreRoot, newStartIndex, preparedIdents, newPostRoot)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.ProofValidationFailure.selector);

        // Test
        assertCallFailsOn(address(localManager), callData, expectedError);
    }

    /// @notice Checks that it reverts if the provided start index is incorrect.
    function testCannotRegisterIdentitiesIfStartIndexIncorrect(uint32 newStartIndex) public {
        // Setup
        vm.assume(newStartIndex != startIndex);
        managerImpl = new ManagerImpl();
        managerImplAddress = address(managerImpl);
        ITreeVerifier actualVerifier = new TreeVerifier();

        bytes memory callData = abi.encodeCall(ManagerImpl.initialize, (preRoot, actualVerifier));

        identityManager = new IdentityManager(managerImplAddress, callData);
        identityManagerAddress = address(identityManager);
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
        managerImpl = new ManagerImpl();
        managerImplAddress = address(managerImpl);
        ITreeVerifier actualVerifier = new TreeVerifier();

        bytes memory callData = abi.encodeCall(ManagerImpl.initialize, (preRoot, actualVerifier));

        identityManager = new IdentityManager(managerImplAddress, callData);
        identityManagerAddress = address(identityManager);
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

        bytes memory callData = abi.encodeCall(ManagerImpl.initialize, (preRoot, actualVerifier));

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

    // TODO [Ara] testCannotRegisterIdentitiesIfNotViaProxy

    ///////////////////////////////////////////////////////////////////////////////
    ///                             CALLABILITY TESTS                           ///
    ///////////////////////////////////////////////////////////////////////////////

    // TODO [Ara] Delete these. They're now superseded.

    /// @notice Checks that it is possible to call `owner()`.
    function testCanCallOwner() public {
        // Setup
        bytes memory callData = abi.encodeCall(OwnableUpgradeable.owner, ());

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
    }

    /// @notice Checks that it is possible to call `transferOwnership()`.
    function testCanCallTransferOwnership() public {
        // Setup
        address newOwner = address(0x0ddba11);
        bytes memory callData = abi.encodeCall(OwnableUpgradeable.transferOwnership, (newOwner));

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
    }

    /// @notice Checks that it is possible to call `renounceOwnership`.
    function testCanCallRenounceOwnership() public {
        // Setup
        bytes memory callData = abi.encodeCall(OwnableUpgradeable.renounceOwnership, ());

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
    }

    /// @notice Checks that it is possible to call `NO_SUCH_ROOT`.
    function testCanCallNoSuchRoot() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImpl.NO_SUCH_ROOT, ());

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
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
        assertCallSucceedsOn(identityManagerAddress, callData);
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
        assertCallSucceedsOn(identityManagerAddress, callData);
    }

    /// @notice Checks that it is possible to call `queryRoot`.
    function testCanCallQueryRoot() public {
        // Setup
        uint256 root = 0xc0ffee;
        bytes memory callData = abi.encodeCall(ManagerImpl.queryRoot, (root));

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
    }

    /// @notice Checks that it is possible to call `isInputInReducedForm`.
    function testIsInputInReducedForm() public {
        // Setup
        uint256 inputNumber = 0xc0ffee;
        bytes memory callData = abi.encodeCall(ManagerImpl.isInputInReducedForm, (inputNumber));

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
    }

    /// @notice Checks that it is possible to call `checkValidRoot`.
    function testCanCallCheckValidRoot() public {
        // Setup
        bytes memory callData = abi.encodeCall(ManagerImpl.checkValidRoot, (initialRoot));

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
    }
}
