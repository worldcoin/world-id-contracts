// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {Vm} from "forge-std/Vm.sol";
import {Test} from "forge-std/Test.sol";

import "forge-std/console.sol";

import {ITreeVerifier} from "../interfaces/ITreeVerifier.sol";
import {SimpleStateBridge} from "./mock/SimpleStateBridge.sol";
import {SimpleVerifier, SimpleVerify} from "./mock/SimpleVerifier.sol";

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

    IdentityManager internal identityManager;
    ManagerImpl internal managerImpl;

    ITreeVerifier internal verifier;
    uint256 internal initialRoot = 0x0;

    address internal identityManagerAddress;
    address internal managerImplAddress;

    uint256 internal slotCounter = 0;

    address internal nullAddress = address(0x0);
    address internal thisAddress = address(this);

    // All hardcoded test data taken from `src/test/data/TestParams.json`. This will be dynamically
    // generated at some point in the future.
    bytes32 internal constant inputHash =
        0x7d7f77c56064e1f8577de14bba99eff85599ab0e76d0caeadd1ad61674b8a9c3;
    uint32 internal constant startIndex = 0;
    uint256 internal constant preRoot =
        0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238;
    uint256 internal constant postRoot =
        0x5c1e52b41a571293b30efacd2afdb7173b20cfaf1f646c4ac9f96eb75848270;
    uint256[] identityCommitments;
    uint256[8] proof;

    // Needed for testing things.
    uint256 internal constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // StateBridgeProxy mock
    SimpleStateBridge internal stateBridge;
    address internal stateBridgeProxy;
    bool internal isStateBridgeEnabled = true;

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

        bytes memory updateVerifierCallData =
            abi.encodeCall(ManagerImpl.setIdentityUpdateVerifier, (new SimpleVerifier()));
        (bool status,) = identityManagerAddress.call(updateVerifierCallData);
        assert(status);
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
    /// @return actualProof The conversion of `prf` to the proper type.
    function prepareInsertIdentitiesTestCase(uint128[] memory idents, uint128[8] memory prf)
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

    /// @notice Prepares a verifier test case.
    /// @dev This is useful to make property-based fuzz testing work better by requiring less
    ///      constraints on the generated input.
    ///
    /// @param idents The generated identity commitments to convert.
    /// @param prf The generate proof terms to convert.
    ///
    /// @return preparedIdents The conversion of `idents` to the proper type.
    /// @return actualProof The conversion of `prf` to the proper type.
    function prepareUpdateIdentitiesTestCase(uint128[] memory idents, uint128[8] memory prf)
        public
        returns (ManagerImpl.IdentityUpdate[] memory preparedIdents, uint256[8] memory actualProof)
    {
        for (uint256 i = 0; i < idents.length; ++i) {
            vm.assume(idents[i] != 0x0);
        }
        preparedIdents = new ManagerImpl.IdentityUpdate[](idents.length);
        for (uint256 i = 0; i < idents.length; ++i) {
            preparedIdents[i].leafIndex = uint32(idents[i] % 1024);
            preparedIdents[i].oldCommitment = idents[i];

            if (idents[i] != type(uint256).min) {
                preparedIdents[i].newCommitment = idents[i] - 1;
            } else {
                preparedIdents[i].newCommitment = idents[i] + 1;
            }
        }

        actualProof = [uint256(prf[0]), prf[1], prf[2], prf[3], prf[4], prf[5], prf[6], prf[7]];
    }

    /// @notice Prepares a verifier test case.
    /// @dev This is useful to make property-based fuzz testing work better by requiring less
    ///      constraints on the generated input.
    ///
    /// @param idents The generated identity commitments to convert.
    /// @param prf The generate proof terms to convert.
    ///
    /// @return preparedIdents The conversion of `idents` to the proper type.
    /// @return actualProof The conversion of `prf` to the proper type.
    function prepareRemoveIdentitiesTestCase(uint128[] memory idents, uint128[8] memory prf)
        public
        returns (ManagerImpl.IdentityUpdate[] memory preparedIdents, uint256[8] memory actualProof)
    {
        for (uint256 i = 0; i < idents.length; ++i) {
            vm.assume(idents[i] != 0x0);
        }
        preparedIdents = new ManagerImpl.IdentityUpdate[](idents.length);
        for (uint256 i = 0; i < idents.length; ++i) {
            preparedIdents[i].leafIndex = uint32(idents[i % 1024]);
            preparedIdents[i].oldCommitment = idents[i];
            preparedIdents[i].newCommitment = 0;
        }

        actualProof = [uint256(prf[0]), prf[1], prf[2], prf[3], prf[4], prf[5], prf[6], prf[7]];
    }
}
