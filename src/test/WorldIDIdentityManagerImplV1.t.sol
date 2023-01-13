// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {Vm} from "forge-std/Vm.sol";
import {Test} from "forge-std/Test.sol";

import {ITreeVerifier} from "../interfaces/ITreeVerifier.sol";
import {Verifier as TreeVerifier} from "./mock/TreeVerifier.sol";
import {SimpleVerifier, SimpleVerify} from "./mock/SimpleVerifier.sol";

import {WorldIDIdentityManagerImplV1 as ManagerImpl} from "../WorldIDIdentityManagerImplV1.sol";

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

    ITreeVerifier verifier;
    uint256 initialRoot = 0x0;

    ManagerImpl identityManager;

    // Slot counter.
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
        thisAddress = address(this);

        verifier = new TreeVerifier();

        identityManager = new ManagerImpl();
        identityManager.initialize(preRoot, verifier);

        hevm.label(address(this), "Sender");
        hevm.label(address(identityManager), "IdentityManager");
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                              TEST UTILITIES                             ///
    ///////////////////////////////////////////////////////////////////////////////

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

    ///////////////////////////////////////////////////////////////////////////////
    ///                         IDENTITY MANAGEMENT TESTS                       ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Checks that the proof validates properly with the correct inputs.
    function testRegisterIdentitiesWithCorrectInputsFromKnown() public {
        // Test
        identityManager.registerIdentities(
            proof, preRoot, startIndex, identityCommitments, postRoot
        );
        assertEq(identityManager.latestRoot(), postRoot);
        assertEq(identityManager.queryRoot(postRoot).supersededTimestamp, 0);
        assert(identityManager.queryRoot(postRoot).isValid);
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
        ManagerImpl localManager = new ManagerImpl();
        localManager.initialize(newPreRoot, new SimpleVerifier());
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareVerifierTestCase(identities, prf);

        // Test
        localManager.registerIdentities(
            actualProof, newPreRoot, newStartIndex, preparedIdents, newPostRoot
        );
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
        ManagerImpl localManager = new ManagerImpl();
        localManager.initialize(newPreRoot, new SimpleVerifier());
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareVerifierTestCase(identities, prf);
        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.ProofValidationFailure.selector);
        vm.expectRevert(expectedError);

        // Test
        localManager.registerIdentities(
            actualProof, newPreRoot, newStartIndex, preparedIdents, newPostRoot
        );
    }

    /// @notice Checks that it reverts if the provided start index is incorrect.
    function testCannotRegisterIdentitiesIfStartIndexIncorrect(uint32 newStartIndex) public {
        // Setup
        vm.assume(newStartIndex != startIndex);
        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.ProofValidationFailure.selector);
        vm.expectRevert(expectedError);

        // Test
        identityManager.registerIdentities(
            proof, preRoot, newStartIndex, identityCommitments, postRoot
        );
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
        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.ProofValidationFailure.selector);
        vm.expectRevert(expectedError);

        // Test
        identityManager.registerIdentities(proof, preRoot, startIndex, identities, postRoot);
    }

    /// @notice Checks that it reverts if the provided post root is incorrect.
    function testCannotRegisterIdentitiesIfPostRootIncorrect(uint256 newPostRoot) public {
        // Setup
        vm.assume(newPostRoot != postRoot && newPostRoot < SNARK_SCALAR_FIELD);
        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.ProofValidationFailure.selector);
        vm.expectRevert(expectedError);

        // Test
        identityManager.registerIdentities(
            proof, preRoot, startIndex, identityCommitments, newPostRoot
        );
    }

    /// @notice Tests that it reverts if an attempt is made to register identities as a non-manager.
    function testCannotRegisterIdentitiesAsNonManager(address nonManager) public {
        // Setup
        vm.assume(nonManager != address(this) && nonManager != address(0x0));
        vm.expectRevert("Ownable: caller is not the owner");
        vm.prank(nonManager);

        // Test
        identityManager.registerIdentities(
            proof, preRoot, startIndex, identityCommitments, postRoot
        );
    }

    /// @notice Tests that it reverts if an attempt is made to register identities with an outdated
    ///         root.
    function testCannotRegisterIdentitiesWithOutdatedRoot(uint256 currentPreRoot) public {
        // Setup
        vm.assume(currentPreRoot != preRoot && currentPreRoot < SNARK_SCALAR_FIELD);
        ManagerImpl localManager = new ManagerImpl();
        localManager.initialize(uint256(currentPreRoot), verifier);
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImpl.NotLatestRoot.selector, preRoot, uint256(currentPreRoot)
        );
        vm.expectRevert(expectedError);

        // Test
        localManager.registerIdentities(proof, preRoot, startIndex, identityCommitments, postRoot);
    }

    /// @notice Tests that it reverts if an attempt is made to register identity commitments
    ///         containing an invalid identity.
    function testCannotRegisterIdentitiesWithInvalidIdentities(uint256 fuzz) public {
        delete fuzz; // Not actually used, I just want it to run a few times

        // Setup
        uint256 position = rotateSlot();
        uint256[] memory invalidCommitments = new uint256[](identityCommitments.length);
        invalidCommitments[position] = 0x0;
        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.InvalidCommitment.selector, uint256(0));
        vm.expectRevert(expectedError);

        // Test
        identityManager.registerIdentities(proof, preRoot, startIndex, invalidCommitments, postRoot);
    }

    /// @notice Tests that it reverts if an attempt is made to register identity commitments that
    ///         are not in reduced form.
    function testCannotRegisterIdentitiesWithUnreducedIdentities(uint128 i) public {
        // Setup
        uint256 position = rotateSlot();
        uint256[] memory unreducedCommitments = new uint256[](identityCommitments.length);
        unreducedCommitments[position] = SNARK_SCALAR_FIELD + i;
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImpl.UnreducedElement.selector,
            ManagerImpl.UnreducedElementType.IdentityCommitment,
            SNARK_SCALAR_FIELD + i
        );
        vm.expectRevert(expectedError);

        // Test
        identityManager.registerIdentities(
            proof, preRoot, startIndex, unreducedCommitments, postRoot
        );
    }

    /// @notice Tests that it reverts if an attempt is made to register new identities with a pre
    ///         root that is not in reduced form.
    function testCannotRegisterIdentitiesWithUnresducedPreRoot(uint128 i) public {
        // Setup
        uint256 newPreRoot = SNARK_SCALAR_FIELD + i;
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImpl.UnreducedElement.selector,
            ManagerImpl.UnreducedElementType.PreRoot,
            newPreRoot
        );
        vm.expectRevert(expectedError);

        // Test
        identityManager.registerIdentities(
            proof, newPreRoot, startIndex, identityCommitments, postRoot
        );
    }

    /// @notice Tests that it reverts if an attempt is made to register identities with a postRoot
    ///         that is not in reduced form.
    function testCannotRegisterIdentitiesWithUnreducedPostRoot(uint128 i) public {
        // Setup
        uint256 newPostRoot = SNARK_SCALAR_FIELD + i;
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImpl.UnreducedElement.selector,
            ManagerImpl.UnreducedElementType.PostRoot,
            newPostRoot
        );
        vm.expectRevert(expectedError);

        // Test
        identityManager.registerIdentities(
            proof, preRoot, startIndex, identityCommitments, newPostRoot
        );
    }

    /// @notice Tests that it reverts if an attempt is made to violate type safety and register with
    ///         a startIndex that is not type safe within the bounds of `type(uint32).max` and hence
    ///         within `SNARK_SCALAR_FIELD`.
    function testCannotRegisterIdentitiesWithUnreducedStartIndex(uint256 i) public {
        // Setup
        vm.assume(i > type(uint32).max);
        address managerAddress = address(identityManager);
        bytes4 functionSelector = ManagerImpl.registerIdentities.selector;
        bytes memory callData = abi.encodeWithSelector(
            functionSelector, proof, preRoot, i, identityCommitments, postRoot
        );

        // Test
        (bool success, bytes memory returnValue) = managerAddress.call(callData);
        delete returnValue; // No data here as the type safety violation reverts in the EVM.
        assert(!success);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                            DATA QUERYING TESTS                          ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Tests whether it is possible to query accurate information about the current root.
    function testQueryCurrentRoot(uint128 newPreRoot) public {
        // Setup
        ManagerImpl localManager = new ManagerImpl();
        localManager.initialize(newPreRoot, new SimpleVerifier());

        // Test
        ManagerImpl.RootInfo memory rootInfo = localManager.queryRoot(newPreRoot);
        assertEq(rootInfo.root, newPreRoot);
        assertEq(rootInfo.supersededTimestamp, 0); // Never been inserted into the history.
        assert(rootInfo.isValid);
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
        ManagerImpl localManager = new ManagerImpl();
        localManager.initialize(newPreRoot, new SimpleVerifier());
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareVerifierTestCase(identities, prf);
        localManager.registerIdentities(
            actualProof, newPreRoot, newStartIndex, preparedIdents, newPostRoot
        );

        // Test
        ManagerImpl.RootInfo memory rootInfo = localManager.queryRoot(newPreRoot);
        assertEq(rootInfo.root, newPreRoot);
        assertEq(rootInfo.supersededTimestamp, block.timestamp);
        assert(rootInfo.isValid);
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
        ManagerImpl localManager = new ManagerImpl();
        localManager.initialize(newPreRoot, new SimpleVerifier());
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareVerifierTestCase(identities, prf);
        uint256 originalTimestamp = block.timestamp;
        localManager.registerIdentities(
            actualProof, newPreRoot, newStartIndex, preparedIdents, newPostRoot
        );
        vm.warp(originalTimestamp + 2 hours); // Force preRoot to expire

        // Test
        ManagerImpl.RootInfo memory rootInfo = localManager.queryRoot(newPreRoot);
        assertEq(rootInfo.root, newPreRoot);
        assertEq(rootInfo.supersededTimestamp, originalTimestamp);
        assert(!rootInfo.isValid);

        // Cleanup
        vm.warp(originalTimestamp);
    }

    /// @notice Checks that we get `NO_SUCH_ROOT` back when we query for information about an
    ///         invalid root.
    function testQueryInvalidRoot(uint256 badRoot) public {
        // Setup
        vm.assume(badRoot != preRoot);

        // Test
        ManagerImpl.RootInfo memory rootInfo = identityManager.queryRoot(uint256(0xBADCAFE));
        ManagerImpl.RootInfo memory noSuchRoot = identityManager.NO_SUCH_ROOT();
        assertEq(rootInfo.root, noSuchRoot.root);
        assertEq(rootInfo.supersededTimestamp, noSuchRoot.supersededTimestamp);
        assertEq(rootInfo.isValid, noSuchRoot.isValid);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                             CALCULATION TESTS                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Tests whether it is possible to correctly calculate the `inputHash` to the merkle
    ///         tree verifier.
    function testCalculateInputHashFromParametersOnKnownInput() public {
        // Test
        bytes32 calculatedHash = identityManager.calculateTreeVerifierInputHash(
            startIndex, preRoot, postRoot, identityCommitments
        );
        assertEq(calculatedHash, inputHash);
    }

    /// @notice Tests whether it is possible to check whether values are in reduced form.
    function testCanCheckValueIsInReducedForm(uint256 value) public {
        // Setup
        vm.assume(value < SNARK_SCALAR_FIELD);

        // Test
        assert(identityManager.isInputInReducedForm(value));
    }

    /// @notice Tests whether it is possible to detect un-reduced values.
    function testCanCheckValueIsNotInReducedForm(uint256 value) public {
        // Setup
        vm.assume(value >= SNARK_SCALAR_FIELD);

        // Test
        assert(!identityManager.isInputInReducedForm(value));
    }
}
