// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {Vm} from "forge-std/Vm.sol";
import {Test} from "forge-std/Test.sol";

import {Semaphore, ITreeVerifier} from "../Semaphore.sol";
import {Verifier as TreeVerifier} from "./mock/TreeVerifier.sol";

import "forge-std/console.sol";

contract SemaphoreTest is Test {
    ///////////////////////////////////////////////////////////////////////////////
    ///                                TEST DATA                                ///
    ///////////////////////////////////////////////////////////////////////////////

    Semaphore internal semaphore;
    Vm internal hevm = Vm(HEVM_ADDRESS);

    // All hardcoded test data taken from `src/test/data/TestParams.json`. This will be dynamically
    // generated at some point in the future.
    bytes32 inputHash = 0x7d7f77c56064e1f8577de14bba99eff85599ab0e76d0caeadd1ad61674b8a9c3;
    uint32 startIndex = uint32(0);
    uint256 preRoot = 0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238;
    uint256 postRoot = 0x5c1e52b41a571293b30efacd2afdb7173b20cfaf1f646c4ac9f96eb75848270;
    uint256[] identityCommitments;
    uint256[8] proof;

    // Needed for testing things.
    uint256 constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    ///////////////////////////////////////////////////////////////////////////////
    ///                                   SETUP                                 ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice The tests require some static data setup that can't be easily written inline. We use
    /// the constructor for this.
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

    /// @notice This runs before every test.
    function setUp() public {
        TreeVerifier verifier = new TreeVerifier();
        semaphore = new Semaphore(preRoot, ITreeVerifier(address(verifier)));

        hevm.label(address(this), "Sender");
        hevm.label(address(semaphore), "Semaphore");
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                                 THE TESTS                               ///
    ///////////////////////////////////////////////////////////////////////////////

    // ===== Identity Registration ================================================

    /// @notice Checks that the proof validates properly with the correct inputs.
    function testRegisterValidIdentities() public {
        // Test
        semaphore.registerIdentities(proof, preRoot, startIndex, identityCommitments, postRoot);
        assertEq(semaphore.latestRoot(), postRoot);
        assertEq(semaphore.queryRoot(postRoot).supersededTimestamp, 0);
        assert(semaphore.queryRoot(postRoot).isValid);
    }

    /// @notice Checks that it reverts if the provided proof is incorrect for the public inputs.
    function testCannotRegisterIfProofIncorrect() public {
        // Setup
        uint256[8] memory badProof = [
            0x2a45bf326884bbf13c821a5e4f30690a391156cccf80a2922fb24250111dd7eb,
            0x23a7376a159513e6d0e22d43fcdca9d0c8a5c54a73b59fce6962a41e71355894,
            0x21b9fc7c2d1f76c2e1a972b00f18728a57a34d7e4ae040811bf1626132ff3658,
            0x2a7c3c660190a33ab92cd84e4b2540e49ea80bdc766eb3aeec49806a78071c75,
            0x2fc9a52a7f4bcc29faab28a8d8ec126b4fe604a7b41e7d2b3efe92422951d706,
            0x110740f0b21fb329de682dffc95a5ede11c11c6328606fe254b6ba469b15f68,
            0x23115ff1573808639f19724479b195b7894a45c9868242ad2a416767359c6c78,
            0x23f3fa30273c7f38e360496e7f9790450096d4a9592e1fe6e0a996cb04b8fb28
        ];
        bytes memory expectedError =
            abi.encodeWithSelector(Semaphore.ProofValidationFailure.selector);
        vm.expectRevert(expectedError);

        // Test
        semaphore.registerIdentities(badProof, preRoot, startIndex, identityCommitments, postRoot);
    }

    /// @notice Checks that it reverts if the provided start index is incorrect.
    function testCannotRegisterIfStartIndexIncorrect() public {
        bytes memory expectedError =
            abi.encodeWithSelector(Semaphore.ProofValidationFailure.selector);
        vm.expectRevert(expectedError);

        // Test
        semaphore.registerIdentities(proof, preRoot, startIndex + 1, identityCommitments, postRoot);
    }

    /// @notice Checks that it reverts if the provided set of identities is incorrect.
    function testCannotRegisterIfIdentitiesIncorrect() public {
        // Setup
        identityCommitments[2] = 0x7F;
        bytes memory expectedError =
            abi.encodeWithSelector(Semaphore.ProofValidationFailure.selector);
        vm.expectRevert(expectedError);

        // Test
        semaphore.registerIdentities(proof, preRoot, startIndex, identityCommitments, postRoot);
    }

    /// @notice Checks that it reverts if the provided post root is incorrect.
    function testCannotRegisterIfPostRootIncorrect() public {
        bytes memory expectedError =
            abi.encodeWithSelector(Semaphore.ProofValidationFailure.selector);
        vm.expectRevert(expectedError);

        // Test
        semaphore.registerIdentities(proof, preRoot, startIndex, identityCommitments, postRoot + 1);
    }

    /// @notice Tests that it reverts if an attempt is made to register identities as a non-manager.
    function testCannotRegisterIdentitiesAsNonManager() public {
        // Setup
        address prankAddress = address(0xBADD00D);
        bytes memory expectedError =
            abi.encodeWithSelector(Semaphore.Unauthorized.selector, prankAddress);
        vm.expectRevert(expectedError);
        vm.prank(prankAddress);

        // Test
        semaphore.registerIdentities(proof, preRoot, startIndex, identityCommitments, postRoot);
    }

    /// @notice Tests that it reverts if an attempt is made to register identities with an outdated
    ///         root.
    function testCannotRegisterIdentitiesWithOutdatedRoot() public {
        // Setup
        TreeVerifier verifier = new TreeVerifier();
        Semaphore localSemaphore = new Semaphore(uint256(0), ITreeVerifier((verifier)));
        bytes memory expectedError =
            abi.encodeWithSelector(Semaphore.NotLatestRoot.selector, preRoot, uint256(0));
        vm.expectRevert(expectedError);

        // Test
        localSemaphore.registerIdentities(proof, preRoot, startIndex, identityCommitments, postRoot);
    }

    /// @notice Tests that it reverts if an attempt is made to register identity commitments
    ///         containing an invalid identity.
    function testCannotRegisterInvalidIdentities() public {
        // Setup
        uint256[] memory invalidCommitments = new uint256[](identityCommitments.length);
        invalidCommitments[0] = 0x0;
        invalidCommitments[1] = 0x1;
        invalidCommitments[2] = 0x2;
        bytes memory expectedError =
            abi.encodeWithSelector(Semaphore.InvalidCommitment.selector, uint256(0));
        vm.expectRevert(expectedError);

        // Test
        semaphore.registerIdentities(proof, preRoot, startIndex, invalidCommitments, postRoot);
    }

    /// @notice Tests that it reverts if an attempt is made to register identity commitments that
    ///         are not in reduced form.
    function testCannotRegisterUnreducedIdentities(uint128 i, uint128 j, uint128 k) public {
        // Setup
        uint256[] memory unreducedCommitments = new uint256[](identityCommitments.length);
        unreducedCommitments[0] = SNARK_SCALAR_FIELD + i;
        unreducedCommitments[1] = SNARK_SCALAR_FIELD + j;
        unreducedCommitments[2] = SNARK_SCALAR_FIELD + k;
        bytes memory expectedError = abi.encodeWithSelector(
            Semaphore.UnreducedElement.selector,
            Semaphore.UnreducedElementType.IdentityCommitment,
            SNARK_SCALAR_FIELD + i
        );
        vm.expectRevert(expectedError);

        // Test
        semaphore.registerIdentities(proof, preRoot, startIndex, unreducedCommitments, postRoot);
    }

    /// @notice Tests that it reverts if an attempt is made to register new identities with a pre
    ///         root that is not in reduced form.
    function testCannotRegisterUnreducedPreRoot(uint128 i) public {
        // Setup
        uint256 newPreRoot = SNARK_SCALAR_FIELD + i;
        bytes memory expectedError = abi.encodeWithSelector(
            Semaphore.UnreducedElement.selector, Semaphore.UnreducedElementType.PreRoot, newPreRoot
        );
        vm.expectRevert(expectedError);

        // Test
        semaphore.registerIdentities(proof, newPreRoot, startIndex, identityCommitments, postRoot);
    }

    /// @notice Tests that it reverts if an attempt is made to register identities with a postRoot
    ///         that is not in reduced form.
    function testCannotRegisterUnreducedPostRoot(uint128 i) public {
        // Setup
        uint256 newPostRoot = SNARK_SCALAR_FIELD + i;
        bytes memory expectedError = abi.encodeWithSelector(
            Semaphore.UnreducedElement.selector,
            Semaphore.UnreducedElementType.PostRoot,
            newPostRoot
        );
        vm.expectRevert(expectedError);

        // Test
        semaphore.registerIdentities(proof, preRoot, startIndex, identityCommitments, newPostRoot);
    }

    /// @notice Tests that it reverts if an attempt is made to violate type safety and register with
    ///         a startIndex that is not type safe within the bounds of `type(uint32).max` and hence
    ///         within `SNARK_SCALAR_FIELD`.
    function testCannotRegisterUnreducedStartIndex(uint256 i) public {
        // Setup
        vm.assume(i > type(uint32).max);
        address semaphoreAddress = address(semaphore);
        bytes4 functionSelector = Semaphore.registerIdentities.selector;
        bytes memory callData = abi.encodeWithSelector(
            functionSelector, proof, preRoot, i, identityCommitments, postRoot
        );

        // Test
        (bool success, bytes memory returnValue) = semaphoreAddress.call(callData);
        delete returnValue; // No data here as the type safety violation reverts in the EVM.
        assert(!success);
    }

    // ===== Input Hash Calculation ===============================================

    /// @notice Tests whether it is possible to correctly calculate the `inputHash` to the merkle
    ///         tree verifier.
    function testCalculateInputHashFromParameters() public {
        // Test
        bytes32 calculatedHash = semaphore.calculateTreeVerifierInputHash(
            startIndex, preRoot, postRoot, identityCommitments
        );
        assertEq(calculatedHash, inputHash);
    }

    // ===== Root Querying ========================================================

    /// @notice Tests whether it is possible to query accurate information about the current root.
    function testQueryCurrentRoot() public {
        // Test
        Semaphore.RootInfo memory rootInfo = semaphore.queryRoot(preRoot);
        assertEq(rootInfo.root, preRoot);
        assertEq(rootInfo.supersededTimestamp, 0); // Never been inserted into the history.
        assert(rootInfo.isValid);
    }

    /// @notice Tests whether it is possible to query accurate information about an arbitrary root.
    function testQueryOlderRoot() public {
        // Setup
        semaphore.registerIdentities(proof, preRoot, startIndex, identityCommitments, postRoot);

        // Test
        Semaphore.RootInfo memory rootInfo = semaphore.queryRoot(preRoot);
        assertEq(rootInfo.root, preRoot);
        assertEq(rootInfo.supersededTimestamp, block.timestamp);
        assert(rootInfo.isValid);
    }

    /// @notice Tests whether it is possible to query accurate information about an expired root.
    function testQueryExpiredRoot() public {
        // Setup
        uint256 originalTimestamp = block.timestamp;
        semaphore.registerIdentities(proof, preRoot, startIndex, identityCommitments, postRoot);
        vm.warp(originalTimestamp + 2 hours); // Force preRoot to expire

        // Test
        Semaphore.RootInfo memory rootInfo = semaphore.queryRoot(preRoot);
        assertEq(rootInfo.root, preRoot);
        assertEq(rootInfo.supersededTimestamp, originalTimestamp);
        assert(!rootInfo.isValid);

        // Cleanup
        vm.warp(originalTimestamp);
    }

    /// @notice Checks that we get `NO_SUCH_ROOT` back when we query for information about an
    ///         invalid root.
    function testQueryInvalidRoot() public {
        // Test
        Semaphore.RootInfo memory rootInfo = semaphore.queryRoot(uint256(0xBADCAFE));
        Semaphore.RootInfo memory noSuchRoot = semaphore.NO_SUCH_ROOT();
        assertEq(rootInfo.root, noSuchRoot.root);
        assertEq(rootInfo.supersededTimestamp, noSuchRoot.supersededTimestamp);
        assertEq(rootInfo.isValid, noSuchRoot.isValid);
    }

    // ===== Access Control =======================================================

    /// @notice Tests whether it is possible to transfer the contract's management to another
    ///         address.
    function testTransferAccess() public {
        // Setup
        address targetAddress = address(0x900DD00D);

        // Test
        semaphore.transferAccess(targetAddress);
        assertEq(semaphore.manager(), targetAddress);
    }

    /// @notice Tests whether the call reverts if an attempt is made to transfer access as a
    ///         non-manager.
    function testCannotTransferAccessAsNonManager() public {
        // Setup
        address targetAddress = address(0x900DD00D);
        address prankAddress = address(0xBADD00D);
        bytes memory expectedError =
            abi.encodeWithSelector(Semaphore.Unauthorized.selector, prankAddress);
        vm.expectRevert(expectedError);
        vm.prank(prankAddress);

        // Test
        semaphore.transferAccess(targetAddress);
    }

    // ===== Reduced Form Checking ================================================

    /// @notice Tests whether it is possible to check whether values are in reduced form.
    function testCanCheckValueIsInReducedForm(uint256 value) public {
        // Setup
        vm.assume(value < SNARK_SCALAR_FIELD);

        // Test
        assert(semaphore.isInputInReducedForm(value));
    }

    /// @notice Tests whether it is possible to detect un-reduced values.
    function testCanCheckValueIsNotInReducedForm(uint256 value) public {
        // Setup
        vm.assume(value >= SNARK_SCALAR_FIELD);

        // Test
        assert(!semaphore.isInputInReducedForm(value));
    }
}
