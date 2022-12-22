// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {Vm} from "forge-std/Vm.sol";
import {Test} from "forge-std/Test.sol";

import {Semaphore} from "../Semaphore.sol";

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
        semaphore = new Semaphore(preRoot);

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
        assertEq(semaphore.queryRoot(postRoot).timestamp, block.timestamp);
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

    /// @notice Checks that it reverts if you pass it an incorrect set of identities.
    function testCannotRegisterIfIdentitiesIncorrect() public {
        // Setup
        identityCommitments[2] = 0x7F;
        bytes memory expectedError =
            abi.encodeWithSelector(Semaphore.ProofValidationFailure.selector);
        vm.expectRevert(expectedError);

        // Test
        semaphore.registerIdentities(proof, preRoot, startIndex, identityCommitments, postRoot);
    }

    /// @notice Checks that it reverts if you pass it the wrong post root.
    function testCannotRegisterIfPostRootIncorrect() public {
        bytes memory expectedError =
            abi.encodeWithSelector(Semaphore.ProofValidationFailure.selector);
        vm.expectRevert(expectedError);

        // Test
        semaphore.registerIdentities(proof, preRoot, startIndex, identityCommitments, postRoot + 1);
    }

    /// @notice Tests that it reverts if you try and register identities as a non manager.
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

    /// @notice Tests that it reverts if you try and register identities based on an outdated root.
    function testCannotRegisterIdentitiesWithOutdatedRoot() public {
        // Setup
        Semaphore localSemaphore = new Semaphore(uint256(0));
        bytes memory expectedError =
            abi.encodeWithSelector(Semaphore.NotLatestRoot.selector, preRoot, uint256(0));
        vm.expectRevert(expectedError);

        // Test
        localSemaphore.registerIdentities(proof, preRoot, startIndex, identityCommitments, postRoot);
    }

    /// @notice Tests that it reverts if you try and register commitments containing an invalid identity.
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

    // ===== Input Hash Calculation ===============================================

    /// @notice Tests whether we can correctly calculate the `inputHash` to the merkle tree verifier.
    function testCalculateInputHashFromParameters() public {
        // Test
        bytes32 calculatedHash = semaphore.calculateTreeVerifierInputHash(
            startIndex, preRoot, postRoot, identityCommitments
        );
        assertEq(calculatedHash, inputHash);
    }

    // ===== Root Querying ========================================================

    /// @notice Tests whether it is possible to query accurate information about an existing root.
    function testQueryRoot() public {
        // Test
        Semaphore.RootInfo memory rootInfo = semaphore.queryRoot(preRoot);
        assertEq(rootInfo.root, preRoot);
        assertEq(rootInfo.timestamp, 0);
        assert(rootInfo.isValid);
    }

    /// @notice Checks that we get `NO_SUCH_ROOT` back when we query an invalid root.
    function testQueryInvalidRoot() public {
        // Test
        Semaphore.RootInfo memory rootInfo = semaphore.queryRoot(uint256(0xBADCAFE));
        Semaphore.RootInfo memory noSuchRoot = semaphore.NO_SUCH_ROOT();
        assertEq(rootInfo.root, noSuchRoot.root);
        assertEq(rootInfo.timestamp, noSuchRoot.timestamp);
        assertEq(rootInfo.isValid, noSuchRoot.isValid);
    }

    // ===== Access Control =======================================================

    /// @notice Tests whether it is possible to transfer the contract's management.
    function testTransferAccess() public {
        // Setup
        address targetAddress = address(0x900DD00D);

        // Test
        semaphore.transferAccess(targetAddress);
        assertEq(semaphore.manager(), targetAddress);
    }

    /// @notice Tests whether it reverts if you try and transfer access as a non-manager.
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
}
