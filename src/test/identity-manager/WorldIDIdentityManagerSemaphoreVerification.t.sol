// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {ISemaphoreVerifier} from "src/interfaces/ISemaphoreVerifier.sol";
import {SemaphoreTreeDepthValidator} from "../../utils/SemaphoreTreeDepthValidator.sol";
import {SimpleSemaphoreVerifier} from "../mock/SimpleSemaphoreVerifier.sol";
import {SemaphoreVerifier} from "src/test/SemaphoreVerifier16.sol";
import {WorldIDIdentityManager as IdentityManager} from "../../WorldIDIdentityManager.sol";
import {WorldIDIdentityManagerImplV2 as ManagerImpl} from "../../WorldIDIdentityManagerImplV2.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImplV1} from "../../WorldIDIdentityManagerImplV1.sol";
import {WorldIDIdentityManagerImplV3 as ManagerImplV3} from "../../WorldIDIdentityManagerImplV3.sol";

/// @title World ID Identity Manager Semaphore Proof Verification Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerSemaphoreVerification is WorldIDIdentityManagerTest {
    /// @notice Checks that the proof validates properly with the correct inputs.
    function testProofVerificationWithCompressedProof(
        uint8 actualTreeDepth,
        uint256 nullifierHash,
        uint256 signalHash,
        uint256 externalNullifierHash,
        uint256[4] memory prf // Compressed proof is 4 uints
    ) public {
        // Setup
        ISemaphoreVerifier actualSemaphoreVerifier = new SimpleSemaphoreVerifier();
        vm.assume(SemaphoreTreeDepthValidator.validate(actualTreeDepth));
        vm.assume(prf[0] != 0);
        // SimpleVerifier expects that proof[0] % 2 == 0 for compressed proof
        // The opposite is true for non-compressed proofs
        // This checks that the correct logical path in IdentityManager is taken
        vm.assume(prf[0] % 2 == 0);
        uint256[8] memory prfExpanded = [prf[0], prf[1], prf[2], prf[3], 0, 0, 0, 0];

        // Use IdentityManager V3
        makeNewIdentityManagerV3(
            actualTreeDepth,
            insertionPreRoot,
            defaultInsertVerifiers,
            defaultDeletionVerifiers,
            defaultUpdateVerifiers,
            actualSemaphoreVerifier
        );
        bytes memory verifyProofCallData = abi.encodeCall(
            ManagerImplV1.verifyProof,
            (insertionPreRoot, nullifierHash, signalHash, externalNullifierHash, prfExpanded)
        );

        // Test
        assertCallSucceedsOn(identityManagerAddress, verifyProofCallData);

        bytes memory verifyCompressedProofCallData = abi.encodeCall(
            ManagerImplV3.verifyCompressedProof,
            (insertionPreRoot, nullifierHash, signalHash, externalNullifierHash, prf)
        );

        // Test
        assertCallSucceedsOn(identityManagerAddress, verifyCompressedProofCallData);
    }

    /// @notice Checks that the proof validates properly with the correct inputs.
    function testProofVerificationWithCorrectInputs(
        uint8 actualTreeDepth,
        uint256 nullifierHash,
        uint256 signalHash,
        uint256 externalNullifierHash,
        uint256[8] memory prf
    ) public {
        // Setup
        ISemaphoreVerifier actualSemaphoreVerifier = new SimpleSemaphoreVerifier();
        vm.assume(SemaphoreTreeDepthValidator.validate(actualTreeDepth));
        vm.assume(prf[0] != 0);
        // SimpleVerifier expects that proof[0] % 2 != 0 for non-compressed proof
        // This checks that the correct logical path in IdentityManager is taken
        vm.assume(prf[0] % 2 != 0);
        makeNewIdentityManager(
            actualTreeDepth,
            insertionPreRoot,
            defaultInsertVerifiers,
            defaultDeletionVerifiers,
            defaultUpdateVerifiers,
            actualSemaphoreVerifier
        );
        bytes memory verifyProofCallData = abi.encodeCall(
            ManagerImplV1.verifyProof,
            (insertionPreRoot, nullifierHash, signalHash, externalNullifierHash, prf)
        );

        // Test
        assertCallSucceedsOn(identityManagerAddress, verifyProofCallData);
    }

    /// @notice Checks that the proof validates properly with the correct inputs.
    function testProofVerificationWithInorrectProof(
        uint8 actualTreeDepth,
        uint256 nullifierHash,
        uint256 signalHash,
        uint256 externalNullifierHash,
        uint256[8] memory prf
    ) public {
        // Setup
        ISemaphoreVerifier actualSemaphoreVerifier = new SimpleSemaphoreVerifier();
        vm.assume(SemaphoreTreeDepthValidator.validate(actualTreeDepth));
        vm.assume(prf[0] % 2 == 0);
        makeNewIdentityManager(
            actualTreeDepth,
            inclusionRoot,
            defaultInsertVerifiers,
            defaultDeletionVerifiers,
            defaultUpdateVerifiers,
            actualSemaphoreVerifier
        );
        bytes memory verifyProofCallData = abi.encodeCall(
            ManagerImplV1.verifyProof,
            (inclusionRoot, nullifierHash, signalHash, externalNullifierHash, prf)
        );

        vm.expectRevert("Semaphore__InvalidProof()");
        // Test
        assertCallFailsOn(identityManagerAddress, verifyProofCallData);
    }

    /// @notice Checks that the proof validates properly with the correct inputs.
    function testOptimizedProofVerificationWithCorrectInputs(uint256[8] memory prf) public {
        // Setup
        ISemaphoreVerifier actualSemaphoreVerifier = new SemaphoreVerifier();
        vm.assume(prf[0] != 0);
        makeNewIdentityManager(
            treeDepth,
            inclusionRoot,
            defaultInsertVerifiers,
            defaultDeletionVerifiers,
            defaultUpdateVerifiers,
            actualSemaphoreVerifier
        );
        bytes memory verifyProofCallData = abi.encodeCall(
            ManagerImplV1.verifyProof,
            (
                inclusionRoot,
                inclusionSignalHash,
                inclusionNullifierHash,
                inclusionExternalNullifierHash,
                inclusionProof
            )
        );

        // Test
        assertCallSucceedsOn(identityManagerAddress, verifyProofCallData);
    }
}
