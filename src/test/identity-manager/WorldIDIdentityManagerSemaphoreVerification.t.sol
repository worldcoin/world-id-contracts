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
contract WorldIDIdentityManagerSemaphoreVerification is
    WorldIDIdentityManagerTest
{
    error ProofInvalid();

    /// @notice Checks that the proof validates properly with the correct inputs.
    function testProofVerificationWithCompressedProof() public {
        // Setup
        SemaphoreVerifier actualSemaphoreVerifier = new SemaphoreVerifier();

        uint256[4] memory compressedProof = actualSemaphoreVerifier
            .compressProof(inclusionProof);

        // Use IdentityManager V3
        makeNewIdentityManagerV3(
            treeDepth,
            inclusionRoot,
            defaultInsertVerifiers,
            defaultDeletionVerifiers,
            defaultUpdateVerifiers,
            actualSemaphoreVerifier
        );
        // expanded proof
        bytes memory verifyProofCallData = abi.encodeCall(
            ManagerImplV3.verifyCompressedProof,
            (
                inclusionRoot,
                inclusionSignalHash,
                inclusionNullifierHash,
                inclusionExternalNullifierHash,
                compressedProof
            )
        );

        // Test
        assertCallSucceedsOn(identityManagerAddress, verifyProofCallData);

        // 0 padded proof
        uint256[8] memory zeroPaddedProof = [
            compressedProof[0],
            compressedProof[1],
            compressedProof[2],
            compressedProof[3],
            0,
            0,
            0,
            0
        ];

        bytes memory verifyProofCallData2 = abi.encodeCall(
            ManagerImplV3.verifyProof,
            (
                inclusionRoot,
                inclusionSignalHash,
                inclusionNullifierHash,
                inclusionExternalNullifierHash,
                zeroPaddedProof
            )
        );

        // Test
        assertCallSucceedsOn(identityManagerAddress, verifyProofCallData2);
    }

    /// @notice Checks that the proof validates properly with the correct inputs.
    function testProofVerificationWithCorrectInputs(
        uint256 nullifierHash,
        uint256 signalHash,
        uint256 externalNullifierHash
    ) public {
        // Setup
        ISemaphoreVerifier actualSemaphoreVerifier = new SemaphoreVerifier();
        makeNewIdentityManager(
            treeDepth,
            inclusionRoot,
            defaultInsertVerifiers,
            defaultDeletionVerifiers,
            defaultUpdateVerifiers,
            actualSemaphoreVerifier
        );
        bytes memory verifyProofCallData = abi.encodeCall(
            ManagerImplV3.verifyProof,
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

    /// @notice Checks that the proof validates properly with the correct inputs.
    function testProofVerificationWithIncorrectProof(
        uint8 actualTreeDepth,
        uint256[8] memory prf
    ) public {
        ISemaphoreVerifier actualSemaphoreVerifier = new SemaphoreVerifier();
        // Setup
        vm.assume(SemaphoreTreeDepthValidator.validate(actualTreeDepth));
        vm.assume(prf[0] != inclusionProof[0]);
        makeNewIdentityManagerV3(
            actualTreeDepth,
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
                prf
            )
        );

        // Custom error elector doesn't work for low level calls, use string instead
        bytes memory errorData = abi.encodeWithSelector(
            SemaphoreVerifier.ProofInvalid.selector
        );

        // Test
        vm.expectRevert(errorData);
        (bool success, ) = identityManagerAddress.call(verifyProofCallData);
        assertTrue(success, "expectRevert: call did not revert");
    }

    /// @notice Checks that the verifyProof will fail with incorrect inputs.
    function testProofVerificationWithIncorrectInputs() public {
        // Setup
        ISemaphoreVerifier actualSemaphoreVerifier = new SemaphoreVerifier();
        makeNewIdentityManagerV3(
            treeDepth,
            inclusionRoot,
            defaultInsertVerifiers,
            defaultDeletionVerifiers,
            defaultUpdateVerifiers,
            actualSemaphoreVerifier
        );

        // 1) Use all-zero compressed proof so that decompress() does not revert
        //    A=0 => G1 infinity, B=0 => G2 infinity, C=0 => G1 infinity
        uint256[4] memory compressedProof = [
            uint256(0), // A in G1 compressed = 0 => point at infinity
            0, // B in G2 compressed part #1
            0, // B in G2 compressed part #2
            0 // C in G1 compressed = 0 => point at infinity
        ];

        // 2) Make the public input array with at least one element >= R.
        //    R is 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
        //    Just reuse the constant from your contract if it's public; otherwise hardcode it.
        uint256 unreducedSignalHash = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001; // >= R

        bytes memory verifyProofCallData = abi.encodeCall(
            ManagerImplV3.verifyCompressedProof,
            (
                inclusionRoot, // make sure the root is correct, as there is separate validation logic for it compared to other public inputs
                unreducedSignalHash,
                inclusionNullifierHash,
                inclusionExternalNullifierHash,
                compressedProof
            )
        );

        // Test
        assertCallFailsOn(
            identityManagerAddress,
            verifyProofCallData,
            abi.encodeWithSelector(
                SemaphoreVerifier.PublicInputNotInField.selector
            )
        );
    }
}
