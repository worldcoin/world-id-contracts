// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {ISemaphoreVerifier} from "semaphore/interfaces/ISemaphoreVerifier.sol";
import {SemaphoreTreeDepthValidator} from "../../utils/SemaphoreTreeDepthValidator.sol";
import {SimpleSemaphoreVerifier} from "../mock/SimpleSemaphoreVerifier.sol";

import {WorldIDIdentityManager as IdentityManager} from "../../WorldIDIdentityManager.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImpl} from "../../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Semaphore Proof Verification Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerSemaphoreValidation is WorldIDIdentityManagerTest {
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
        makeNewIdentityManager(
            actualTreeDepth,
            preRoot,
            defaultInsertVerifiers,
            defaultUpdateVerifiers,
            actualSemaphoreVerifier
        );
        bytes memory verifyProofCallData = abi.encodeCall(
            ManagerImpl.verifyProof,
            (preRoot, nullifierHash, signalHash, externalNullifierHash, proof)
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
            preRoot,
            defaultInsertVerifiers,
            defaultUpdateVerifiers,
            actualSemaphoreVerifier
        );
        bytes memory verifyProofCallData = abi.encodeCall(
            ManagerImpl.verifyProof,
            (preRoot, nullifierHash, signalHash, externalNullifierHash, prf)
        );

        vm.expectRevert("Semaphore__InvalidProof()");
        // Test
        assertCallFailsOn(identityManagerAddress, verifyProofCallData);
    }
}
