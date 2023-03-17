// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {ISemaphoreVerifier} from
    "semaphore/packages/contracts/contracts/interfaces/ISemaphoreVerifier.sol";
import {SimpleVerifier, SimpleVerify} from "../mock/SimpleVerifier.sol";
import {SimpleSemaphoreVerifier} from "../mock/SimpleSemaphoreVerifier.sol";

import {WorldIDIdentityManager as IdentityManager} from "../../WorldIDIdentityManager.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImpl} from "../../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Identity Registration Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerIdentityRegistration is WorldIDIdentityManagerTest {
    /// @notice Checks that the proof validates properly with the correct inputs.
    function testProofVerificationWithCorrectInputs() public {
        // Setup
        ISemaphoreVerifier actualSemaphoreVerifier = new SimpleSemaphoreVerifier();
        makeNewIdentityManager(
            preRoot, treeVerifier, actualSemaphoreVerifier, isStateBridgeEnabled, stateBridgeProxy
        );
        uint256 nullifierHash = 0;
        uint256 signalHash = 0;
        uint256 externalNullifierHash = 0;
        bytes memory verifyProofCallData = abi.encodeCall(
            ManagerImpl.verifyProof,
            (preRoot, nullifierHash, signalHash, externalNullifierHash, proof)
        );

        // Test
        assertCallSucceedsOn(identityManagerAddress, verifyProofCallData);
    }

    /// @notice Checks that the proof validates properly with the correct inputs.
    function testProofVerificationWithInorrectProof() public {
        // Setup
        ISemaphoreVerifier actualSemaphoreVerifier = new SimpleSemaphoreVerifier();
        makeNewIdentityManager(
            preRoot, treeVerifier, actualSemaphoreVerifier, isStateBridgeEnabled, stateBridgeProxy
        );
        uint256 nullifierHash = 0;
        uint256 signalHash = 0;
        uint256 externalNullifierHash = 0;
        uint256[8] memory actualProof =
            [proof[0], proof[1], proof[2], proof[3], proof[4], proof[5], proof[6], 0];
        bytes memory verifyProofCallData = abi.encodeCall(
            ManagerImpl.verifyProof,
            (preRoot, nullifierHash, signalHash, externalNullifierHash, actualProof)
        );

        vm.expectRevert("Semaphore__InvalidProof()");
        // Test
        assertCallFailsOn(identityManagerAddress, verifyProofCallData);
    }
}
