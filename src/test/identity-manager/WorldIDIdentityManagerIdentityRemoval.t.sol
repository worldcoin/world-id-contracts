// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";
import {SimpleVerifier, SimpleVerify} from "../mock/SimpleVerifier.sol";
import {TypeConverter as TC} from "../utils/TypeConverter.sol";
import {Verifier as TreeVerifier} from "../mock/TreeVerifier.sol";
import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

import {WorldIDIdentityManager as IdentityManager} from "../../WorldIDIdentityManager.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImpl} from "../../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Identity Removal Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerIdentityRemoval is WorldIDIdentityManagerTest {
    /// Taken from SimpleVerifier.sol
    event VerifiedProof(uint256 batchSize);

    /// @notice Checks that the proof validates properly with correct inputs.
    function testRemoveIdentitiesWithCorrectInputs(
        uint128[8] memory prf,
        uint128 newPreRoot,
        uint128 newPostRoot,
        uint128[] memory identities
    ) public {
        // Setup
        vm.assume(SimpleVerify.isValidInput(uint256(prf[0])));
        vm.assume(newPreRoot != newPostRoot);
        vm.assume(identities.length <= 1000);
        (VerifierLookupTable insertVerifiers, VerifierLookupTable updateVerifiers) =
            makeVerifierLookupTables(TC.makeDynArray([identities.length]));
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            updateVerifiers,
            semaphoreVerifier,
            isStateBridgeEnabled,
            stateBridgeProxy
        );
        (ManagerImpl.IdentityUpdate[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareRemoveIdentitiesTestCase(identities, prf);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.removeIdentities, (actualProof, newPreRoot, preparedIdents, newPostRoot)
        );

        // Expect that the state root was sent to the state bridge
        vm.expectEmit(true, true, true, true);
        emit StateRootSentMultichain(newPostRoot);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
    }

    /// @notice Ensures that identity removals select the correct verifier when removing identities.
    function testRemoveIdentitiesSelectsCorrectVerifier(
        uint128[8] memory prf,
        uint128 newPreRoot,
        uint128 newPostRoot,
        uint128[] memory identities
    ) public {
        vm.assume(SimpleVerify.isValidInput(uint256(prf[0])));
        vm.assume(newPreRoot != newPostRoot);
        vm.assume(identities.length <= 1000 && identities.length > 0);
        uint256 secondIdentsLength = identities.length / 2;
        (VerifierLookupTable insertVerifiers, VerifierLookupTable updateVerifiers) =
            makeVerifierLookupTables(TC.makeDynArray([identities.length, secondIdentsLength]));
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            updateVerifiers,
            semaphoreVerifier,
            isStateBridgeEnabled,
            stateBridgeProxy
        );
        (ManagerImpl.IdentityUpdate[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareRemoveIdentitiesTestCase(identities, prf);
        ManagerImpl.IdentityUpdate[] memory secondIdents =
            new ManagerImpl.IdentityUpdate[](secondIdentsLength);
        for (uint256 i = 0; i < secondIdentsLength; ++i) {
            secondIdents[i] = preparedIdents[i];
        }
        bytes memory firstCallData = abi.encodeCall(
            ManagerImpl.removeIdentities, (actualProof, newPreRoot, preparedIdents, newPostRoot)
        );
        uint256 secondPostRoot = uint256(newPostRoot) + 1;
        bytes memory secondCallData = abi.encodeCall(
            ManagerImpl.removeIdentities, (actualProof, newPostRoot, secondIdents, secondPostRoot)
        );

        vm.expectEmit(true, true, true, true);
        emit VerifiedProof(identities.length);
        vm.expectEmit(true, true, true, true);
        emit StateRootSentMultichain(newPostRoot);
        vm.expectEmit(true, true, true, true);
        emit VerifiedProof(identities.length / 2);
        vm.expectEmit(true, true, true, true);
        emit StateRootSentMultichain(secondPostRoot);

        // Test
        assertCallSucceedsOn(identityManagerAddress, firstCallData);
        assertCallSucceedsOn(identityManagerAddress, secondCallData);
    }

    /// @notice Ensures that the contract reverts if passed a batch size it doesn't know about.
    function testCannotRemoveIdentitiesWithInvalidBatchSize(
        uint128[8] memory prf,
        uint128 newPreRoot,
        uint128 newPostRoot,
        uint128[] memory identities
    ) public {
        vm.assume(SimpleVerify.isValidInput(uint256(prf[0])));
        vm.assume(newPreRoot != newPostRoot);
        vm.assume(identities.length > 0);
        (VerifierLookupTable insertVerifiers, VerifierLookupTable updateVerifiers) =
            makeVerifierLookupTables(TC.makeDynArray([identities.length - 1]));
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            updateVerifiers,
            semaphoreVerifier,
            isStateBridgeEnabled,
            stateBridgeProxy
        );
        (ManagerImpl.IdentityUpdate[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareRemoveIdentitiesTestCase(identities, prf);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.removeIdentities, (actualProof, newPreRoot, preparedIdents, newPostRoot)
        );
        bytes memory errorData;
        if (identities.length > 1000) {
            errorData = abi.encodeWithSelector(
                VerifierLookupTable.BatchTooLarge.selector, identities.length
            );
        } else {
            errorData = abi.encodeWithSelector(VerifierLookupTable.NoSuchVerifier.selector);
        }

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Checks that it reverts if the provided proof is incorrect for the public inputs.
    function testCannotRemoveIdentitiesWithIncorrectInputs(
        uint128[8] memory prf,
        uint128 newPreRoot,
        uint128 newPostRoot,
        uint128[] memory identities
    ) public {
        // Setup
        vm.assume(!SimpleVerify.isValidInput(uint256(prf[0])));
        vm.assume(newPreRoot != newPostRoot);
        vm.assume(identities.length <= 1000);
        (VerifierLookupTable insertVerifiers, VerifierLookupTable updateVerifiers) =
            makeVerifierLookupTables(TC.makeDynArray([identities.length]));
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            updateVerifiers,
            semaphoreVerifier,
            isStateBridgeEnabled,
            stateBridgeProxy
        );
        (ManagerImpl.IdentityUpdate[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareRemoveIdentitiesTestCase(identities, prf);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.removeIdentities, (actualProof, newPreRoot, preparedIdents, newPostRoot)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.ProofValidationFailure.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that it reverts if an attempt is made to remove identities as a non-manager.
    function testCannotRemoveIdentitiesAsNonManager(
        address nonManager,
        uint128[] memory identities,
        uint128[8] memory prf
    ) public {
        // Setup
        vm.assume(nonManager != address(this) && nonManager != address(0x0));
        (ManagerImpl.IdentityUpdate[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareRemoveIdentitiesTestCase(identities, prf);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.removeIdentities, (actualProof, preRoot, preparedIdents, postRoot)
        );
        bytes memory errorData = encodeStringRevert("Ownable: caller is not the owner");
        vm.prank(nonManager);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Ensures that it is not possible to remove identities if a provided commitment is
    ///         not zero.
    function testCannotRemoveIdentitiesIfNewCommitmentIsNonZero(
        uint256 index,
        uint128 commitment,
        uint128[] memory identities,
        uint128[8] memory prf
    ) public {
        // Setup
        vm.assume(index < identities.length && commitment != 0);
        (ManagerImpl.IdentityUpdate[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareRemoveIdentitiesTestCase(identities, prf);
        preparedIdents[index].newCommitment = uint256(commitment);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.removeIdentities, (actualProof, initialRoot, preparedIdents, postRoot)
        );
        bytes memory errorData =
            abi.encodeWithSelector(ManagerImpl.InvalidCommitment.selector, index);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Tests that it reverts if an attempt is made to remove identities with an outdated
    ///         root.
    function testCannotRegisterIdentitiesWithOutdatedRoot(
        uint256 currentPreRoot,
        uint256 actualRoot,
        uint128[] memory identities,
        uint128[8] memory prf
    ) public {
        // Setup
        vm.assume(
            currentPreRoot != actualRoot && currentPreRoot < SNARK_SCALAR_FIELD
                && actualRoot < SNARK_SCALAR_FIELD
        );
        (ManagerImpl.IdentityUpdate[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareRemoveIdentitiesTestCase(identities, prf);
        makeNewIdentityManager(
            treeDepth,
            uint256(currentPreRoot),
            defaultInsertVerifiers,
            defaultUpdateVerifiers,
            semaphoreVerifier,
            isStateBridgeEnabled,
            stateBridgeProxy
        );
        bytes memory callData = abi.encodeCall(
            ManagerImpl.removeIdentities, (actualProof, actualRoot, preparedIdents, postRoot)
        );
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImpl.NotLatestRoot.selector, actualRoot, uint256(currentPreRoot)
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that it reverts if an attempt is made to remove identity commitments that
    ///         are not in reduced form.
    function testCannotRegisterIdentitiesWithUnreducedIdentities(
        uint128 i,
        uint256 position,
        uint128 newPreRoot,
        uint128[] memory identities,
        uint128[8] memory prf
    ) public {
        // Setup
        vm.assume(position < identities.length);
        vm.assume(identities.length <= 1000);
        (ManagerImpl.IdentityUpdate[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareRemoveIdentitiesTestCase(identities, prf);
        (VerifierLookupTable insertVerifiers, VerifierLookupTable updateVerifiers) =
            makeVerifierLookupTables(TC.makeDynArray([identities.length]));
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            updateVerifiers,
            semaphoreVerifier,
            isStateBridgeEnabled,
            stateBridgeProxy
        );
        preparedIdents[position].oldCommitment = SNARK_SCALAR_FIELD + i;
        bytes memory callData = abi.encodeCall(
            ManagerImpl.removeIdentities, (actualProof, newPreRoot, preparedIdents, postRoot)
        );
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImpl.UnreducedElement.selector,
            ManagerImpl.UnreducedElementType.IdentityCommitment,
            SNARK_SCALAR_FIELD + i
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that it reverts if an attempt is made to remove identities with a pre root
    ///         that is not in reduced form.
    function testCannotUpdateIdentitiesWithUnreducedPreRoot(
        uint128 i,
        uint128[] memory identities,
        uint128[8] memory prf
    ) public {
        // Setup
        uint256 newPreRoot = SNARK_SCALAR_FIELD + i;
        (ManagerImpl.IdentityUpdate[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareRemoveIdentitiesTestCase(identities, prf);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.removeIdentities, (actualProof, newPreRoot, preparedIdents, postRoot)
        );
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImpl.UnreducedElement.selector,
            ManagerImpl.UnreducedElementType.PreRoot,
            newPreRoot
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that it reverts if an attempt is made to remove identities with a postRoot
    ///         that is not in reduced form.
    function testCannotUpdateIdentitiesWithUnreducedPostRoot(
        uint128 i,
        uint128[] memory identities,
        uint128[8] memory prf
    ) public {
        // Setup
        uint256 newPostRoot = SNARK_SCALAR_FIELD + i;
        (ManagerImpl.IdentityUpdate[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareRemoveIdentitiesTestCase(identities, prf);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.removeIdentities, (actualProof, initialRoot, preparedIdents, newPostRoot)
        );
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImpl.UnreducedElement.selector,
            ManagerImpl.UnreducedElementType.PostRoot,
            newPostRoot
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that identities can only be updated through the proxy.
    function testCannotUpdateIdentitiesIfNotViaProxy(
        uint128[] memory identities,
        uint128[8] memory prf
    ) public {
        // Setup
        address expectedOwner = managerImpl.owner();
        (ManagerImpl.IdentityUpdate[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareRemoveIdentitiesTestCase(identities, prf);
        vm.expectRevert("Function must be called through delegatecall");
        vm.prank(expectedOwner);

        // Test
        managerImpl.removeIdentities(actualProof, initialRoot, preparedIdents, postRoot);
    }
}
