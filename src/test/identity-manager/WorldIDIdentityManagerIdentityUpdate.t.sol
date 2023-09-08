// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";
import {SimpleVerifier, SimpleVerify} from "../mock/SimpleVerifier.sol";
import {TypeConverter as TC} from "../utils/TypeConverter.sol";
import {Verifier as TreeVerifier} from "../mock/InsertionTreeVerifier.sol";
import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

import {WorldIDIdentityManager as IdentityManager} from "../../WorldIDIdentityManager.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImpl} from "../../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Identity Update Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerIdentityUpdate is WorldIDIdentityManagerTest {
    /// Taken from SimpleVerifier.sol
    event VerifiedProof(uint256 batchSize);

    /// Taken from WorldIDIdentityManagerImplV1.sol
    event TreeChanged(
        uint256 indexed insertionPreRoot,
        ManagerImpl.TreeChange indexed kind,
        uint256 indexed insertionPostRoot
    );

    /// @notice Checks that the proof validates properly with correct inputs.
    function testUpdateIdentitiesWithCorrectInputs(
        uint128[8] memory prf,
        uint128 newPreRoot,
        uint128 newPostRoot,
        uint128[] memory identities,
        address identityOperator
    ) public {
        // Setup
        vm.assume(SimpleVerify.isValidInput(uint256(prf[0])));
        vm.assume(newPreRoot != newPostRoot);
        vm.assume(identities.length <= 1000); // Keeps the test time sane-ish.
        vm.assume(identityOperator != nullAddress && identityOperator != thisAddress);
        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(TC.makeDynArray([identities.length]));
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );
        (
            uint32[] memory leafIndices,
            uint256[] memory oldIdents,
            uint256[] memory newIdents,
            uint256[8] memory actualProof
        ) = prepareUpdateIdentitiesTestCase(identities, prf);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.updateIdentities,
            (actualProof, newPreRoot, leafIndices, oldIdents, newIdents, newPostRoot)
        );

        bytes memory setupCallData =
            abi.encodeCall(ManagerImpl.setIdentityOperator, identityOperator);
        (bool success,) = identityManagerAddress.call(setupCallData);
        assert(success);

        // Expect that the state root was sent to the state bridge
        vm.expectEmit(true, true, true, true);
        emit TreeChanged(newPreRoot, ManagerImpl.TreeChange.Update, newPostRoot);
        vm.prank(identityOperator);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
    }

    /// @notice Ensures that identity updates select the correct verifier when updating identities.
    function testUpdateIdentitiesSelectsCorrectVerifier(
        uint128[8] memory prf,
        uint128 newPreRoot,
        uint128 newPostRoot,
        uint128[] memory identities
    ) public {
        vm.assume(SimpleVerify.isValidInput(uint256(prf[0])));
        vm.assume(newPreRoot != newPostRoot);
        vm.assume(identities.length <= 1000 && identities.length > 0);
        uint256 secondIdentsLength = identities.length / 2;
        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(TC.makeDynArray([identities.length, secondIdentsLength]));
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );
        (
            uint32[] memory leafIndices,
            uint256[] memory oldIdents,
            uint256[] memory newIdents,
            uint256[8] memory actualProof
        ) = prepareUpdateIdentitiesTestCase(identities, prf);

        part2TestUpdateIdentitiesSelectsCorrectVerifier(
            actualProof, newPreRoot, leafIndices, oldIdents, newIdents, newPostRoot
        );
    }

    /// @notice Exists to work around local variable limits.
    function part2TestUpdateIdentitiesSelectsCorrectVerifier(
        uint256[8] memory actualProof,
        uint256 newPreRoot,
        uint32[] memory leafIndices,
        uint256[] memory oldIdents,
        uint256[] memory newIdents,
        uint256 newPostRoot
    ) public {
        uint256 secondIdentsLength = leafIndices.length / 2;
        uint32[] memory secondLeafIndices = new uint32[](secondIdentsLength);
        uint256[] memory secondOldIdents = new uint256[](secondIdentsLength);
        uint256[] memory secondNewIdents = new uint256[](secondIdentsLength);
        for (uint256 i = 0; i < secondIdentsLength; ++i) {
            secondLeafIndices[i] = leafIndices[i];
            secondOldIdents[i] = oldIdents[i];
            secondNewIdents[i] = newIdents[i];
        }

        part3TestUpdateIdentitiesSelectsCorrectVerifier(
            actualProof,
            newPreRoot,
            leafIndices,
            oldIdents,
            newIdents,
            newPostRoot,
            secondLeafIndices,
            secondOldIdents,
            secondNewIdents
        );
    }

    /// @notice Exists to work around local variable limits.
    function part3TestUpdateIdentitiesSelectsCorrectVerifier(
        uint256[8] memory actualProof,
        uint256 newPreRoot,
        uint32[] memory leafIndices,
        uint256[] memory oldIdents,
        uint256[] memory newIdents,
        uint256 newPostRoot,
        uint32[] memory secondLeafIndices,
        uint256[] memory secondOldIdents,
        uint256[] memory secondNewIdents
    ) public {
        bytes memory firstCallData = abi.encodeCall(
            ManagerImpl.updateIdentities,
            (actualProof, newPreRoot, leafIndices, oldIdents, newIdents, newPostRoot)
        );
        uint256 secondPostRoot = uint256(newPostRoot) + 1;
        bytes memory secondCallData = abi.encodeCall(
            ManagerImpl.updateIdentities,
            (
                actualProof,
                newPostRoot,
                secondLeafIndices,
                secondOldIdents,
                secondNewIdents,
                secondPostRoot
            )
        );

        vm.expectEmit(true, true, true, true);
        emit VerifiedProof(oldIdents.length);

        // Test
        assertCallSucceedsOn(identityManagerAddress, firstCallData);

        vm.expectEmit(true, true, true, true);
        emit VerifiedProof(secondOldIdents.length);

        assertCallSucceedsOn(identityManagerAddress, secondCallData);
    }

    /// @notice Ensures that the contract reverts if passed a batch size it doesn't know about.
    function testCannotUpdateIdentitiesWithInvalidBatchSize(
        uint128[8] memory prf,
        uint128 newPreRoot,
        uint128 newPostRoot,
        uint128[] memory identities
    ) public {
        vm.assume(SimpleVerify.isValidInput(uint256(prf[0])));
        vm.assume(newPreRoot != newPostRoot);
        vm.assume(identities.length > 0);
        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(TC.makeDynArray([identities.length - 1]));
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );
        (
            uint32[] memory leafIndices,
            uint256[] memory oldIdents,
            uint256[] memory newIdents,
            uint256[8] memory actualProof
        ) = prepareUpdateIdentitiesTestCase(identities, prf);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.updateIdentities,
            (actualProof, newPreRoot, leafIndices, oldIdents, newIdents, newPostRoot)
        );
        bytes memory errorData = abi.encodeWithSelector(VerifierLookupTable.NoSuchVerifier.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Checks that it reverts if the provided proof is incorrect for the public inputs.
    function testCannotUpdateIdentitiesWithIncorrectInputs(
        uint128[8] memory prf,
        uint128 newPreRoot,
        uint128 newPostRoot,
        uint128[] memory identities
    ) public {
        // Setup
        vm.assume(!SimpleVerify.isValidInput(uint256(prf[0])));
        vm.assume(newPreRoot != newPostRoot);
        vm.assume(identities.length <= 1000);
        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(TC.makeDynArray([identities.length]));
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );
        (
            uint32[] memory leafIndices,
            uint256[] memory oldIdents,
            uint256[] memory newIdents,
            uint256[8] memory actualProof
        ) = prepareUpdateIdentitiesTestCase(identities, prf);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.updateIdentities,
            (actualProof, newPreRoot, leafIndices, oldIdents, newIdents, newPostRoot)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImpl.ProofValidationFailure.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that it reverts if an attempt is made to update identities as an address that
    ///         is not the identity operator address.
    function testCannotUpdateIdentitiesAsNonIdentityOperator(
        address nonOperator,
        uint128[] memory identities,
        uint128[8] memory prf
    ) public {
        // Setup
        vm.assume(nonOperator != address(this) && nonOperator != address(0x0));
        (
            uint32[] memory leafIndices,
            uint256[] memory oldIdents,
            uint256[] memory newIdents,
            uint256[8] memory actualProof
        ) = prepareUpdateIdentitiesTestCase(identities, prf);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.updateIdentities,
            (actualProof, insertionPreRoot, leafIndices, oldIdents, newIdents, insertionPostRoot)
        );
        bytes memory errorData =
            abi.encodeWithSelector(ManagerImpl.Unauthorized.selector, nonOperator);
        vm.prank(nonOperator);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Tests that it reverts if an attempt is made to update identities with an outdated
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
        vm.assume(identities.length <= 1000);
        (
            uint32[] memory leafIndices,
            uint256[] memory oldIdents,
            uint256[] memory newIdents,
            uint256[8] memory actualProof
        ) = prepareUpdateIdentitiesTestCase(identities, prf);
        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(TC.makeDynArray([identities.length]));
        makeNewIdentityManager(
            treeDepth,
            uint256(currentPreRoot),
            insertVerifiers,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );
        bytes memory callData = abi.encodeCall(
            ManagerImpl.updateIdentities,
            (actualProof, actualRoot, leafIndices, oldIdents, newIdents, insertionPostRoot)
        );
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImpl.NotLatestRoot.selector, actualRoot, uint256(currentPreRoot)
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
        (
            uint32[] memory leafIndices,
            uint256[] memory oldIdents,
            uint256[] memory newIdents,
            uint256[8] memory actualProof
        ) = prepareUpdateIdentitiesTestCase(identities, prf);
        vm.expectRevert("Function must be called through delegatecall");
        vm.prank(expectedOwner);

        // Test
        managerImpl.updateIdentities(
            actualProof, initialRoot, leafIndices, oldIdents, newIdents, insertionPostRoot
        );
    }
}
