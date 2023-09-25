// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";
import {SimpleVerifier, SimpleVerify} from "../mock/SimpleVerifier.sol";
import {TypeConverter as TC} from "../utils/TypeConverter.sol";
import {Verifier as TreeVerifier} from "../mock/DeletionTreeVerifier.sol";
import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

import {WorldIDIdentityManager as IdentityManager} from "../../WorldIDIdentityManager.sol";
import {WorldIDIdentityManagerImplV2 as ManagerImpl} from "../../WorldIDIdentityManagerImplV2.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImplV1} from "../../WorldIDIdentityManagerImplV1.sol";

import {console} from "forge-std/console.sol";

/// @title World ID Identity Manager Identity Deletion Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerIdentityDeletion is WorldIDIdentityManagerTest {
    /// Taken from SimpleVerifier.sol
    event VerifiedProof(uint256 batchSize);

    /// Taken from WorldIDIdentityManagerImplV1.sol
    event TreeChanged(
        uint256 indexed deletionPreRoot,
        ManagerImpl.TreeChange indexed kind,
        uint256 indexed deletionPostRoot
    );

    /// @notice Checks that the deletionProof validates properly with the correct inputs.
    function testDeleteIdentitiesWithCorrectInputsFromKnown() public {
        // Setup
        ITreeVerifier actualVerifier = new TreeVerifier();
        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(TC.makeDynArray([40]));
        deletionVerifiers.addVerifier(deletionBatchSize, actualVerifier);
        makeNewIdentityManager(
            treeDepth,
            deletionPreRoot,
            insertVerifiers,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );
        bytes memory deleteCallData = abi.encodeCall(
            ManagerImpl.deleteIdentities,
            (
                deletionProof,
                deletionBatchSize,
                packedDeletionIndices,
                deletionPreRoot,
                deletionPostRoot
            )
        );
        bytes memory latestRootCallData = abi.encodeCall(ManagerImplV1.latestRoot, ());
        bytes memory queryRootCallData = abi.encodeCall(ManagerImplV1.queryRoot, (deletionPostRoot));

        // Test
        assertCallSucceedsOn(identityManagerAddress, deleteCallData);
        assertCallSucceedsOn(
            identityManagerAddress, latestRootCallData, abi.encode(deletionPostRoot)
        );
        assertCallSucceedsOn(
            identityManagerAddress,
            queryRootCallData,
            abi.encode(ManagerImplV1.RootInfo(deletionPostRoot, 0, true))
        );
    }

    /// @notice Checks that the deletionProof validates properly with correct inputs.
    function testDeleteIdentitiesWithCorrectInputs(
        uint128[8] memory prf,
        uint128 newPreRoot,
        bytes calldata packedDeletionIndices,
        uint128 newPostRoot,
        address identityOperator
    ) public {
        // Setup
        vm.assume(SimpleVerify.isValidInput(uint256(prf[0])));
        vm.assume(newPreRoot != newPostRoot);
        vm.assume(packedDeletionIndices.length <= 125);
        vm.assume(identityOperator != nullAddress && identityOperator != thisAddress);
        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(TC.makeDynArray([packedDeletionIndices.length * 8]));
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );
        uint256[8] memory actualProof = prepareDeleteIdentitiesTestCase(prf);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.deleteIdentities,
            (
                actualProof,
                uint32(packedDeletionIndices.length * 8),
                packedDeletionIndices,
                newPreRoot,
                newPostRoot
            )
        );

        bytes memory setupCallData =
            abi.encodeCall(ManagerImplV1.setIdentityOperator, identityOperator);
        (bool success,) = identityManagerAddress.call(setupCallData);
        assert(success);

        // Expect the root to have been sent to the state bridge.
        vm.expectEmit(true, true, true, true);
        emit TreeChanged(newPreRoot, ManagerImplV1.TreeChange.Deletion, newPostRoot);
        vm.prank(identityOperator);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
    }

    /// @notice Ensures that identity deletion selects the correct verifier when deleting
    ///         identities.
    function testDeleteIdentitiesSelectsCorrectVerifier(
        uint128[8] memory prf,
        uint128 newPreRoot,
        bytes calldata packedDeletionIndices,
        uint128 newPostRoot
    ) public {
        vm.assume(SimpleVerify.isValidInput(uint256(prf[0])));
        vm.assume(newPreRoot != newPostRoot);
        vm.assume(packedDeletionIndices.length <= 1000 && packedDeletionIndices.length > 0);

        bytes memory secondIndices = abi.encodePacked(uint32(0), uint32(2), uint32(4), uint32(6));
        uint32 secondIndicesLength = uint32(secondIndices.length);

        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(TC.makeDynArray([deletionBatchSize, secondIndicesLength]));
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );
        uint256[8] memory actualProof = prepareDeleteIdentitiesTestCase(prf);
        bytes memory firstCallData = abi.encodeCall(
            ManagerImpl.deleteIdentities,
            (actualProof, deletionBatchSize, packedDeletionIndices, newPreRoot, newPostRoot)
        );
        uint256 secondPostRoot = uint256(newPostRoot) + 1;
        bytes memory secondCallData = abi.encodeCall(
            ManagerImpl.deleteIdentities,
            (actualProof, secondIndicesLength, secondIndices, newPostRoot, secondPostRoot)
        );

        vm.expectEmit(true, true, true, true);
        emit VerifiedProof(deletionBatchSize);

        // Test
        assertCallSucceedsOn(identityManagerAddress, firstCallData);

        vm.expectEmit(true, true, true, true);
        emit VerifiedProof(uint256(secondIndicesLength));

        assertCallSucceedsOn(identityManagerAddress, secondCallData);
    }

    /// @notice Ensures that the contract reverts if passed a batch size it doesn't know about.
    function testCannotDeleteIdentitiesWithInvalidBatchSize(
        uint128[8] memory prf,
        uint128 newPreRoot,
        bytes calldata packedDeletionIndices,
        uint128 newPostRoot
    ) public {
        vm.assume(SimpleVerify.isValidInput(uint256(prf[0])));
        vm.assume(newPreRoot != newPostRoot);
        vm.assume(packedDeletionIndices.length > 0);
        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(TC.makeDynArray([deletionBatchSize - 1]));
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );
        uint256[8] memory actualProof = prepareDeleteIdentitiesTestCase(prf);

        bytes memory callData = abi.encodeCall(
            ManagerImpl.deleteIdentities,
            (actualProof, deletionBatchSize, packedDeletionIndices, newPreRoot, newPostRoot)
        );
        bytes memory errorData = abi.encodeWithSelector(VerifierLookupTable.NoSuchVerifier.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Checks that it reverts if the provided deletionProof is incorrect for the public inputs.
    function testCannotDeleteIdentitiesWithIncorrectInputs(
        uint128[8] memory prf,
        uint128 newPreRoot,
        uint128 newPostRoot
    ) public {
        // Setup
        vm.assume(!SimpleVerify.isValidInput(uint256(prf[0])));
        vm.assume(newPreRoot != newPostRoot);
        ITreeVerifier actualVerifier = new TreeVerifier();
        uint32 indicesLength = uint32(packedDeletionIndices.length);
        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(TC.makeDynArray([70]));
        deletionVerifiers.addVerifier(indicesLength, actualVerifier);
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );
        uint256[8] memory actualProof = prepareDeleteIdentitiesTestCase(prf);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.deleteIdentities,
            (actualProof, indicesLength, packedDeletionIndices, newPreRoot, newPostRoot)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImplV1.ProofValidationFailure.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it reverts if the provided post root is incorrect.
    function testCannotDeleteIdentitiesIfPostRootIncorrect(uint256 newPostRoot) public {
        // Setup
        vm.assume(newPostRoot != deletionPostRoot && newPostRoot < SNARK_SCALAR_FIELD);
        ITreeVerifier actualVerifier = new TreeVerifier();
        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(TC.makeDynArray([70]));
        deletionVerifiers.addVerifier(deletionBatchSize, actualVerifier);
        makeNewIdentityManager(
            treeDepth,
            deletionPreRoot,
            insertVerifiers,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );

        bytes memory deletionCallData = abi.encodeCall(
            ManagerImpl.deleteIdentities,
            (deletionProof, deletionBatchSize, packedDeletionIndices, deletionPreRoot, newPostRoot)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImplV1.ProofValidationFailure.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, deletionCallData, expectedError);
    }

    /// @notice Tests that it reverts if an attempt is made to delete identities as an address
    ///         that is not the identity operator address.
    function testCannotDeleteIdentitiesAsNonIdentityOperator(address nonOperator) public {
        // Setup
        vm.assume(nonOperator != address(this) && nonOperator != address(0x0));
        bytes memory callData = abi.encodeCall(
            ManagerImpl.deleteIdentities,
            (
                deletionProof,
                deletionBatchSize,
                packedDeletionIndices,
                deletionPreRoot,
                deletionPostRoot
            )
        );
        bytes memory errorData =
            abi.encodeWithSelector(ManagerImplV1.Unauthorized.selector, nonOperator);
        vm.prank(nonOperator);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Tests that it reverts if an attempt is made to delete identities with an outdated
    ///         root.
    function testCannotDeleteIdentitiesWithOutdatedRoot(uint256 currentPreRoot, uint256 actualRoot)
        public
    {
        // Setup
        vm.assume(
            currentPreRoot != actualRoot && currentPreRoot < SNARK_SCALAR_FIELD
                && actualRoot < SNARK_SCALAR_FIELD
        );
        makeNewIdentityManager(
            treeDepth,
            uint256(currentPreRoot),
            defaultInsertVerifiers,
            defaultDeletionVerifiers,
            defaultUpdateVerifiers,
            semaphoreVerifier
        );
        bytes memory callData = abi.encodeCall(
            ManagerImpl.deleteIdentities,
            (deletionProof, deletionBatchSize, packedDeletionIndices, actualRoot, deletionPostRoot)
        );
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImplV1.NotLatestRoot.selector, actualRoot, uint256(currentPreRoot)
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that it reverts if an attempt is made to delete identities with a pre
    ///         root that is not in reduced form.
    function testCannotDeleteIdentitiesWithUnreducedPreRoot(uint128 i) public {
        // Setup
        uint256 newPreRoot = SNARK_SCALAR_FIELD + i;
        bytes memory callData = abi.encodeCall(
            ManagerImpl.deleteIdentities,
            (deletionProof, deletionBatchSize, packedDeletionIndices, newPreRoot, deletionPostRoot)
        );
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImplV1.UnreducedElement.selector,
            ManagerImplV1.UnreducedElementType.PreRoot,
            newPreRoot
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that it reverts if an attempt is made to delete identities with a deletionPostRoot
    ///         that is not in reduced form.
    function testCannotDeleteIdentitiesWithUnreducedPostRoot(uint128 i) public {
        // Setup
        uint256 newPostRoot = SNARK_SCALAR_FIELD + i;
        bytes memory callData = abi.encodeCall(
            ManagerImpl.deleteIdentities,
            (deletionProof, deletionBatchSize, packedDeletionIndices, initialRoot, newPostRoot)
        );
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImplV1.UnreducedElement.selector,
            ManagerImplV1.UnreducedElementType.PostRoot,
            newPostRoot
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that identities can only be deleted through the proxy.
    function testCannotDelteIdentitiesIfNotViaProxy() public {
        // Setup
        address expectedOwner = managerImpl.owner();
        vm.expectRevert("Function must be called through delegatecall");
        vm.prank(expectedOwner);

        // Test
        managerImpl.deleteIdentities(
            deletionProof, deletionBatchSize, packedDeletionIndices, initialRoot, deletionPostRoot
        );
    }
}
