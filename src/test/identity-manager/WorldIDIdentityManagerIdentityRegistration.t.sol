// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {UUPSUpgradeable} from "contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";
import {SimpleVerifier, SimpleVerify} from "../mock/SimpleVerifier.sol";
import {TypeConverter as TC} from "../utils/TypeConverter.sol";
import {Verifier as TreeVerifier} from "../mock/TreeVerifier.sol";
import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

import {WorldIDIdentityManager as IdentityManager} from "../../WorldIDIdentityManager.sol";
import {WorldIDIdentityManagerImplV2 as ManagerImpl} from "../../WorldIDIdentityManagerImplV2.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImplV1} from "../../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Identity Registration Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerIdentityRegistration is WorldIDIdentityManagerTest {
    /// Taken from SimpleVerifier.sol
    event VerifiedProof(uint256 batchSize);

    /// Taken from WorldIDIdentityManagerImplV1.sol
    event TreeChanged(
        uint256 indexed preRoot, ManagerImpl.TreeChange indexed kind, uint256 indexed postRoot
    );

    /// @notice Checks that the proof validates properly with the correct inputs.
    function testRegisterIdentitiesWithCorrectInputsFromKnown() public {
        // Setup
        ITreeVerifier actualVerifier = new TreeVerifier();
        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(TC.makeDynArray([40]));
        insertVerifiers.addVerifier(identityCommitmentsSize, actualVerifier);
        makeNewIdentityManager(
            treeDepth,
            preRoot,
            insertVerifiers,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );
        bytes memory registerCallData = abi.encodeCall(
            ManagerImplV1.registerIdentities,
            (proof, preRoot, startIndex, identityCommitments, postRoot)
        );
        bytes memory latestRootCallData = abi.encodeCall(ManagerImplV1.latestRoot, ());
        bytes memory queryRootCallData = abi.encodeCall(ManagerImplV1.queryRoot, (postRoot));

        // Test
        assertCallSucceedsOn(identityManagerAddress, registerCallData);
        assertCallSucceedsOn(identityManagerAddress, latestRootCallData, abi.encode(postRoot));
        assertCallSucceedsOn(
            identityManagerAddress,
            queryRootCallData,
            abi.encode(ManagerImplV1.RootInfo(postRoot, 0, true))
        );
    }

    /// @notice Checks that the proof validates properly with correct inputs.
    function testRegisterIdentitiesWithCorrectInputs(
        uint128[8] memory prf,
        uint32 newStartIndex,
        uint128 newPreRoot,
        uint128 newPostRoot,
        uint128[] memory identities,
        address identityOperator
    ) public {
        // Setup
        vm.assume(SimpleVerify.isValidInput(uint256(prf[0])));
        vm.assume(newPreRoot != newPostRoot);
        vm.assume(identities.length <= 1000);
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
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareInsertIdentitiesTestCase(identities, prf);
        bytes memory callData = abi.encodeCall(
            ManagerImplV1.registerIdentities,
            (actualProof, newPreRoot, newStartIndex, preparedIdents, newPostRoot)
        );

        bytes memory setupCallData =
            abi.encodeCall(ManagerImplV1.setIdentityOperator, identityOperator);
        (bool success,) = identityManagerAddress.call(setupCallData);
        assert(success);

        // Expect the root to have been sent to the state bridge.
        vm.expectEmit(true, true, true, true);
        emit TreeChanged(newPreRoot, ManagerImplV1.TreeChange.Insertion, newPostRoot);
        vm.prank(identityOperator);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData);
    }

    /// @notice Ensures that identity registration selects the correct verifier when registering
    ///         identities.
    function testRegisterIdentitiesSelectsCorrectVerifier(
        uint128[8] memory prf,
        uint32 newStartIndex,
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
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareInsertIdentitiesTestCase(identities, prf);
        uint256[] memory secondIdents = new uint256[](secondIdentsLength);
        for (uint256 i = 0; i < secondIdentsLength; ++i) {
            secondIdents[i] = preparedIdents[i];
        }
        bytes memory firstCallData = abi.encodeCall(
            ManagerImplV1.registerIdentities,
            (actualProof, newPreRoot, newStartIndex, preparedIdents, newPostRoot)
        );
        uint256 secondPostRoot = uint256(newPostRoot) + 1;
        bytes memory secondCallData = abi.encodeCall(
            ManagerImplV1.registerIdentities,
            (actualProof, newPostRoot, newStartIndex, secondIdents, secondPostRoot)
        );

        vm.expectEmit(true, true, true, true);
        emit VerifiedProof(identities.length);

        // Test
        assertCallSucceedsOn(identityManagerAddress, firstCallData);

        vm.expectEmit(true, true, true, true);
        emit VerifiedProof(identities.length / 2);

        assertCallSucceedsOn(identityManagerAddress, secondCallData);
    }

    /// @notice Ensures that the contract reverts if passed a batch size it doesn't know about.
    function testCannotRegisterIdentitiesWithInvalidBatchSize(
        uint128[8] memory prf,
        uint32 newStartIndex,
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
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareInsertIdentitiesTestCase(identities, prf);

        bytes memory callData = abi.encodeCall(
            ManagerImplV1.registerIdentities,
            (actualProof, newPreRoot, newStartIndex, preparedIdents, newPostRoot)
        );
        bytes memory errorData = abi.encodeWithSelector(VerifierLookupTable.NoSuchVerifier.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
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
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareInsertIdentitiesTestCase(identities, prf);
        bytes memory callData = abi.encodeCall(
            ManagerImplV1.registerIdentities,
            (actualProof, newPreRoot, newStartIndex, preparedIdents, newPostRoot)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImplV1.ProofValidationFailure.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it reverts if the provided start index is incorrect.
    function testCannotRegisterIdentitiesIfStartIndexIncorrect(uint32 newStartIndex) public {
        // Setup
        vm.assume(newStartIndex != startIndex);
        ITreeVerifier actualVerifier = new TreeVerifier();
        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(TC.makeDynArray([70]));
        insertVerifiers.addVerifier(identityCommitmentsSize, actualVerifier);
        makeNewIdentityManager(
            treeDepth,
            preRoot,
            insertVerifiers,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );
        bytes memory registerCallData = abi.encodeCall(
            ManagerImplV1.registerIdentities,
            (proof, preRoot, newStartIndex, identityCommitments, postRoot)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImplV1.ProofValidationFailure.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, registerCallData, expectedError);
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
        ITreeVerifier actualVerifier = new TreeVerifier();
        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(TC.makeDynArray([70]));
        insertVerifiers.addVerifier(identityCommitmentsSize, actualVerifier);
        makeNewIdentityManager(
            treeDepth,
            preRoot,
            insertVerifiers,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );
        bytes memory registerCallData = abi.encodeCall(
            ManagerImplV1.registerIdentities, (proof, preRoot, startIndex, identities, postRoot)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImplV1.ProofValidationFailure.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, registerCallData, expectedError);
    }

    /// @notice Checks that it reverts if the provided post root is incorrect.
    function testCannotRegisterIdentitiesIfPostRootIncorrect(uint256 newPostRoot) public {
        // Setup
        vm.assume(newPostRoot != postRoot && newPostRoot < SNARK_SCALAR_FIELD);
        managerImpl = new ManagerImpl();
        managerImplAddress = address(managerImpl);
        ITreeVerifier actualVerifier = new TreeVerifier();
        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(TC.makeDynArray([70]));
        insertVerifiers.addVerifier(identityCommitmentsSize, actualVerifier);

        bytes memory callData = abi.encodeCall(
            ManagerImplV1.initialize,
            (treeDepth, preRoot, insertVerifiers, updateVerifiers, semaphoreVerifier)
        );

        identityManager = new IdentityManager(managerImplAddress, callData);
        identityManagerAddress = address(identityManager);

        // Init V2
        bytes memory initCallV2 = abi.encodeCall(ManagerImpl.initializeV2, (deletionVerifiers));
        bytes memory upgradeCall = abi.encodeCall(
            UUPSUpgradeable.upgradeToAndCall, (address(managerImplAddress), initCallV2)
        );
        assertCallSucceedsOn(identityManagerAddress, upgradeCall, new bytes(0x0));

        bytes memory registerCallData = abi.encodeCall(
            ManagerImplV1.registerIdentities,
            (proof, preRoot, startIndex, identityCommitments, newPostRoot)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImplV1.ProofValidationFailure.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, registerCallData, expectedError);
    }

    /// @notice Tests that it reverts if an attempt is made to register identities as an address
    ///         that is not the identity operator address.
    function testCannotRegisterIdentitiesAsNonIdentityOperator(address nonOperator) public {
        // Setup
        vm.assume(nonOperator != address(this) && nonOperator != address(0x0));
        bytes memory callData = abi.encodeCall(
            ManagerImplV1.registerIdentities,
            (proof, preRoot, startIndex, identityCommitments, postRoot)
        );
        bytes memory errorData =
            abi.encodeWithSelector(ManagerImplV1.Unauthorized.selector, nonOperator);
        vm.prank(nonOperator);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Tests that it reverts if an attempt is made to register identities with an outdated
    ///         root.
    function testCannotRegisterIdentitiesWithOutdatedRoot(
        uint256 currentPreRoot,
        uint256 actualRoot
    ) public {
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
            ManagerImplV1.registerIdentities,
            (proof, actualRoot, startIndex, identityCommitments, postRoot)
        );
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImplV1.NotLatestRoot.selector, actualRoot, uint256(currentPreRoot)
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that it reverts if an attempt is made to register identity commitments
    ///         containing an invalid identity.
    function testCannotRegisterIdentitiesWithInvalidIdentities(
        uint8 identitiesLength,
        uint8 invalidPosition
    ) public {
        // Setup
        vm.assume(identitiesLength != 0);
        vm.assume(invalidPosition < (identitiesLength - 1));
        uint256[] memory invalidCommitments = new uint256[](identitiesLength);

        for (uint256 i = 0; i < identitiesLength; ++i) {
            invalidCommitments[i] = i + 1;
        }
        invalidCommitments[invalidPosition] = 0x0;

        bytes memory callData = abi.encodeCall(
            ManagerImplV1.registerIdentities,
            (proof, initialRoot, startIndex, invalidCommitments, postRoot)
        );
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImplV1.InvalidCommitment.selector, uint256(invalidPosition + 1)
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that runs of zeroes are accepted by the `registerIdentities` function as valid
    ///         arrays of identity commitments.
    function testRegisterIdentitiesWithRunsOfZeroes(uint8 identitiesLength, uint8 zeroPosition)
        public
    {
        // Setup
        vm.assume(identitiesLength != 0 && identitiesLength <= 1000);
        vm.assume(zeroPosition < identitiesLength && zeroPosition > 0);
        uint256[] memory identities = new uint256[](identitiesLength);
        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(TC.makeDynArray([identitiesLength]));
        makeNewIdentityManager(
            treeDepth,
            initialRoot,
            insertVerifiers,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );

        for (uint256 i = 0; i < zeroPosition; ++i) {
            identities[i] = i + 1;
        }
        for (uint256 i = zeroPosition; i < identitiesLength; ++i) {
            identities[i] = 0x0;
        }

        bytes memory callData = abi.encodeCall(
            ManagerImplV1.registerIdentities,
            ([uint256(2), 1, 3, 4, 5, 6, 7, 9], initialRoot, startIndex, identities, postRoot)
        );

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, new bytes(0));
    }

    /// @notice Tests that it reverts if an attempt is made to register identity commitments that
    ///         are not in reduced form.
    function testCannotRegisterIdentitiesWithUnreducedIdentities(uint128 i) public {
        // Setup
        uint256 position = rotateSlot();
        uint256[] memory unreducedCommitments = new uint256[](identityCommitments.length);
        unreducedCommitments[position] = SNARK_SCALAR_FIELD + i;
        bytes memory callData = abi.encodeCall(
            ManagerImplV1.registerIdentities,
            (proof, initialRoot, startIndex, unreducedCommitments, postRoot)
        );
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImplV1.UnreducedElement.selector,
            ManagerImplV1.UnreducedElementType.IdentityCommitment,
            SNARK_SCALAR_FIELD + i
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that it reverts if an attempt is made to register new identities with a pre
    ///         root that is not in reduced form.
    function testCannotRegisterIdentitiesWithUnreducedPreRoot(uint128 i) public {
        // Setup
        uint256 newPreRoot = SNARK_SCALAR_FIELD + i;
        bytes memory callData = abi.encodeCall(
            ManagerImplV1.registerIdentities,
            (proof, newPreRoot, startIndex, identityCommitments, postRoot)
        );
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImplV1.UnreducedElement.selector,
            ManagerImplV1.UnreducedElementType.PreRoot,
            newPreRoot
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that it reverts if an attempt is made to register identities with a postRoot
    ///         that is not in reduced form.
    function testCannotRegisterIdentitiesWithUnreducedPostRoot(uint128 i) public {
        // Setup
        uint256 newPostRoot = SNARK_SCALAR_FIELD + i;
        bytes memory callData = abi.encodeCall(
            ManagerImplV1.registerIdentities,
            (proof, initialRoot, startIndex, identityCommitments, newPostRoot)
        );
        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImplV1.UnreducedElement.selector,
            ManagerImplV1.UnreducedElementType.PostRoot,
            newPostRoot
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that it reverts if an attempt is made to violate type safety and register with
    ///         a startIndex that is not type safe within the bounds of `type(uint32).max` and hence
    ///         within `SNARK_SCALAR_FIELD`.
    function testCannotRegisterIdentitiesWithUnreducedStartIndex(uint256 i) public {
        // Setup
        vm.assume(i > type(uint32).max);
        bytes4 functionSelector = ManagerImplV1.registerIdentities.selector;
        // Have to encode with selector as otherwise it's typechecked.
        bytes memory callData = abi.encodeWithSelector(
            functionSelector, proof, preRoot, i, identityCommitments, postRoot
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData);
    }

    /// @notice Tests that identities can only be registered through the proxy.
    function testCannotRegisterIdentitiesIfNotViaProxy() public {
        // Setup
        address expectedOwner = managerImpl.owner();
        vm.expectRevert("Function must be called through delegatecall");
        vm.prank(expectedOwner);

        // Test
        managerImpl.registerIdentities(
            proof, initialRoot, startIndex, identityCommitments, postRoot
        );
    }
}
