// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UUPSUpgradeable} from "contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {ITreeVerifier4844 as ITreeVerifier} from "../../interfaces/ITreeVerifier4844.sol";
import {SimpleVerify} from "../mock/SimpleVerifier.sol";
import {TypeConverter as TC} from "../utils/TypeConverter.sol";
import {Verifier as TreeVerifier} from "src/test/InsertionTreeVerifier164844.sol";
import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";
import {VerifierLookupTable4844} from "../../data/VerifierLookupTable4844.sol";

import {WorldIDIdentityManager as IdentityManager} from "../../WorldIDIdentityManager.sol";
import {WorldIDIdentityManagerImplV2 as ManagerImpl} from "../../WorldIDIdentityManagerImplV2.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImplV1} from "../../WorldIDIdentityManagerImplV1.sol";
import {WorldIDIdentityManagerImplV3 as ManagerImplV3} from "../../WorldIDIdentityManagerImplV3.sol";

/// @title World ID Identity Manager Identity Registration Tests for EIP-4844 protocol.
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerIdentityRegistration4844 is WorldIDIdentityManagerTest {
    /// Taken from SimpleVerifier.sol
    event VerifiedProof(uint256 batchSize);

    /// Taken from WorldIDIdentityManagerImplV1.sol
    event TreeChanged(
        uint256 indexed insertionPreRoot,
        ManagerImplV1.TreeChange indexed kind,
        uint256 indexed insertionPostRoot
    );

    /// @notice Checks that the proof validates properly with the correct inputs.
    function testRegisterIdentitiesWithCorrectInputsFromKnown() public {
        // Setup
        ITreeVerifier actualVerifier = new TreeVerifier();
        (insertVerifiers, deletionVerifiers, updateVerifiers, insertVerifiers4844) =
            makeVerifierLookupTables(TC.makeDynArray([40]));
        insertVerifiers4844.addVerifier(identityCommitmentsSize, actualVerifier);
        makeNewIdentityManager(
            treeDepth,
            insertionPreRoot,
            insertVerifiers,
            insertVerifiers4844,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );

        ManagerImplV3.RegisterIdentities4844Params memory params = ManagerImplV3
            .RegisterIdentities4844Params({
            insertionProof: insertionProof4844,
            commitments: commitments,
            commitmentPok: commitmentsPok,
            kzgCommitment: kzgCommitment,
            kzgProof: kzgProof,
            expectedEvaluation: insertionExpectedEvaluation,
            preRoot: insertionPreRoot,
            postRoot: insertionPostRoot4844,
            inputHash: insertionInputHash4844,
            batchSize: uint32(identityCommitmentsSize),
            startIndex: startIndex
        });

        // Mock blobhash. This is valid for the next call only.
        prepareBlobhash(kzgToVersionedHash(kzgCommitment));

        bytes memory registerCallData = abi.encodeCall(ManagerImplV3.registerIdentities4844, params);

        bytes memory latestRootCallData = abi.encodeCall(ManagerImplV1.latestRoot, ());
        bytes memory queryRootCallData =
            abi.encodeCall(ManagerImplV1.queryRoot, (insertionPostRoot4844));

        // Test
        assertCallSucceedsOn(identityManagerAddress, registerCallData);
        assertCallSucceedsOn(
            identityManagerAddress, latestRootCallData, abi.encode(insertionPostRoot4844)
        );
        assertCallSucceedsOn(
            identityManagerAddress,
            queryRootCallData,
            abi.encode(ManagerImplV1.RootInfo(insertionPostRoot4844, 0, true))
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
        (insertVerifiers, deletionVerifiers, updateVerifiers, insertVerifiers4844) =
            makeVerifierLookupTables(TC.makeDynArray([identities.length]));
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            insertVerifiers4844,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );

        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareInsertIdentitiesTestCase(identities, prf);

        ManagerImplV3.RegisterIdentities4844Params memory params = ManagerImplV3
            .RegisterIdentities4844Params({
            insertionProof: actualProof,
            commitments: commitments,
            commitmentPok: commitmentsPok,
            kzgCommitment: kzgCommitment,
            kzgProof: kzgProof,
            expectedEvaluation: insertionExpectedEvaluation,
            preRoot: newPreRoot,
            postRoot: newPostRoot,
            inputHash: insertionInputHash4844,
            batchSize: uint32(preparedIdents.length),
            startIndex: newStartIndex
        });

        // Mock blobhash. This is valid for the next call only.
        prepareBlobhash(kzgToVersionedHash(kzgCommitment));
        bytes memory callData = abi.encodeCall(ManagerImplV3.registerIdentities4844, params);

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
        (insertVerifiers, deletionVerifiers, updateVerifiers, insertVerifiers4844) =
            makeVerifierLookupTables(TC.makeDynArray([identities.length, secondIdentsLength]));
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            insertVerifiers4844,
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

        ManagerImplV3.RegisterIdentities4844Params memory params = ManagerImplV3
            .RegisterIdentities4844Params({
            insertionProof: actualProof,
            commitments: commitments,
            commitmentPok: commitmentsPok,
            kzgCommitment: kzgCommitment,
            kzgProof: kzgProof,
            expectedEvaluation: insertionExpectedEvaluation,
            preRoot: newPreRoot,
            postRoot: newPostRoot,
            inputHash: insertionInputHash4844,
            batchSize: uint32(preparedIdents.length),
            startIndex: newStartIndex
        });

        // Mock blobhash. This is valid for the next call only.
        prepareBlobhash(kzgToVersionedHash(kzgCommitment));
        bytes memory firstCallData = abi.encodeCall(ManagerImplV3.registerIdentities4844, params);

        uint256 secondPostRoot = uint256(newPostRoot) + 1;
        params.preRoot = newPostRoot;
        params.batchSize = uint32(secondIdentsLength);
        params.postRoot = secondPostRoot;

        // Mock blobhash. This is valid for the next call only.
        prepareBlobhash(kzgToVersionedHash(kzgCommitment));
        bytes memory secondCallData = abi.encodeCall(ManagerImplV3.registerIdentities4844, params);

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
        (insertVerifiers, deletionVerifiers, updateVerifiers, insertVerifiers4844) =
            makeVerifierLookupTables(TC.makeDynArray([identities.length - 1]));
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            insertVerifiers4844,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );
        (uint256[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareInsertIdentitiesTestCase(identities, prf);

        ManagerImplV3.RegisterIdentities4844Params memory params = ManagerImplV3
            .RegisterIdentities4844Params({
            insertionProof: actualProof,
            commitments: commitments,
            commitmentPok: commitmentsPok,
            kzgCommitment: kzgCommitment,
            kzgProof: kzgProof,
            expectedEvaluation: insertionExpectedEvaluation,
            preRoot: newPreRoot,
            postRoot: newPostRoot,
            inputHash: insertionInputHash4844,
            batchSize: uint32(preparedIdents.length),
            startIndex: newStartIndex
        });

        // Mock blobhash. This is valid for the next call only.
        prepareBlobhash(kzgToVersionedHash(kzgCommitment));
        bytes memory callData = abi.encodeCall(ManagerImplV3.registerIdentities4844, params);

        bytes memory errorData =
            abi.encodeWithSelector(VerifierLookupTable4844.NoSuchVerifier.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, errorData);
    }

    /// @notice Checks that it reverts if the provided proof is incorrect for the public inputs.
    function testCannotRegisterIdentitiesWithIncorrectInputs(
        uint128[8] memory prf,
        uint32 newStartIndex,
        uint128 newPreRoot,
        uint128 newPostRoot
    ) public {
        // Setup
        vm.assume(!SimpleVerify.isValidInput(uint256(prf[0])));
        ITreeVerifier actualVerifier = new TreeVerifier();
        (insertVerifiers, deletionVerifiers, updateVerifiers, insertVerifiers4844) =
            makeVerifierLookupTables(TC.makeDynArray([70]));
        insertVerifiers4844.addVerifier(identityCommitments.length, actualVerifier);
        makeNewIdentityManager(
            treeDepth,
            newPreRoot,
            insertVerifiers,
            insertVerifiers4844,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );

        ManagerImplV3.RegisterIdentities4844Params memory params = ManagerImplV3
            .RegisterIdentities4844Params({
            insertionProof: insertionProof,
            commitments: commitments,
            commitmentPok: commitmentsPok,
            kzgCommitment: kzgCommitment,
            kzgProof: kzgProof,
            expectedEvaluation: insertionExpectedEvaluation,
            preRoot: newPreRoot,
            postRoot: newPostRoot,
            inputHash: insertionInputHash4844,
            batchSize: uint32(identityCommitments.length),
            startIndex: newStartIndex
        });

        // Mock blobhash. This is valid for the next call only.
        prepareBlobhash(kzgToVersionedHash(kzgCommitment));
        bytes memory callData = abi.encodeCall(ManagerImplV3.registerIdentities4844, params);

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
        (insertVerifiers, deletionVerifiers, updateVerifiers, insertVerifiers4844) =
            makeVerifierLookupTables(TC.makeDynArray([70]));
        insertVerifiers4844.addVerifier(identityCommitmentsSize, actualVerifier);
        makeNewIdentityManager(
            treeDepth,
            insertionPreRoot,
            insertVerifiers,
            insertVerifiers4844,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );

        ManagerImplV3.RegisterIdentities4844Params memory params = ManagerImplV3
            .RegisterIdentities4844Params({
            insertionProof: insertionProof,
            commitments: commitments,
            commitmentPok: commitmentsPok,
            kzgCommitment: kzgCommitment,
            kzgProof: kzgProof,
            expectedEvaluation: insertionExpectedEvaluation,
            preRoot: insertionPreRoot,
            postRoot: insertionPostRoot,
            inputHash: insertionInputHash4844,
            batchSize: uint32(identityCommitments.length),
            startIndex: newStartIndex
        });

        // Mock blobhash. This is valid for the next call only.
        prepareBlobhash(kzgToVersionedHash(kzgCommitment));
        bytes memory registerCallData = abi.encodeCall(ManagerImplV3.registerIdentities4844, params);

        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImplV1.ProofValidationFailure.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, registerCallData, expectedError);
    }

    /// @notice Checks that it reverts if the provided post root is incorrect.
    function testCannotRegisterIdentitiesIfPostRootIncorrect(uint256 newPostRoot) public {
        // Setup
        vm.assume(newPostRoot != insertionPostRoot && newPostRoot < SNARK_SCALAR_FIELD);
        managerImplV2 = new ManagerImpl();
        managerImplV2Address = address(managerImplV2);
        ITreeVerifier actualVerifier = new TreeVerifier();
        (insertVerifiers, deletionVerifiers, updateVerifiers, insertVerifiers4844) =
            makeVerifierLookupTables(TC.makeDynArray([70]));
        insertVerifiers4844.addVerifier(identityCommitmentsSize, actualVerifier);

        bytes memory callData = abi.encodeCall(
            ManagerImplV1.initialize,
            (treeDepth, insertionPreRoot, insertVerifiers, updateVerifiers, semaphoreVerifier)
        );

        identityManager = new IdentityManager(managerImplV2Address, callData);
        identityManagerAddress = address(identityManager);

        // Init V2
        bytes memory initCallV2 = abi.encodeCall(ManagerImpl.initializeV2, (deletionVerifiers));
        bytes memory upgradeCall = abi.encodeCall(
            UUPSUpgradeable.upgradeToAndCall, (address(managerImplV2Address), initCallV2)
        );
        assertCallSucceedsOn(identityManagerAddress, upgradeCall, new bytes(0x0));

        // Init V3
        managerImplV3 = new ManagerImplV3();
        managerImplV3Address = address(managerImplV3);
        bytes memory initCallV3 = abi.encodeCall(managerImplV3.initializeV3, (insertVerifiers4844));
        bytes memory upgradeCallV3 = abi.encodeCall(
            UUPSUpgradeable.upgradeToAndCall, (address(managerImplV3Address), initCallV3)
        );
        assertCallSucceedsOn(identityManagerAddress, upgradeCallV3, new bytes(0x0));

        ManagerImplV3.RegisterIdentities4844Params memory params = ManagerImplV3
            .RegisterIdentities4844Params({
            insertionProof: insertionProof,
            commitments: commitments,
            commitmentPok: commitmentsPok,
            kzgCommitment: kzgCommitment,
            kzgProof: kzgProof,
            expectedEvaluation: insertionExpectedEvaluation,
            preRoot: insertionPreRoot,
            postRoot: newPostRoot,
            inputHash: insertionInputHash4844,
            batchSize: uint32(identityCommitments.length),
            startIndex: startIndex
        });

        // Mock blobhash. This is valid for the next call only.
        prepareBlobhash(kzgToVersionedHash(kzgCommitment));
        bytes memory registerCallData = abi.encodeCall(ManagerImplV3.registerIdentities4844, params);

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

        ManagerImplV3.RegisterIdentities4844Params memory params = ManagerImplV3
            .RegisterIdentities4844Params({
            insertionProof: insertionProof,
            commitments: commitments,
            commitmentPok: commitmentsPok,
            kzgCommitment: kzgCommitment,
            kzgProof: kzgProof,
            expectedEvaluation: insertionExpectedEvaluation,
            preRoot: insertionPreRoot,
            postRoot: insertionPostRoot,
            inputHash: insertionInputHash4844,
            batchSize: uint32(identityCommitments.length),
            startIndex: startIndex
        });

        // Mock blobhash. This is valid for the next call only.
        prepareBlobhash(kzgToVersionedHash(kzgCommitment));
        bytes memory callData = abi.encodeCall(ManagerImplV3.registerIdentities4844, params);

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
            defaultInsertVerifiers4844,
            defaultDeletionVerifiers,
            defaultUpdateVerifiers,
            semaphoreVerifier
        );

        ManagerImplV3.RegisterIdentities4844Params memory params = ManagerImplV3
            .RegisterIdentities4844Params({
            insertionProof: insertionProof,
            commitments: commitments,
            commitmentPok: commitmentsPok,
            kzgCommitment: kzgCommitment,
            kzgProof: kzgProof,
            expectedEvaluation: insertionExpectedEvaluation,
            preRoot: actualRoot,
            postRoot: insertionPostRoot,
            inputHash: insertionInputHash4844,
            batchSize: uint32(identityCommitments.length),
            startIndex: startIndex
        });

        // Mock blobhash. This is valid for the next call only.
        prepareBlobhash(kzgToVersionedHash(kzgCommitment));
        bytes memory callData = abi.encodeCall(ManagerImplV3.registerIdentities4844, params);

        bytes memory expectedError = abi.encodeWithSelector(
            ManagerImplV1.NotLatestRoot.selector, actualRoot, uint256(currentPreRoot)
        );

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Tests that runs of zeroes are accepted by the `registerIdentities4844` function as valid
    ///         arrays of identity commitments.
    function testRegisterIdentitiesWithRunsOfZeroes(uint8 identitiesLength, uint8 zeroPosition)
        public
    {
        // Setup
        vm.assume(identitiesLength != 0 && identitiesLength <= 1000);
        vm.assume(zeroPosition < identitiesLength && zeroPosition > 0);
        uint256[] memory identities = new uint256[](identitiesLength);
        (insertVerifiers, deletionVerifiers, updateVerifiers, insertVerifiers4844) =
            makeVerifierLookupTables(TC.makeDynArray([identitiesLength]));
        makeNewIdentityManager(
            treeDepth,
            initialRoot,
            insertVerifiers,
            insertVerifiers4844,
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

        ManagerImplV3.RegisterIdentities4844Params memory params = ManagerImplV3
            .RegisterIdentities4844Params({
            insertionProof: [uint256(2), 1, 3, 4, 5, 6, 7, 9],
            commitments: commitments,
            commitmentPok: commitmentsPok,
            kzgCommitment: kzgCommitment,
            kzgProof: kzgProof,
            expectedEvaluation: insertionExpectedEvaluation,
            preRoot: initialRoot,
            postRoot: insertionPostRoot,
            inputHash: insertionInputHash4844,
            batchSize: uint32(identities.length),
            startIndex: startIndex
        });

        // Mock blobhash. This is valid for the next call only.
        prepareBlobhash(kzgToVersionedHash(kzgCommitment));
        bytes memory callData = abi.encodeCall(ManagerImplV3.registerIdentities4844, params);

        // Test
        assertCallSucceedsOn(identityManagerAddress, callData, new bytes(0));
    }

    /// @notice Tests that identities can only be registered through the proxy.
    function testCannotRegisterIdentitiesIfNotViaProxy() public {
        // Setup
        address expectedOwner = managerImplV3.owner();
        vm.expectRevert("Function must be called through delegatecall");
        vm.prank(expectedOwner);

        // Test
        ManagerImplV3.RegisterIdentities4844Params memory params = ManagerImplV3
            .RegisterIdentities4844Params({
            insertionProof: insertionProof,
            commitments: commitments,
            commitmentPok: commitmentsPok,
            kzgCommitment: kzgCommitment,
            kzgProof: kzgProof,
            expectedEvaluation: insertionExpectedEvaluation,
            preRoot: initialRoot,
            postRoot: insertionPostRoot,
            inputHash: insertionInputHash4844,
            batchSize: uint32(identityCommitments.length),
            startIndex: startIndex
        });

        managerImplV3.registerIdentities4844(params);
    }

    /// @notice Checks that the transaction fails if KZG proof cannot be verified.
    function testRegisterIdentitiesWithBadKzgProof() public {
        // Setup
        ITreeVerifier actualVerifier = new TreeVerifier();
        (insertVerifiers, deletionVerifiers, updateVerifiers, insertVerifiers4844) =
            makeVerifierLookupTables(TC.makeDynArray([40]));
        insertVerifiers4844.addVerifier(identityCommitmentsSize, actualVerifier);
        makeNewIdentityManager(
            treeDepth,
            insertionPreRoot,
            insertVerifiers,
            insertVerifiers4844,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );

        ManagerImplV3.RegisterIdentities4844Params memory params = ManagerImplV3
            .RegisterIdentities4844Params({
            insertionProof: insertionProof4844,
            commitments: commitments,
            commitmentPok: commitmentsPok,
            kzgCommitment: kzgCommitment,
            kzgProof: kzgCommitment, // Intentionally pass something that's not the KZG proof
            expectedEvaluation: insertionExpectedEvaluation,
            preRoot: insertionPreRoot,
            postRoot: insertionPostRoot4844,
            inputHash: insertionInputHash4844,
            batchSize: uint32(identityCommitmentsSize),
            startIndex: startIndex
        });

        // Mock blobhash. This is valid for the next call only.
        prepareBlobhash(kzgToVersionedHash(kzgCommitment));

        bytes memory registerCallData = abi.encodeCall(ManagerImplV3.registerIdentities4844, params);

        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImplV3.KzgProofVerificationFailed.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, registerCallData, expectedError);
    }

    /// @notice Checks that the transaction fails if KZG commitment does not match the rest of KZG-related input.
    function testRegisterIdentitiesWithBadKzgCommitment() public {
        // Setup
        ITreeVerifier actualVerifier = new TreeVerifier();
        (insertVerifiers, deletionVerifiers, updateVerifiers, insertVerifiers4844) =
            makeVerifierLookupTables(TC.makeDynArray([40]));
        insertVerifiers4844.addVerifier(identityCommitmentsSize, actualVerifier);
        makeNewIdentityManager(
            treeDepth,
            insertionPreRoot,
            insertVerifiers,
            insertVerifiers4844,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );

        ManagerImplV3.RegisterIdentities4844Params memory params = ManagerImplV3
            .RegisterIdentities4844Params({
            insertionProof: insertionProof4844,
            commitments: commitments,
            commitmentPok: commitmentsPok,
            kzgCommitment: kzgProof, // Intentionally pass something that's not the KZG commitment
            kzgProof: kzgProof,
            expectedEvaluation: insertionExpectedEvaluation,
            preRoot: insertionPreRoot,
            postRoot: insertionPostRoot4844,
            inputHash: insertionInputHash4844,
            batchSize: uint32(identityCommitmentsSize),
            startIndex: startIndex
        });

        // Mock blobhash. This is valid for the next call only.
        prepareBlobhash(kzgToVersionedHash(kzgCommitment));

        bytes memory registerCallData = abi.encodeCall(ManagerImplV3.registerIdentities4844, params);

        bytes memory expectedError =
            abi.encodeWithSelector(ManagerImplV3.KzgProofVerificationFailed.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, registerCallData, expectedError);
    }
}
