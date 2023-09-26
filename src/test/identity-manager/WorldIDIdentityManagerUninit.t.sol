// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";

import {CheckInitialized} from "../../utils/CheckInitialized.sol";
import {SemaphoreVerifier} from "semaphore/base/SemaphoreVerifier.sol";
import {TypeConverter as TC} from "../utils/TypeConverter.sol";
import {Verifier as TreeVerifier} from "src/InsertionTreeVerifier.sol";
import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

import {WorldIDIdentityManagerImplV2 as ManagerImpl} from "../../WorldIDIdentityManagerImplV2.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImplV1} from "../../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Uninit Tests
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerUninit is WorldIDIdentityManagerTest {
    /// @notice Checks that it is impossible to call `registerIdentities` while the contract is not
    ///         initialised.
    function testShouldNotCallRegisterIdentitiesWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(
            ManagerImplV1.registerIdentities,
            (insertionProof, insertionPreRoot, startIndex, identityCommitments, insertionPostRoot)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `deleteIdentities` while the contract is not
    ///         initialised.
    function testShouldNotCallDeleteIdentitiesWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
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
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `calculateIdentityRegistrationInputHash` while
    ///         the contract is not initialised.
    function testShouldNotCallCalculateIdentityRegistrationInputHash() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(
            ManagerImplV1.calculateIdentityRegistrationInputHash,
            (startIndex, insertionPreRoot, insertionPostRoot, identityCommitments)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `latestRoot` while the contract is not
    ///         initialised.
    function testShouldNotCallLatestRootWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(ManagerImplV1.latestRoot, ());
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `queryRoot` while the contract is not
    ///         initialised.
    function testShouldNotCallQueryRootWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(ManagerImplV1.queryRoot, (insertionPreRoot));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `checkValidRoot` while the contract is not
    ///         initialised.
    function testShouldNotCallRequireValidRootWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(ManagerImplV1.requireValidRoot, (insertionPreRoot));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `getRegisterIdentitiesVerifierLookupTableAddress`
    ///         while the contract is not initialized.
    function testShouldNotCallGetRegisterIdentitiesVerifierLookupTableAddressWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData =
            abi.encodeCall(ManagerImplV1.getRegisterIdentitiesVerifierLookupTableAddress, ());
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `setRegisterIdentitiesVerifierLookupTable`
    ///         while the contract is not initialized.
    function testShouldNotCallSetRegisterIdentitiesVerifierLookupTableWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        (VerifierLookupTable insertVerifiers,,) = makeVerifierLookupTables(TC.makeDynArray([75]));
        bytes memory callData = abi.encodeCall(
            ManagerImplV1.setRegisterIdentitiesVerifierLookupTable, (insertVerifiers)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `getDeleteIdentitiesVerifierLookupTableAddress`
    ///         while the contract is not initialized.
    function testShouldNotCallGetDeleteIdentitiesVerifierLookupTableAddressWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData =
            abi.encodeCall(ManagerImpl.getDeleteIdentitiesVerifierLookupTableAddress, ());
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `setDeleteIdentitiesVerifierLookupTable`
    ///         while the contract is not initialized.
    function testShouldNotCallSetDeleteIdentitiesVerifierLookupTableWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        (, VerifierLookupTable deletionVerifiers,) = makeVerifierLookupTables(TC.makeDynArray([75]));
        bytes memory callData =
            abi.encodeCall(ManagerImpl.setDeleteIdentitiesVerifierLookupTable, (deletionVerifiers));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `getSemaphoreVerifierAddress` while the
    ///         contract is not initialized.
    function testShouldNotCallGetSemaphoreVerifierAddressWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(ManagerImplV1.getSemaphoreVerifierAddress, ());
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `setSemaphoreVerifier` while the contract is
    ///         not initialized.
    function testShouldNotCallSetSemaphoreVerifierWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        SemaphoreVerifier newVerifier = new SemaphoreVerifier();
        bytes memory callData = abi.encodeCall(ManagerImplV1.setSemaphoreVerifier, (newVerifier));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `getRootHistoryExpiry` while the contract is
    ///         not initialized.
    function testShouldNotCallGetRootHistoryExpiryWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(ManagerImplV1.getRootHistoryExpiry, ());
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `setRootHistoryExpiry` while the contract is
    ///         not initialized.
    function testShouldNotCallSetRootHistoryExpiryWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(ManagerImplV1.setRootHistoryExpiry, (2 hours));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `identityOperator` while the contract is not
    ///         initialized.
    function testShouldNotCallIdentityOperatorWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(ManagerImplV1.identityOperator, ());
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `setIdentityOperator` while the contract is not
    ///         initialized.
    function testShouldNotCallSetIdentityOperatorWhileUninit(address newOperator) public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(ManagerImplV1.setIdentityOperator, (newOperator));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }
}
