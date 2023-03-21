// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {WorldIDIdentityManagerTest} from "./WorldIDIdentityManagerTest.sol";

import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";

import {CheckInitialized} from "../../utils/CheckInitialized.sol";
import {SemaphoreVerifier} from "semaphore/base/SemaphoreVerifier.sol";
import {TypeConverter as TC} from "../utils/TypeConverter.sol";
import {Verifier as TreeVerifier} from "../mock/TreeVerifier.sol";
import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

import {WorldIDIdentityManagerImplV1 as ManagerImpl} from "../../WorldIDIdentityManagerImplV1.sol";

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
            ManagerImpl.registerIdentities,
            (proof, preRoot, startIndex, identityCommitments, postRoot)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `updateIdentities` while the contract is not
    ///         initialised.
    function testShouldNotCallUpdateIdentitiesWhileUninit(
        uint128[] memory identities,
        uint128[8] memory prf
    ) public {
        // Setup
        makeUninitIdentityManager();
        (ManagerImpl.IdentityUpdate[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareUpdateIdentitiesTestCase(identities, prf);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.updateIdentities, (actualProof, initialRoot, preparedIdents, postRoot)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `removeIdentities` while the contract is not
    ///         initialised.
    function testShouldNotCallRemoveIdentitiesWhileUninit(
        uint128[] memory identities,
        uint128[8] memory prf
    ) public {
        // Setup
        makeUninitIdentityManager();
        (ManagerImpl.IdentityUpdate[] memory preparedIdents, uint256[8] memory actualProof) =
            prepareRemoveIdentitiesTestCase(identities, prf);
        bytes memory callData = abi.encodeCall(
            ManagerImpl.removeIdentities, (actualProof, initialRoot, preparedIdents, postRoot)
        );
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `calculateTreeVerifierInputHash` while the
    ///         contract is not initialised.
    function testShouldNotCallCalculateInputHash() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(
            ManagerImpl.calculateIdentityRegistrationInputHash,
            (startIndex, preRoot, postRoot, identityCommitments)
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
        bytes memory callData = abi.encodeCall(ManagerImpl.latestRoot, ());
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
        bytes memory callData = abi.encodeCall(ManagerImpl.queryRoot, (preRoot));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `isInputInReducedForm` while the contract is
    ///         not initialised.
    function testShouldNotCallIsInputInReducedFormWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(ManagerImpl.isInputInReducedForm, (preRoot));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `checkValidRoot` while the contract is not
    ///         initialised.
    function testShouldNotCallCheckValidRootWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData = abi.encodeCall(ManagerImpl.checkValidRoot, (preRoot));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `getRegisterIdentitiesVerifierLookupTableAddress`
    ///         while the contract is not initialized.
    function testShouldNotCallgetRegisterIdentitiesVerifierLookupTableAddressWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData =
            abi.encodeCall(ManagerImpl.getRegisterIdentitiesVerifierLookupTableAddress, ());
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
        (VerifierLookupTable insertVerifiers,) = makeVerifierLookupTables(TC.makeDynArray([75]));
        bytes memory callData =
            abi.encodeCall(ManagerImpl.setRegisterIdentitiesVerifierLookupTable, (insertVerifiers));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `getIdentityUpdateVerifierLookupTableAddress`
    ///         while the contract is not initialized.
    function testShouldNotCallGetIdentityUpdateVerifierLookupTableAddressWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        bytes memory callData =
            abi.encodeCall(ManagerImpl.getIdentityUpdateVerifierLookupTableAddress, ());
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }

    /// @notice Checks that it is impossible to call `setIdentityUpdateVerifierLookupTable` while
    ///         the contract is not initialized.
    function testShouldNotCallSetIdentityUpdateVerifierLookupTableWhileUninit() public {
        // Setup
        makeUninitIdentityManager();
        (, VerifierLookupTable updateVerifiers) = makeVerifierLookupTables(TC.makeDynArray([75]));
        bytes memory callData =
            abi.encodeCall(ManagerImpl.setIdentityUpdateVerifierLookupTable, (updateVerifiers));
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
        bytes memory callData = abi.encodeCall(ManagerImpl.getSemaphoreVerifierAddress, ());
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
        bytes memory callData = abi.encodeCall(ManagerImpl.setSemaphoreVerifier, (newVerifier));
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
        bytes memory callData = abi.encodeCall(ManagerImpl.getRootHistoryExpiry, ());
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
        bytes memory callData = abi.encodeCall(ManagerImpl.setRootHistoryExpiry, (2 hours));
        bytes memory expectedError =
            abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        // Test
        assertCallFailsOn(identityManagerAddress, callData, expectedError);
    }
}
