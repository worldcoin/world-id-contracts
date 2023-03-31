// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {WorldIDTest} from "../WorldIDTest.sol";

import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";
import {ISemaphoreVerifier} from "semaphore/interfaces/ISemaphoreVerifier.sol";
import {IBridge} from "../../interfaces/IBridge.sol";

import {SimpleStateBridge} from "../mock/SimpleStateBridge.sol";
import {SimpleVerifier, SimpleVerify} from "../mock/SimpleVerifier.sol";
import {UnimplementedTreeVerifier} from "../../utils/UnimplementedTreeVerifier.sol";
import {SemaphoreVerifier} from "semaphore/base/SemaphoreVerifier.sol";
import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

import {WorldIDIdentityManager as IdentityManager} from "../../WorldIDIdentityManager.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImpl} from "../../WorldIDIdentityManagerImplV1.sol";

/// @title World ID Identity Manager Test.
/// @notice Contains tests for the WorldID identity manager.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract WorldIDIdentityManagerTest is WorldIDTest {
    ///////////////////////////////////////////////////////////////////////////////
    ///                                TEST DATA                                ///
    ///////////////////////////////////////////////////////////////////////////////

    IdentityManager internal identityManager;
    ManagerImpl internal managerImpl;

    ITreeVerifier internal treeVerifier;
    uint256 internal initialRoot = 0x0;
    uint8 internal treeDepth = 16;

    address internal identityManagerAddress;
    address internal managerImplAddress;

    uint256 internal slotCounter = 0;

    // All hardcoded test data taken from `src/test/data/TestParams.json`. This will be dynamically
    // generated at some point in the future.
    bytes32 internal constant inputHash =
        0x7d7f77c56064e1f8577de14bba99eff85599ab0e76d0caeadd1ad61674b8a9c3;
    uint32 internal constant startIndex = 0;
    uint256 internal constant preRoot =
        0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238;
    uint256 internal constant postRoot =
        0x5c1e52b41a571293b30efacd2afdb7173b20cfaf1f646c4ac9f96eb75848270;
    uint256[] identityCommitments;
    uint256 identityCommitmentsSize = 3;
    uint256[8] proof;

    // Needed for testing things.
    uint256 internal constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // State bridge mock
    IBridge internal stateBridge;
    bool internal isStateBridgeEnabled = true;

    event StateRootSentMultichain(uint256 indexed root);

    // Mock Verifiers
    ITreeVerifier unimplementedVerifier = new UnimplementedTreeVerifier();
    SemaphoreVerifier semaphoreVerifier = new SemaphoreVerifier();

    // Verifiers
    uint256 initialBatchSize = 30;
    VerifierLookupTable internal defaultInsertVerifiers;
    VerifierLookupTable internal defaultUpdateVerifiers;

    ///////////////////////////////////////////////////////////////////////////////
    ///                            TEST ORCHESTRATION                           ///
    ///////////////////////////////////////////////////////////////////////////////

    constructor() {
        // Make the identity commitments.
        identityCommitments = new uint256[](identityCommitmentsSize);
        identityCommitments[0] = 0x1;
        identityCommitments[1] = 0x2;
        identityCommitments[2] = 0x3;

        // Create the proof term.
        proof = [
            0x2a45bf326884bbf13c821a5e4f30690a391156cccf80a2922fb24250111dd7eb,
            0x23a7376a159513e6d0e22d43fcdca9d0c8a5c54a73b59fce6962a41e71355894,
            0x21b9fc7c2d1f76c2e1a972b00f18728a57a34d7e4ae040811bf1626132ff3658,
            0x2a7c3c660190a33ab92cd84e4b2540e49ea80bdc766eb3aeec49806a78071c75,
            0x2fc9a52a7f4bcc29faab28a8d8ec126b4fe604a7b41e7d2b3efe92422951d706,
            0x110740f0b21fb329de682dffc95a5ede11c11c6328606fe254b6ba469b15f68,
            0x23115ff1573808639f19724479b195b7894a45c9868242ad2a416767359c6c78,
            0x23f3fa30273c7f38e360496e7f9790450096d4a9592e1fe6e0a996cb05b8fb28
        ];
    }

    /// @notice This function runs before every single test.
    /// @dev It is run before every single iteration of a property-based fuzzing test.
    function setUp() public {
        treeVerifier = new SimpleVerifier(initialBatchSize);
        defaultInsertVerifiers = new VerifierLookupTable();
        defaultInsertVerifiers.addVerifier(initialBatchSize, treeVerifier);
        defaultUpdateVerifiers = new VerifierLookupTable();
        defaultUpdateVerifiers.addVerifier(initialBatchSize, treeVerifier);
        stateBridge = new SimpleStateBridge();
        stateBridge = IBridge(stateBridge);
        makeNewIdentityManager(
            treeDepth,
            initialRoot,
            defaultInsertVerifiers,
            defaultUpdateVerifiers,
            semaphoreVerifier,
            isStateBridgeEnabled,
            stateBridge
        );

        hevm.label(address(this), "Sender");
        hevm.label(identityManagerAddress, "IdentityManager");
        hevm.label(managerImplAddress, "ManagerImplementation");
        hevm.label(address(stateBridge), "StateBridge");
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                              TEST UTILITIES                             ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Initialises a new identity manager using the provided information.
    /// @dev It is initialised in the globals.
    ///
    /// @param actualPreRoot The pre-root to use.
    /// @param insertVerifiers The insertion verifier lookup table.
    /// @param updateVerifiers The udpate verifier lookup table.
    /// @param actualSemaphoreVerifier The Semaphore verifier instance to use.
    /// @param enableStateBridge Whether or not the new identity manager should have the state
    ///        bridge enabled.
    /// @param actualStateBridge The current state bridge.
    function makeNewIdentityManager(
        uint8 actualTreeDepth,
        uint256 actualPreRoot,
        VerifierLookupTable insertVerifiers,
        VerifierLookupTable updateVerifiers,
        ISemaphoreVerifier actualSemaphoreVerifier,
        bool enableStateBridge,
        IBridge actualStateBridge
    ) public {
        managerImpl = new ManagerImpl();
        managerImplAddress = address(managerImpl);

        bytes memory initCallData = abi.encodeCall(
            ManagerImpl.initialize,
            (
                actualTreeDepth,
                actualPreRoot,
                insertVerifiers,
                updateVerifiers,
                actualSemaphoreVerifier,
                enableStateBridge,
                actualStateBridge
            )
        );

        identityManager = new IdentityManager(managerImplAddress, initCallData);
        identityManagerAddress = address(identityManager);
    }

    /// @notice Initialises a new identity manager using the provided information.
    /// @dev It is initialised in the globals.
    ///
    /// @param actualPreRoot The pre-root to use.
    /// @param enableStateBridge Whether or not the new identity manager should have the state
    ///        bridge enabled.
    /// @param actualStateBridge The current state bridge.
    /// @param batchSizes The batch sizes to create verifiers for. Verifiers will be created for
    ///        both insertions and updates. Must be non-empty.
    ///
    /// @custom:reverts string If any batch size exceeds 1000.
    /// @custom:reverts string If `batchSizes` is empty.
    function makeNewIdentityManager(
        uint256 actualPreRoot,
        bool enableStateBridge,
        IBridge actualStateBridge,
        uint256[] calldata batchSizes
    ) public {
        (VerifierLookupTable insertVerifiers, VerifierLookupTable updateVerifiers) =
            makeVerifierLookupTables(batchSizes);
        defaultInsertVerifiers = insertVerifiers;
        defaultUpdateVerifiers = updateVerifiers;

        // Now we can build the identity manager as usual.
        makeNewIdentityManager(
            treeDepth,
            actualPreRoot,
            insertVerifiers,
            updateVerifiers,
            semaphoreVerifier,
            enableStateBridge,
            actualStateBridge
        );
    }

    /// @notice Constructs new verifier lookup tables from the provided `batchSizes`.
    ///
    /// @param batchSizes The batch sizes to create verifiers for. Verifiers will be created for
    ///        both insertions and updates. Must be non-empty and contain no duplicates.
    ///
    /// @return insertVerifiers The insertion verifier lookup table.
    /// @return updateVerifiers The update verifier lookup table.
    ///
    /// @custom:reverts VerifierExists If `batchSizes` contains a duplicate.
    /// @custom:reverts string If any batch size exceeds 1000.
    /// @custom:reverts string If `batchSizes` is empty.
    function makeVerifierLookupTables(uint256[] memory batchSizes)
        public
        returns (VerifierLookupTable insertVerifiers, VerifierLookupTable updateVerifiers)
    {
        // Construct the verifier LUTs from the provided `batchSizes` info.
        if (batchSizes.length == 0) {
            revert("batchSizes must be non-empty.");
        }
        if (batchSizes[0] > 1000) {
            revert("batch size greater than 1000.");
        }
        ITreeVerifier initialVerifier = new SimpleVerifier(batchSizes[0]);
        insertVerifiers = new VerifierLookupTable();
        updateVerifiers = new VerifierLookupTable();
        for (uint256 i = 0; i < batchSizes.length; ++i) {
            uint256 batchSize = batchSizes[i];
            if (batchSize > 1000) {
                revert("batch size greater than 1000.");
            }

            ITreeVerifier batchVerifier = new SimpleVerifier(batchSize);
            insertVerifiers.addVerifier(batchSize, batchVerifier);
            updateVerifiers.addVerifier(batchSize, batchVerifier);
        }
    }

    /// @notice Creates a new identity manager without initializing the delegate.
    /// @dev It is constructed in the globals.
    function makeUninitIdentityManager() public {
        managerImpl = new ManagerImpl();
        managerImplAddress = address(managerImpl);
        identityManager = new IdentityManager(managerImplAddress, new bytes(0x0));
        identityManagerAddress = address(identityManager);
    }

    /// @notice Moves through the slots in the identity commitments array _without_ resetting
    ///         between runs.
    function rotateSlot() public returns (uint256) {
        uint256 currentSlot = slotCounter;
        slotCounter = (slotCounter + 1) % (identityCommitments.length - 1);
        return currentSlot;
    }

    /// @notice Shallow clones an array.
    ///
    /// @param arr The array to clone.
    ///
    /// @return out The clone of `arr`.
    function cloneArray(uint256[] memory arr) public pure returns (uint256[] memory out) {
        out = new uint256[](arr.length);
        for (uint256 i = 0; i < arr.length; ++i) {
            out[i] = arr[i];
        }
        return out;
    }

    /// @notice Prepares a verifier test case.
    /// @dev This is useful to make property-based fuzz testing work better by requiring less
    ///      constraints on the generated input.
    ///
    /// @param idents The generated identity commitments to convert.
    /// @param prf The generated proof terms to convert.
    ///
    /// @return preparedIdents The conversion of `idents` to the proper type.
    /// @return actualProof The conversion of `prf` to the proper type.
    function prepareInsertIdentitiesTestCase(uint128[] memory idents, uint128[8] memory prf)
        public
        returns (uint256[] memory preparedIdents, uint256[8] memory actualProof)
    {
        for (uint256 i = 0; i < idents.length; ++i) {
            vm.assume(idents[i] != 0x0);
        }
        preparedIdents = new uint256[](idents.length);
        for (uint256 i = 0; i < idents.length; ++i) {
            preparedIdents[i] = uint256(idents[i]);
        }

        actualProof = [uint256(prf[0]), prf[1], prf[2], prf[3], prf[4], prf[5], prf[6], prf[7]];
    }

    /// @notice Prepares a verifier test case.
    /// @dev This is useful to make property-based fuzz testing work better by requiring less
    ///      constraints on the generated input.
    ///
    /// @param idents The generated identity commitments to convert.
    /// @param prf The generate proof terms to convert.
    ///
    /// @return leafIndices The leaf indices for the updates.
    /// @return oldIdents The conversion of `idents` to the proper type.
    /// @return newIdents The conversion of `idents` to the proper type.
    /// @return actualProof The conversion of `prf` to the proper type.
    function prepareUpdateIdentitiesTestCase(uint128[] memory idents, uint128[8] memory prf)
        public
        pure
        returns (
            uint32[] memory leafIndices,
            uint256[] memory oldIdents,
            uint256[] memory newIdents,
            uint256[8] memory actualProof
        )
    {
        uint256 length = idents.length;
        leafIndices = new uint32[](length);
        oldIdents = new uint256[](length);
        newIdents = new uint256[](length);
        for (uint256 i = 0; i < idents.length; ++i) {
            leafIndices[i] = uint32(idents[i] % 1024);
            oldIdents[i] = idents[i];

            if (idents[i] != type(uint256).min) {
                newIdents[i] = idents[i] - 1;
            } else {
                newIdents[i] = idents[i] + 1;
            }
        }

        actualProof = [uint256(prf[0]), prf[1], prf[2], prf[3], prf[4], prf[5], prf[6], prf[7]];
    }
}
