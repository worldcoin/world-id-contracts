// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {UUPSUpgradeable} from "contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {WorldIDTest} from "../WorldIDTest.sol";

import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";
import {ISemaphoreVerifier} from "src/interfaces/ISemaphoreVerifier.sol";
import {IBridge} from "../../interfaces/IBridge.sol";

import {SimpleStateBridge} from "../mock/SimpleStateBridge.sol";
import {SimpleVerifier, SimpleVerify} from "../mock/SimpleVerifier.sol";
import {UnimplementedTreeVerifier} from "../../utils/UnimplementedTreeVerifier.sol";
import {SemaphoreVerifier} from "src/SemaphoreVerifier.sol";
import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

import {WorldIDIdentityManager as IdentityManager} from "../../WorldIDIdentityManager.sol";
import {WorldIDIdentityManagerImplV1 as ManagerImplV1} from "../../WorldIDIdentityManagerImplV1.sol";
import {WorldIDIdentityManagerImplV2 as ManagerImplV2} from "../../WorldIDIdentityManagerImplV2.sol";

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
    // V2
    ManagerImplV2 internal managerImplV2;
    // V1
    ManagerImplV1 internal managerImplV1;

    ITreeVerifier internal treeVerifier;
    uint256 internal initialRoot = 0x0;
    uint8 internal treeDepth = 16;

    address internal identityManagerAddress;
    // V2
    address internal managerImplV2Address;
    // V1
    address internal managerImplV1Address;

    uint256 internal slotCounter = 0;

    ///////////////////////////////////////////////////////////////////
    ///                          INSERTION                          ///
    ///////////////////////////////////////////////////////////////////
    // All hardcoded test data taken from `src/test/data/TestInsertionParams.json`. This will be dynamically
    // generated at some point in the future.
    /// @dev generated using `./semaphore-mtb/gnark-mbu gen-test-params --mode insertion --tree-depth 16 --batch-size 3`
    bytes32 internal constant insertionInputHash =
        0x66f12f84870ce040647fb5f207b08f69676c8a7f6063dbe6b20de111183f2688;
    uint32 internal constant startIndex = 0;
    uint256 internal constant insertionPreRoot =
        0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323;
    uint256 internal constant insertionPostRoot =
        0x193289951bec3e4a099d9f1b0fb22cf20fe9dc4ea75c253352f22848b08c888b;

    uint256[] identityCommitments;
    uint256 identityCommitmentsSize = 3;
    uint256[8] insertionProof;

    ///////////////////////////////////////////////////////////////////
    ///                           DELETION                          ///
    ///////////////////////////////////////////////////////////////////
    // All hardcoded test data taken from `src/test/data/TestDeletionParams.json`. This will be dynamically
    // generated at some point in the future.
    /// @dev generated using semaphore-mtb: ./gnark-mbu gen-test-params --mode deletion --tree-depth 16 --batch-size 8
    bytes32 internal constant deletionInputHash =
        0x227590f99431e20f2f95fdfb1b7dfb648c04242c950c31263ba165647c96501a;
    uint256 internal constant deletionPreRoot =
        0x18cb13df3e79b9f847a1494d0a2e6f3cc0041d9cae7e5ccb8cd1852ecdc4af58;
    uint256 internal constant deletionPostRoot =
        0x82fcf94594d7363636338e2c29242cc77e3d04f36c8ad64d294d2ab4d251708;
    bytes packedDeletionIndices = abi.encodePacked(
        uint32(0), uint32(2), uint32(4), uint32(6), uint32(8), uint32(10), uint32(12), uint32(14)
    );
    uint32 deletionBatchSize = 8;
    uint256[8] deletionProof;

    ///////////////////////////////////////////////////////////////////
    ///                          INCLUSION                          ///
    ///////////////////////////////////////////////////////////////////
    /// @dev generated using https://github.com/worldcoin/semaphore-mock
    /// steps:
    /// 1. cargo run --release generate-identities --identities 10
    /// 2. cargo run --release prove-inclusion --identities out/random_identities.json --tree-depth 16 --identity-index 3
    /// @dev params from `src/test/data/InclusionProof.json` (output of step 2.)
    uint256 internal constant inclusionRoot =
        0xdf9f0cb5a3afe2129e349c1435bfbe9e6f091832fdfa7b739b61c5db2cbdde9;
    uint256 internal constant inclusionSignalHash =
        0xbc6bb462e38af7da48e0ae7b5cbae860141c04e5af2cf92328cd6548df111f;
    uint256 internal constant inclusionNullifierHash =
        0x2887375654a2f83868b277f3836678aa55475fd5c840b117913ea4a7c9ded6fc;
    uint256 internal constant inclusionExternalNullifierHash =
        0xfd3a1e9736c12a5d4a31f26362b577ccafbd523d358daf40cdc04d90e17f77;

    uint256[8] inclusionProof;

    // Needed for testing things.
    uint256 internal constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // Mock Verifiers
    ITreeVerifier unimplementedVerifier = new UnimplementedTreeVerifier();
    SemaphoreVerifier semaphoreVerifier = new SemaphoreVerifier();

    // Verifiers
    uint256 initialBatchSize = 30;
    VerifierLookupTable internal defaultInsertVerifiers;
    VerifierLookupTable internal defaultDeletionVerifiers;
    VerifierLookupTable internal defaultUpdateVerifiers;

    ///////////////////////////////////////////////////////////////////////////////
    ///                            TEST ORCHESTRATION                           ///
    ///////////////////////////////////////////////////////////////////////////////

    constructor() {
        // Make the identity commitments to be inserted.
        // needs to match the params in src/test/data/TestInsertionParams.json
        identityCommitments = new uint256[](identityCommitmentsSize);
        identityCommitments[0] = 0x1;
        identityCommitments[1] = 0x2;
        identityCommitments[2] = 0x3;

        // Create the insertion proof term.
        // output from semaphore-mtb prove in src/test/data/InsertionProof.json
        /// @dev test_insertion.ps is generated using semaphore-mtb: `./gnark-mbu setup --mode insertion --batch-size 3 --tree-depth 16 --output test_insertion.ps`
        /// @dev generated using semaphore-mtb: `./gnark-mbu gen-test-params --mode insertion --tree-depth 16 --batch-size 3 | ./gnark-mbu prove --mode insertion --keys-file test_insertion.ps`
        insertionProof = [
            0x18491e665bc7128f0113b3cf187502311cf5a82b0304e02464099782483b14ba,
            0x1dace8033bc22eda25b483b2a260195b67ee5bef07990bf0e2c5f7923423fe,
            0x1d4489b99a91a972e878bef7a147251c8d4941b415bb7b36a9740e714f995b7e,
            0x772049285800265c330a0850d30d32c1ece88a0aa6adbd6a6197d0a1c2e2de2,
            0x27afc608a28bd2f8743bc2b423dbc34829b374cf702789f9549d4b730fcc7ec8,
            0x1011cfd2347e8db6cd489a8090331a73db380b6774ec3bc14c77a2dabe0e83dd,
            0x2f5f37e84d6acff8cfd7988d33aaea072dbe5071093b2df022d23047f134ac45,
            0x24830332559eada283d4473b17091b239443e75e9e09f0ebce8e72c235ee665d
        ];

        // Create the deletion proof term.
        // output from semaphore-mtb prove in src/test/data/DeletionProof.json
        /// @dev test_deletion.ps is generated using semaphore-mtb: `./gnark-mbu setup --mode deletion --batch-size 8 --tree-depth 16 --output test_deletion.ps`
        /// @dev generated using semaphore-mtb: `./gnark-mbu gen-test-params --mode deletion --tree-depth 16 --batch-size 8 | ./gnark-mbu prove --mode deletion --keys-file test_deletion.ps`
        deletionProof = [
            0x19233cf0c60aa740585125dd5936462b1795bc2c8da7b9d0b7e92392cf91e1fd,
            0x244096da06de365f3bd8e7f428c2de4214096c4cd0feeba579642435ab15e90a,
            0x107395cd3aa9bfe3bcaada7f171d43a1ffffd576325598e2b9c8fbe1cfd6d032,
            0xac23f21fb0376055adeee2a78491ca13afc288c63c6450d0ce6ded6fda14344,
            0x29022f4cf64701ff88807430b9e333d87c670a4bdfe7d495d76271044a2d3711,
            0x134e41bef89e02289885852b368395b1b679dd243e5cf9e2f36b04ba990ab6a2,
            0x280894db66e6a9f9bf8aa48ffa1de98b755adadcf5962fb308cd1802a1101a0c,
            0x1484814b74243a07930c6af61079f94eefd843efe95e2388d9d49956cfacf3ab
        ];

        // Create the inclusion proof term.
        // output from semaphore-mtb prove in src/test/data/InclusionProof.json
        //
        /// @dev generated using https://github.com/worldcoin/semaphore-mock
        /// steps:
        /// 1. cargo run --release generate-identities --identities 10
        /// 2. cargo run --release prove-inclusion --identities out/random_identities.json --tree-depth 16 --identity-index 3
        inclusionProof = [
            0x27d70bdecb420a7322a0e44ef68345fc67e9903a3980762c23dfda5cf4d65715,
            0x1aba064ef272dd53b498d856c711890249a63a46825fe6d332fc5868ad854ef4,
            0x23a76f9777710f268d2092d859344cdc8d7f77abef35695f89d1ebf771d8a520,
            0x295ab87eb7c0ad9470ec2b56b35309f5e4576679ef6180ed78124e3f549f125d,
            0x1da63a007225659d3a70a2dfe807df5c3e8423bfd8e059d72909a1def161573f,
            0x2578db76ee9f64ff4eb0b532cb796dfa27d86ae8cd29e2d6b32f9428c71acb8b,
            0xd00d49d5db4c5b11a13aca379f5c3c627a6e8fc1c4470e7a56017307aca51a2,
            0xf6ee8db704ecb5c149e5a046a03e8767ba5a818c08320f6245070e4c0e99b77
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
        defaultDeletionVerifiers = new VerifierLookupTable();
        defaultDeletionVerifiers.addVerifier(initialBatchSize, treeVerifier);
        makeNewIdentityManager(
            treeDepth,
            initialRoot,
            defaultInsertVerifiers,
            defaultDeletionVerifiers,
            defaultUpdateVerifiers,
            semaphoreVerifier
        );

        hevm.label(address(this), "Sender");
        hevm.label(identityManagerAddress, "IdentityManager");
        hevm.label(managerImplV2Address, "ManagerImplementationV2");
        hevm.label(managerImplV1Address, "ManagerImplementationV1");
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
    function makeNewIdentityManager(
        uint8 actualTreeDepth,
        uint256 actualPreRoot,
        VerifierLookupTable insertVerifiers,
        VerifierLookupTable deletionVerifiers,
        VerifierLookupTable updateVerifiers,
        ISemaphoreVerifier actualSemaphoreVerifier
    ) public {
        managerImplV1 = new ManagerImplV1();
        managerImplV1Address = address(managerImplV1);

        bytes memory initCallData = abi.encodeCall(
            ManagerImplV1.initialize,
            (
                actualTreeDepth,
                actualPreRoot,
                insertVerifiers,
                updateVerifiers,
                actualSemaphoreVerifier
            )
        );

        identityManager = new IdentityManager(managerImplV1Address, initCallData);
        identityManagerAddress = address(identityManager);

        // creates Manager Impl V2, which will be used for tests
        managerImplV2 = new ManagerImplV2();
        managerImplV2Address = address(managerImplV2);

        bytes memory initCallV2 = abi.encodeCall(ManagerImplV2.initializeV2, (deletionVerifiers));
        bytes memory upgradeCall = abi.encodeCall(
            UUPSUpgradeable.upgradeToAndCall, (address(managerImplV2Address), initCallV2)
        );

        // Test
        assertCallSucceedsOn(identityManagerAddress, upgradeCall, new bytes(0x0));
    }

    /// @notice Initialises a new identity manager using the provided information.
    /// @dev It is initialised in the globals.
    ///
    /// @param actualPreRoot The pre-root to use.
    /// @param batchSizes The batch sizes to create verifiers for. Verifiers will be created for
    ///        both insertions and updates. Must be non-empty.
    ///
    /// @custom:reverts string If any batch size exceeds 1000.
    /// @custom:reverts string If `batchSizes` is empty.
    function makeNewIdentityManager(uint256 actualPreRoot, uint256[] calldata batchSizes) public {
        (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        ) = makeVerifierLookupTables(batchSizes);
        defaultInsertVerifiers = insertVerifiers;
        defaultDeletionVerifiers = deletionVerifiers;
        defaultUpdateVerifiers = updateVerifiers;

        // Now we can build the identity manager as usual.
        makeNewIdentityManager(
            treeDepth,
            actualPreRoot,
            insertVerifiers,
            deletionVerifiers,
            updateVerifiers,
            semaphoreVerifier
        );
    }

    /// @notice Constructs new verifier lookup tables from the provided `batchSizes`.
    ///
    /// @param batchSizes The batch sizes to create verifiers for. Verifiers will be created for
    ///        both insertions and updates. Must be non-empty and contain no duplicates.
    ///
    /// @return insertVerifiers The insertion verifier lookup table.
    /// @return deletionVerifiers The deletion verifier lookup table.
    /// @return updateVerifiers The update verifier lookup table.
    ///
    /// @custom:reverts VerifierExists If `batchSizes` contains a duplicate.
    /// @custom:reverts string If any batch size exceeds 1000.
    /// @custom:reverts string If `batchSizes` is empty.
    function makeVerifierLookupTables(uint256[] memory batchSizes)
        public
        returns (
            VerifierLookupTable insertVerifiers,
            VerifierLookupTable deletionVerifiers,
            VerifierLookupTable updateVerifiers
        )
    {
        // Construct the verifier LUTs from the provided `batchSizes` info.
        if (batchSizes.length == 0) {
            revert("batchSizes must be non-empty.");
        }
        if (batchSizes[0] > 1000) {
            revert("batch size greater than 1000.");
        }
        insertVerifiers = new VerifierLookupTable();
        deletionVerifiers = new VerifierLookupTable();
        updateVerifiers = new VerifierLookupTable();
        for (uint256 i = 0; i < batchSizes.length; ++i) {
            uint256 batchSize = batchSizes[i];
            if (batchSize > 1000) {
                revert("batch size greater than 1000.");
            }

            ITreeVerifier batchVerifier = new SimpleVerifier(batchSize);
            insertVerifiers.addVerifier(batchSize, batchVerifier);
            deletionVerifiers.addVerifier(batchSize, batchVerifier);
            updateVerifiers.addVerifier(batchSize, batchVerifier);
        }
    }

    /// @notice Creates a new identity manager without initializing the delegate.
    /// @dev It is constructed in the globals.
    function makeUninitIdentityManager() public {
        managerImplV2 = new ManagerImplV2();
        managerImplV2Address = address(managerImplV2);
        identityManager = new IdentityManager(managerImplV2Address, new bytes(0x0));
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
        pure
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
    /// @param prf The generated proof terms to convert.
    ///
    /// @return actualProof The conversion of `prf` to the proper type.
    function prepareDeleteIdentitiesTestCase(uint128[8] memory prf)
        public
        pure
        returns (uint256[8] memory actualProof)
    {
        actualProof = [uint256(prf[0]), prf[1], prf[2], prf[3], prf[4], prf[5], prf[6], prf[7]];
    }
}
