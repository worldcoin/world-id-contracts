// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {WorldIDTest} from "../WorldIDTest.sol";

import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";
import {SimpleVerifier} from "../mock/SimpleVerifier.sol";

contract VerifierLookupTableTest is WorldIDTest {
    ///////////////////////////////////////////////////////////////////////////////
    ///                                TEST DATA                                ///
    ///////////////////////////////////////////////////////////////////////////////

    VerifierLookupTable internal lookupTable;
    ITreeVerifier internal defaultVerifier;
    ITreeVerifier internal nullVerifier = ITreeVerifier(address(0x0));
    uint256 internal defaultBatchSize = 30;

    address lookupTableAddress;
    address defaultVerifierAddress;

    ///////////////////////////////////////////////////////////////////////////////
    ///                            TEST ORCHESTRATION                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice This function runs before every single test.
    /// @dev It is run before every single iteration of a property-based fuzzing test.
    function setUp() public {
        // Create a new lookup table every time.
        makeNewLUT(defaultBatchSize);

        // Label the addresses for better errors.
        vm.label(thisAddress, "Sender");
        vm.label(lookupTableAddress, "LUT");
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                              TEST UTILITIES                             ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Creates a new lookup table object.
    /// @dev Writes the newly constructed table to the global variables.
    ///
    /// @param initialBatchSize The first batch size. Must be less than `MAXIMUM_BATCH_SIZE`.
    function makeNewLUT(uint256 initialBatchSize) public {
        defaultVerifier = new SimpleVerifier(initialBatchSize);
        defaultVerifierAddress = address(defaultVerifier);

        lookupTable = new VerifierLookupTable();
        lookupTableAddress = address(lookupTable);
        lookupTable.addVerifier(initialBatchSize, defaultVerifier);
    }
}
