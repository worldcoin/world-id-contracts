// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {VerifierLookupTableTest} from "./VerifierLookupTableTest.sol";

import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

/// @title Verifier Lookup Table Construction Tests
/// @notice Contains tests for the batch lookup table.
/// @author Worldcoin
contract BatchLookupTableConstruction is VerifierLookupTableTest {
    /// @notice Tests that it is possible to properly construct and initialise a router.
    function testCanConstructLookupTable(uint256 batchSize) public {
        // Setup
        vm.assume(batchSize <= 1000);

        // Test
        lookupTable = new VerifierLookupTable(batchSize, defaultVerifier);
    }

    /// @notice Tests that it is not possible to construct a lookup table using an invalid initial
    ///         batch size.
    function testCannotConstructLookupTableWithInvalidBatchSize(uint256 batchSize) public {
        // Setup
        uint256 maxBatchSize = lookupTable.maximumBatchSize();
        vm.assume(batchSize > maxBatchSize);
        bytes memory expectedError =
            abi.encodeWithSelector(VerifierLookupTable.BatchTooLarge.selector, batchSize);
        vm.expectRevert(expectedError);

        // Test
        lookupTable = new VerifierLookupTable(batchSize, defaultVerifier);
    }
}
