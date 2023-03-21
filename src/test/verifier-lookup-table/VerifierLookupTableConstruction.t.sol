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
        // Test
        lookupTable = new VerifierLookupTable(batchSize, defaultVerifier);
    }
}
