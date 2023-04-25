// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {VerifierLookupTableTest} from "./VerifierLookupTableTest.sol";

import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

/// @title Verifier Lookup Table Construction Tests
/// @notice Contains tests for the verifier lookup table.
/// @author Worldcoin
contract VerifierLookupTableConstruction is VerifierLookupTableTest {
    /// @notice Tests that it is possible to properly construct and initialise a router.
    function testCanConstructLookupTable() public {
        // Test
        lookupTable = new VerifierLookupTable();
    }
}
