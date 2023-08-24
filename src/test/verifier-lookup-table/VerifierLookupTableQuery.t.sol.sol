// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {VerifierLookupTableTest} from "./VerifierLookupTableTest.sol";

import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";
import {SimpleVerifier} from "../mock/SimpleVerifier.sol";

/// @title Verifier Lookup Table Query Tests
/// @notice Contains tests for the verifier lookup table.
/// @author Worldcoin
contract VerifierLookupTableQuery is VerifierLookupTableTest {
    // Taken from VerifierLookupTable.sol
    event VerifierAdded(uint256 indexed batchSize, address indexed verifierAddress);
    event VerifierUpdated(
        uint256 indexed batchSize,
        address indexed oldVerifierAddress,
        address indexed newVerifierAddress
    );
    event VerifierDisabled(uint256 indexed batchSize);

    ////////////////////////////////////////////////////////////////////////////////
    ///                            VERIFIER QUERYING                             ///
    ////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures that it is possible to get a verifier for a batch size that exists.
    function testCanGetVerifierForExtantBatchSize() public {
        // Test
        address result = address(lookupTable.getVerifierFor(defaultBatchSize));
        assertEq(result, defaultVerifierAddress);
    }

    /// @notice Ensures that it reverts when queried for a missing batch size.
    function testCannotGetVerifierForMissingBatchSize(uint256 batchSize) public {
        // Setup
        vm.assume(batchSize != defaultBatchSize);
        vm.expectRevert(abi.encodeWithSelector(VerifierLookupTable.NoSuchVerifier.selector));

        // Test
        lookupTable.getVerifierFor(batchSize);
    }

    ////////////////////////////////////////////////////////////////////////////////
    ///                             VERIFIER ADDING                              ///
    ////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures that the lookup table can add new verifiers.
    function testCanAddVerifierWithValidBatchSize(uint256 batchSize, ITreeVerifier newVerifier)
        public
    {
        // Setup
        vm.assume(batchSize != defaultBatchSize);
        vm.assume(newVerifier != nullVerifier);
        vm.expectEmit(true, true, true, true);
        emit VerifierAdded(batchSize, address(newVerifier));

        // Test
        lookupTable.addVerifier(batchSize, newVerifier);
        ITreeVerifier result = lookupTable.getVerifierFor(batchSize);
        assertEq(address(result), address(newVerifier));
    }

    /// @notice Ensures that you cannot inadvertently overwrite an existing verifier.
    function testCannotAddVerifierForBatchSizeThatAlreadyExists(uint256 batchSize) public {
        // Setup
        if (batchSize != defaultBatchSize) {
            lookupTable.addVerifier(batchSize, defaultVerifier);
        }
        vm.expectRevert(abi.encodeWithSelector(VerifierLookupTable.VerifierExists.selector));

        // Test
        lookupTable.addVerifier(batchSize, defaultVerifier);
    }

    /// @notice Ensures that a verifier cannot be added except by the owner.
    function testCannotAddVerifierUnlessOwner(address naughty) public {
        // Setup
        vm.assume(naughty != thisAddress && naughty != nullAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        vm.prank(naughty);

        // Test
        lookupTable.addVerifier(10, defaultVerifier);
    }

    ////////////////////////////////////////////////////////////////////////////////
    ///                             VERIFIER UPDATE                              ///
    ////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures that verifiers can be updated if needed.
    function testCanUpdateVerifierWithValidBatchSize(ITreeVerifier newVerifier) public {
        // Setup
        vm.assume(newVerifier != defaultVerifier && newVerifier != nullVerifier);
        vm.expectEmit(true, true, true, true);
        emit VerifierUpdated(defaultBatchSize, defaultVerifierAddress, address(newVerifier));

        // Test
        lookupTable.updateVerifier(defaultBatchSize, newVerifier);
        ITreeVerifier result = lookupTable.getVerifierFor(defaultBatchSize);
        assertEq(address(result), address(newVerifier));
    }

    /// @notice Ensures that verifiers cannot be updated except by the owner.
    function testCannotUpdateVerifierIfNotOwner(address naughty) public {
        // Setup
        vm.assume(naughty != thisAddress && naughty != nullAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        vm.prank(naughty);

        // Test
        lookupTable.updateVerifier(defaultBatchSize, defaultVerifier);
    }

    ////////////////////////////////////////////////////////////////////////////////
    ///                            VERIFIER DISABLE                              ///
    ////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures that it is possible to disable the verifier.
    function testCanDisableVerifier(uint256 batchSize) public {
        // Setup
        if (batchSize != defaultBatchSize) {
            lookupTable.addVerifier(batchSize, defaultVerifier);
        }
        vm.expectEmit(true, true, true, true);
        emit VerifierDisabled(batchSize);

        // Test
        lookupTable.disableVerifier(batchSize);
        vm.expectRevert(abi.encodeWithSelector(VerifierLookupTable.NoSuchVerifier.selector));
        lookupTable.getVerifierFor(batchSize);
    }

    /// @notice Ensures that only the contract owner is able to disable verifiers.
    function testCannotDisableVerifierUnlessOwner(address naughty) public {
        // Setup
        vm.assume(naughty != thisAddress && naughty != nullAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        vm.prank(naughty);

        // Test
        lookupTable.disableVerifier(defaultBatchSize);
    }
}
