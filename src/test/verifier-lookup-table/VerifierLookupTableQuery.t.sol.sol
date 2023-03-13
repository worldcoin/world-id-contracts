// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {VerifierLookupTableTest} from "./VerifierLookupTableTest.sol";

import {VerifierLookupTable} from "../../data/VerifierLookupTable.sol";

import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";
import {SimpleVerifier} from "../mock/SimpleVerifier.sol";

/// @title Verifier Lookup Table Query Tests
/// @notice Contains tests for the batch lookup table.
/// @author Worldcoin
contract VerifierLookupTableQuery is VerifierLookupTableTest {
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
        vm.assume(batchSize <= lookupTable.maximumBatchSize() && batchSize != defaultBatchSize);
        vm.expectRevert(abi.encodeWithSelector(VerifierLookupTable.NoSuchVerifier.selector));

        // Test
        lookupTable.getVerifierFor(batchSize);
    }

    /// @notice Ensures that it reverts when queried for a
    function testCanotGetVerifierForInvalidBatchSize(uint256 batchSize) public {
        // Setup
        vm.assume(batchSize > lookupTable.maximumBatchSize() && batchSize != defaultBatchSize);
        vm.expectRevert(
            abi.encodeWithSelector(VerifierLookupTable.BatchTooLarge.selector, batchSize)
        );

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
        vm.assume(batchSize != defaultBatchSize && batchSize <= lookupTable.maximumBatchSize());
        vm.assume(newVerifier != nullVerifier);

        // Test
        lookupTable.addVerifier(batchSize, newVerifier);
        ITreeVerifier result = lookupTable.getVerifierFor(batchSize);
        assertEq(address(result), address(newVerifier));
    }

    /// @notice Ensures that the lookup table will not add a verifier with an invalid batch size.
    function testCannotAddVerifierWithInvalidBatchSize(uint256 batchSize) public {
        // Setup
        vm.assume(batchSize > lookupTable.maximumBatchSize());
        vm.expectRevert(
            abi.encodeWithSelector(VerifierLookupTable.BatchTooLarge.selector, batchSize)
        );

        // Test
        lookupTable.addVerifier(batchSize, defaultVerifier);
    }

    /// @notice Ensures that you cannot inadvertently overwrite an existing verifier.
    function testCannotAddVerifierForBatchSizeThatAlreadyExists(uint256 batchSize) public {
        // Setup
        vm.assume(batchSize <= lookupTable.maximumBatchSize());
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

        // Test
        lookupTable.updateVerifier(defaultBatchSize, newVerifier);
        ITreeVerifier result = lookupTable.getVerifierFor(defaultBatchSize);
        assertEq(address(result), address(newVerifier));
    }

    /// @notice Ensures that verifiers cannot be updated if the batch size is invalid.
    function testCannotUpdateVerifierIfBatchSizeTooLarge(
        uint256 batchSize,
        ITreeVerifier newVerifier
    ) public {
        // Setup
        vm.assume(batchSize > lookupTable.maximumBatchSize());
        vm.assume(newVerifier != defaultVerifier);
        vm.expectRevert(
            abi.encodeWithSelector(VerifierLookupTable.BatchTooLarge.selector, batchSize)
        );

        // Test
        lookupTable.updateVerifier(batchSize, newVerifier);
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
        vm.assume(batchSize <= lookupTable.maximumBatchSize());
        if (batchSize != defaultBatchSize) {
            lookupTable.addVerifier(batchSize, defaultVerifier);
        }

        // Test
        lookupTable.disableVerifier(batchSize);
        vm.expectRevert(abi.encodeWithSelector(VerifierLookupTable.NoSuchVerifier.selector));
        lookupTable.getVerifierFor(batchSize);
    }

    /// @notice Ensures that the contract reverts if requested to disable a verifier for an invalid
    ///         batch size.
    function testCannotDisableVerifierForInvalidBatchSize(uint256 batchSize) public {
        // Setup
        vm.assume(batchSize > lookupTable.maximumBatchSize());
        vm.expectRevert(
            abi.encodeWithSelector(VerifierLookupTable.BatchTooLarge.selector, batchSize)
        );

        // Test
        lookupTable.disableVerifier(batchSize);
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

    ////////////////////////////////////////////////////////////////////////////////
    ///                            BASIC DATA QUERY                              ///
    ////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures that it is possible to query the maximum batch size no matter who you are.
    function testCanAlwaysGetMaximumBatchSize(address caller) public {
        // Setup
        vm.prank(caller);

        // Test
        assertEq(lookupTable.maximumBatchSize(), 1000);
    }
}
