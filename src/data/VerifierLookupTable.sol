// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Ownable} from "openzeppelin-contracts/access/Ownable.sol";

import {ITreeVerifier} from "../interfaces/ITreeVerifier.sol";

/// @title Batch Lookup Table
/// @author Worldcoin
/// @notice A table that provides the correct tree verifier based on the provided batch size.
/// @dev It should be used to query the correct verifier before using that verifier for verifying a
///      tree modification proof.
contract VerifierLookupTable is Ownable {
    ////////////////////////////////////////////////////////////////////////////////
    ///                                   DATA                                   ///
    ////////////////////////////////////////////////////////////////////////////////

    /// The maximum size of a batch that will be used by the WorldID Identity Manager.
    uint256 internal constant MAXIMUM_BATCH_SIZE = 1000;

    /// The null address.
    address internal constant nullAddress = address(0x0);

    /// The null verifier.
    ITreeVerifier internal constant nullVerifier = ITreeVerifier(nullAddress);

    /// The lookup table for routing batches.
    ///
    /// As we expect to only have a few batch sizes per contract, a mapping is used due to its
    /// natively sparse storage.
    mapping(uint256 => ITreeVerifier) internal verifier_lut;

    ////////////////////////////////////////////////////////////////////////////////
    ///                                  ERRORS                                  ///
    ////////////////////////////////////////////////////////////////////////////////

    /// @notice Raised if a too large batch is inserted or requested.
    ///
    /// @param requestedBatch The size of the batch that was requested.
    error BatchTooLarge(uint256 requestedBatch);

    /// @notice Raised if a batch size is requested that the lookup table doesn't know about.
    error NoSuchVerifier();

    /// @notice Raised if an attempt is made to add a verifier for a batch size that already exists.
    error VerifierExists();

    ////////////////////////////////////////////////////////////////////////////////
    ///                               CONSTRUCTION                               ///
    ////////////////////////////////////////////////////////////////////////////////

    /// @notice Constructs a new batch lookup table.
    ///
    /// @param initialBatchSize The size of the initial batch (the size of the batch in
    ///        `initialVerifier`).
    /// @param initialVerifier The verifier for batches of size `initialBatchSize`.
    ///
    /// @custom:reverts BatchTooLarge If the `initialBatchSize` exceeds the maximum batch size.
    constructor(uint256 initialBatchSize, ITreeVerifier initialVerifier) Ownable() {
        addVerifier(initialBatchSize, initialVerifier);
    }

    ////////////////////////////////////////////////////////////////////////////////
    ///                                ACCESSORS                                 ///
    ////////////////////////////////////////////////////////////////////////////////

    /// @notice Obtains the verifier for the provided `batchSize`.
    ///
    /// @param batchSize The batch size to get the associated verifier for.
    ///
    /// @return verifier The tree verifier for the provided `batchSize`.
    ///
    /// @custom:reverts BatchTooLarge If `batchSize` exceeds the maximum batch size.
    /// @custom:reverts NoSuchVerifier If there is no verifier associated with the `batchSize`.
    function getVerifierFor(uint256 batchSize) public view returns (ITreeVerifier verifier) {
        // Check the preconditions for querying the verifier.
        validateVerifier(batchSize);

        // With the preconditions checked, we can return the verifier.
        verifier = verifier_lut[batchSize];
    }

    /// @notice Adds a verifier for the provided `batchSize`.
    ///
    /// @param batchSize The batch size to add the verifier for.
    /// @param verifier The verifier for a batch of size `batchSize`.
    ///
    /// @custom:reverts VerifierExists If `batchSize` already has an associated verifier.
    /// @custom:reverts BatchTooLarge If `batchSize` exceeds the maximum batch size.
    /// @custom:reverts string If the caller is not the owner.
    function addVerifier(uint256 batchSize, ITreeVerifier verifier) public onlyOwner {
        // Ensure that the batch size is within bounds.
        validateBatchSize(batchSize);

        // Check that there is no entry for that batch size.
        if (verifier_lut[batchSize] != nullVerifier) {
            revert VerifierExists();
        }

        // Add the verifier.
        updateVerifier(batchSize, verifier);
    }

    /// @notice Updates the verifier for the provided `batchSize`.
    ///
    /// @param batchSize The batch size to add the verifier for.
    /// @param verifier The verifier for a batch of size `batchSize`.
    ///
    /// @return oldVerifier The old verifier instance associated with this batch size.
    ///
    /// @custom:reverts BatchTooLarge If `batchSize` exceeds the maximum batch size.
    /// @custom:reverts string If the caller is not the owner.
    function updateVerifier(uint256 batchSize, ITreeVerifier verifier)
        public
        onlyOwner
        returns (ITreeVerifier oldVerifier)
    {
        // Ensure that the batch size is within bounds.
        validateBatchSize(batchSize);

        // Set the verifier in the table.
        oldVerifier = verifier_lut[batchSize];
        verifier_lut[batchSize] = verifier;
    }

    /// @notice Disables the verifier for the provided batch size.
    ///
    /// @param batchSize The batch size to disable the verifier for.
    ///
    /// @return oldVerifier The old verifier associated with the batch size.
    ///
    /// @custom:reverts BatchTooLarge If `batchSize` exceeds the maximum batch size.
    /// @custom:reverts string If the caller is not the owner.
    function disableVerifier(uint256 batchSize)
        public
        onlyOwner
        returns (ITreeVerifier oldVerifier)
    {
        return updateVerifier(batchSize, ITreeVerifier(nullAddress));
    }

    /// @notice Gets the maximum batch size supported by this lookup table.
    ///
    /// @return batchSize The maximum batch size.
    function maximumBatchSize() public pure returns (uint256 batchSize) {
        return MAXIMUM_BATCH_SIZE;
    }

    ////////////////////////////////////////////////////////////////////////////////
    ///                          INTERNAL FUNCTIONALITY                          ///
    ////////////////////////////////////////////////////////////////////////////////

    /// @notice Checks if the batch size is valid.
    ///
    /// @param batchSize The batch size to check.
    ///
    /// @custom:reverts BatchTooLarge If `batchSize` exceeds the maximum batch size.
    function validateBatchSize(uint256 batchSize) internal pure {
        if (batchSize > MAXIMUM_BATCH_SIZE) {
            revert BatchTooLarge(batchSize);
        }
    }

    /// @notice Checks if the entry for the provided `batchSize` is a valid verifier.
    ///
    /// @param batchSize The batch size to check.
    ///
    /// @custom:reverts NoSuchVerifier If `batchSize` does not have an associated verifier.
    /// @custom:reverts BatchTooLarge If `batchSize` exceeds the maximum batch size.
    function validateVerifier(uint256 batchSize) internal view {
        validateBatchSize(batchSize);

        if (verifier_lut[batchSize] == nullVerifier) {
            revert NoSuchVerifier();
        }
    }
}
