// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IBridge} from "../../interfaces/IBridge.sol";
import {IWorldID} from "../../interfaces/IWorldID.sol";

/// @title State Bridge Mock
/// @notice This purely exists to allow tests to compile and does not have any functionality.
/// @author Worldcoin
/// @notice A dumb bridge to make it easy to fuzz test successes and failures.
contract SimpleStateBridge is IBridge, IWorldID {
    event StateRootSentMultichain(uint256 indexed root);
    event SetRootHistoryExpiry(uint256 expiryTime);

    function sendRootMultichain(uint256 root) external virtual override {
        emit StateRootSentMultichain(root);
    }

    function setRootHistoryExpiry(uint256 expiryTime) external virtual override {
        emit SetRootHistoryExpiry(expiryTime);
    }

    error ProofNotVerified();

    function verifyProof(uint256, uint256, uint256, uint256, uint256[8] calldata proof)
        external
        pure
    {
        if (proof[0] % 2 != 0) {
            revert ProofNotVerified();
        }
    }
}
