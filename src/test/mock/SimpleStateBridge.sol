// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import {IBridge} from "../../interfaces/IBridge.sol";

/// @title State Bridge Mock
/// @notice This purely exists to allow tests to compile and does not have any functionality.
/// @author Worldcoin
/// @notice A dumb bridge to make it easy to fuzz test successes and failures.
contract SimpleStateBridge is IBridge {
    event StateRootSentMultichain(uint256 indexed root);

    function sendRootMultichain(uint256 root) external virtual override {
        emit StateRootSentMultichain(root);
    }
}
