// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";

/// @title Sequencer Verifier
/// @author Worldcoin
/// @notice A verifier that matches the success conditions used by the mock prover service in the
///         signup sequencer.
contract SequencerVerifier is ITreeVerifier {
    uint256 internal constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function verifyProof(uint256[8] calldata proof, uint256[1] calldata input) external pure {
        require(proof[0] % 2 == 0 && proof[1] % SNARK_SCALAR_FIELD == input[0], "Invalid Proof");
    }
}
