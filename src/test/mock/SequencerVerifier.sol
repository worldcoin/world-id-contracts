// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {ITreeVerifier} from "../../interfaces/ITreeVerifier.sol";

/// @title Sequencer Verifier
/// @author Worldcoin
/// @notice A verifier that matches the success conditions used by the mock prover service in the
///         signup sequencer.
contract SequencerVerifier is ITreeVerifier {
    uint256 internal constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[1] memory input
    ) external pure override returns (bool) {
        delete b;
        delete c;
        return a[0] % 2 == 0 && a[1] % SNARK_SCALAR_FIELD == input[0];
    }
}
