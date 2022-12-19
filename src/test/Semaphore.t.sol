// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {Vm} from "forge-std/Vm.sol";
import {Test} from "forge-std/Test.sol";

import {Semaphore} from "../Semaphore.sol";

contract SemaphoreTest is Test {
    Semaphore internal semaphore;
    Vm internal hevm = Vm(HEVM_ADDRESS);

    function setUp() public {
        semaphore = new Semaphore();

        hevm.label(address(this), "Sender");
        hevm.label(address(semaphore), "Semaphore");
    }

    /// @notice Tests whether we can correctly calculate the `inputHash` to the merkle tree verifier.
    function testCalculateInputHashFromParameters() public {
        // Taken from `test/data/TestParams.json`
        uint32 startIndex = uint32(0);
        uint256 preRoot = 0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238;
        uint256 postRoot = 0x1a9893c0cc548bb2d45c6dfb683f89ce7a9e9a3eea7a687ae165cadcf5019e8c;
        uint256[] memory identityCommitments = new uint256[](3);
        identityCommitments[0] = 0x0;
        identityCommitments[1] = 0x1;
        identityCommitments[2] = 0x2;

        // Also taken from the same place.
        bytes32 expectedHash = 0x331b273757fd0fb1958235cc1085c61d7aafe36fe17230e5888c94b0c9e65e69;

        // Our actual computation.
        bytes32 calculatedHash = semaphore.calculateTreeVerifierInputHash(
            startIndex, preRoot, postRoot, identityCommitments
        );

        assertEq(calculatedHash, expectedHash);
    }

    // TODO [Ara] Tests are currently not testing any useful functionality so
    // have been removed. Need to add new tests once the current functionality
    // is updated.
}
