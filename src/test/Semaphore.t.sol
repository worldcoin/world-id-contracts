// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {Vm} from "forge-std/Vm.sol";
import {Test} from "forge-std/Test.sol";

import {Semaphore} from "../Semaphore.sol";

contract SemaphoreTest is Test {
    Semaphore internal semaphore;
    Vm internal hevm = Vm(HEVM_ADDRESS);
    uint256 updatedRoot = uint256(15544942873243012709540684980060519338171669902328326108400346498057157852487);
    uint256 identityCommitment = 123;

    event MemberAdded(uint256 indexed groupId, uint256 identityCommitment, uint256 root, uint256 leafIndex);
    event GroupCreated(uint256 indexed groupId, uint8 depth, uint256 zeroValue);

    function setUp() public {
        semaphore = new Semaphore();

        hevm.label(address(this), "Sender");
        hevm.label(address(semaphore), "Semaphore");
    }

    // TODO [Ara] Tests are currently not testing any useful functionality so 
    // have been removed. Need to add new tests once the current functionality
    // is updated.
}
