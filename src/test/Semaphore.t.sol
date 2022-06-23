// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import { Vm } from 'forge-std/Vm.sol';
import 'forge-std/console.sol';

import { DSTest } from 'ds-test/test.sol';
import { Semaphore } from '../Semaphore.sol';

contract SemaphoreTest is DSTest {
    Semaphore internal semaphore;
    Vm internal hevm = Vm(HEVM_ADDRESS);

    event MemberAdded(uint256 indexed groupId, uint256 identityCommitment, uint256 root, uint256 leafIndex);

    function setUp() public {
        semaphore = new Semaphore();

        hevm.label(address(this), 'Sender');
        hevm.label(address(semaphore), 'Semaphore');
    }

    function testCannotUpdateWithoutManagerAccess(address user) public {
        hevm.assume(user != address(this));
        hevm.startPrank(user);

        hevm.expectRevert(Semaphore.Unauthorized.selector);
        semaphore.createGroup(1, 20, 0);

        hevm.expectRevert(Semaphore.Unauthorized.selector);
        semaphore.addMember(1, 0);

        uint8[] memory proofPath;
        uint256[] memory proofSiblings;
        hevm.expectRevert(Semaphore.Unauthorized.selector);
        semaphore.removeMember(1, 0, proofSiblings, proofPath);

        hevm.expectRevert(Semaphore.Unauthorized.selector);
        semaphore.transferAccess(address(this));
    }

    function testCanUpdateManager(address user) public {
        assertEq(semaphore.manager(), address(this));

        semaphore.transferAccess(user);

        assertEq(semaphore.manager(), user);
    }

    function testAddMemberEvent() public {
        uint256 groupId = 1;
        uint256 identityCommitment = 123;
        uint256 updatedRoot = uint256(15544942873243012709540684980060519338171669902328326108400346498057157852487);
        uint256 updatedLeaves = uint256(1);

        semaphore.createGroup(groupId, 20, 0);

        hevm.expectEmit(true, false, false, true);
        emit MemberAdded(groupId, identityCommitment, updatedRoot, updatedLeaves);

        semaphore.addMember(groupId, identityCommitment);
    }
}
