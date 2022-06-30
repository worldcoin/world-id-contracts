// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import { Vm } from 'forge-std/Vm.sol';
import { Test } from 'forge-std/Test.sol';

import { Semaphore } from '../Semaphore.sol';

contract SemaphoreTest is Test {
    Semaphore internal semaphore;
    Vm internal hevm = Vm(HEVM_ADDRESS);
    uint256 updatedRoot = uint256(15544942873243012709540684980060519338171669902328326108400346498057157852487);
    uint256 identityCommitment = 123;

    event MemberAdded(uint256 indexed groupId, uint256 identityCommitment, uint256 root, uint256 leafIndex);
    event GroupCreated(uint256 indexed groupId, uint8 depth, uint256 zeroValue);

    function setUp() public {
        semaphore = new Semaphore();

        hevm.label(address(this), 'Sender');
        hevm.label(address(semaphore), 'Semaphore');
    }

    function testCannotUpdateWithoutManagerAccess(address user) public {
        hevm.assume(user != address(this));
        hevm.startPrank(user);

        hevm.expectRevert(Semaphore.Unauthorized.selector);
        semaphore.createGroup(1, 20);

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

    function testCanCreateGroup() public {
        uint256 groupId = 0;
        uint8 depth = 20;

        hevm.expectEmit(true, false, false, true);
        emit GroupCreated(groupId, depth, 0);

        semaphore.createGroup(groupId, depth);
    }

    function testAddMemberEvent() public {
        uint256 groupId = 1;
        uint256 leafIndex = uint256(0);

        semaphore.createGroup(groupId, 20);

        hevm.expectEmit(true, false, false, true);
        emit MemberAdded(groupId, leafIndex, identityCommitment, updatedRoot);

        semaphore.addMember(groupId, identityCommitment);
    }

    function testCanUpdateLatestRoots() public {
        uint256 groupId = 2;

        semaphore.createGroup(groupId, 20);
        semaphore.addMember(groupId, identityCommitment);

        assertEq(semaphore.latestRoots(groupId), updatedRoot);
    }

    function testCheckLatestRootsNeverExpire() public {
        uint256 groupId = 3;
        uint256 latestRoot = uint256(3994783695359171940075887118805985611479098781999381159167665757376630615738);

        semaphore.createGroup(groupId, 20);
        // the updatedRoot should expire
        semaphore.addMember(groupId, identityCommitment);
        semaphore.addMember(groupId, identityCommitment);

        // approx ~1hr
        skip(3620);

        assertTrue(semaphore.checkValidRoot(groupId, latestRoot));

        hevm.expectRevert(Semaphore.ExpiredRoot.selector);
        semaphore.checkValidRoot(groupId, updatedRoot);
    }

    // TODO: test that the latest root's proof can always be verified
    // function testVerifyProofWithLatestRoot()

    function testRevertForInvalidCommitment() public {
        uint256 groupId = 1;
        semaphore.createGroup(groupId, 20);

        hevm.expectRevert(Semaphore.InvalidCommitment.selector);
        semaphore.addMember(groupId, uint256(0));
    }

    function testRevetForNonExistentRoots() public {
        uint256 groupId = 1;
        semaphore.createGroup(groupId, 20);

        hevm.expectRevert(Semaphore.NonExistentRoot.selector);
        semaphore.checkValidRoot(groupId, updatedRoot);

        hevm.expectRevert(Semaphore.NonExistentRoot.selector);
        semaphore.checkValidRoot(0, updatedRoot);

        // Test empty root for a given group
        hevm.expectRevert(Semaphore.NonExistentRoot.selector);
        semaphore.checkValidRoot(groupId, 0);
    }
}
