// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import { Vm } from 'forge-std/Vm.sol';
import { DSTest } from 'ds-test/test.sol';
import { Semaphore } from '../Semaphore.sol';

contract SemaphoreTest is DSTest {
    Semaphore internal semaphore;
    Vm internal hevm = Vm(HEVM_ADDRESS);

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
}
