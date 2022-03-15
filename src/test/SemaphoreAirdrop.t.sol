// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {Vm} from "forge-std/Vm.sol";
import {DSTest} from "ds-test/test.sol";
import {Semaphore} from "./mock/Semaphore.sol";
import {TestERC20} from "./mock/TestERC20.sol";
import {SemaphoreAirdrop} from "../SemaphoreAirdrop.sol";

contract User {}

contract SemaphoreAirdropTest is DSTest {
    User internal user;
    TestERC20 internal token;
    Semaphore internal semaphore;
    SemaphoreAirdrop internal airdrop;
    Vm internal hevm = Vm(HEVM_ADDRESS);

    function setUp() public {
        user = new User();
        token = new TestERC20();
        semaphore = new Semaphore();
        airdrop = new SemaphoreAirdrop(
            semaphore,
            0,
            token,
            address(user),
            1 ether
        );

        hevm.startPrank(address(user));
        token.issue(address(user), 10 ether);
        token.approve(address(airdrop), type(uint256).max);
    }

    function testExample() public {
        assertTrue(true);
    }
}
