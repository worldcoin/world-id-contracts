// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import { Vm } from 'forge-std/Vm.sol';
import { DSTest } from 'ds-test/test.sol';
import { Semaphore } from '../Semaphore.sol';
import { TestERC20 } from './mock/TestERC20.sol';
import { TypeConverter } from './utils/TypeConverter.sol';
import { SemaphoreAirdrop } from '../SemaphoreAirdrop.sol';

contract User {}

contract SemaphoreAirdropTest is DSTest {
    using TypeConverter for address;

    event AmountUpdated(uint256 amount);

    User internal user;
    uint256 internal groupId;
    TestERC20 internal token;
    Semaphore internal semaphore;
    SemaphoreAirdrop internal airdrop;
    Vm internal hevm = Vm(HEVM_ADDRESS);

    function setUp() public {
        groupId = 1;
        user = new User();
        token = new TestERC20();
        semaphore = new Semaphore();
        airdrop = new SemaphoreAirdrop(semaphore, groupId, token, address(user), 1 ether);

        hevm.label(address(this), 'Sender');
        hevm.label(address(user), 'Holder');
        hevm.label(address(token), 'Token');
        hevm.label(address(semaphore), 'Semaphore');
        hevm.label(address(airdrop), 'SemaphoreAirdrop');

        // Issue some tokens to the user address, to be airdropped from the contract
        token.issue(address(user), 10 ether);

        // Approve spending from the airdrop contract
        hevm.prank(address(user));
        token.approve(address(airdrop), type(uint256).max);
    }

    function genIdentityCommitment() internal returns (uint256) {
        string[] memory ffiArgs = new string[](2);
        ffiArgs[0] = 'node';
        ffiArgs[1] = 'src/test/scripts/generate-commitment.js';

        bytes memory returnData = hevm.ffi(ffiArgs);
        return abi.decode(returnData, (uint256));
    }

    function genProof() internal returns (uint256, uint256[8] memory proof) {
        string[] memory ffiArgs = new string[](5);
        ffiArgs[0] = 'node';
        ffiArgs[1] = '--no-warnings';
        ffiArgs[2] = 'src/test/scripts/generate-proof.js';
        ffiArgs[3] = address(airdrop).toString();
        ffiArgs[4] = address(this).toString();

        bytes memory returnData = hevm.ffi(ffiArgs);

        return abi.decode(returnData, (uint256, uint256[8]));
    }

    function testCanClaim() public {
        assertEq(token.balanceOf(address(this)), 0);

        semaphore.createGroup(groupId, 20, 0);
        semaphore.addMember(groupId, genIdentityCommitment());

        (uint256 nullifierHash, uint256[8] memory proof) = genProof();
        airdrop.claim(address(this), semaphore.getRoot(groupId), nullifierHash, proof);

        assertEq(token.balanceOf(address(this)), airdrop.airdropAmount());
    }

    function testCanClaimAfterNewMemberAdded() public {
        assertEq(token.balanceOf(address(this)), 0);

        semaphore.createGroup(groupId, 20, 0);
        semaphore.addMember(groupId, genIdentityCommitment());
        uint256 root = semaphore.getRoot(groupId);
        semaphore.addMember(groupId, 1);

        (uint256 nullifierHash, uint256[8] memory proof) = genProof();
        airdrop.claim(address(this), root, nullifierHash, proof);

        assertEq(token.balanceOf(address(this)), airdrop.airdropAmount());
    }

    function testCannotClaimHoursAfterNewMemberAdded() public {
        assertEq(token.balanceOf(address(this)), 0);

        semaphore.createGroup(groupId, 20, 0);
        semaphore.addMember(groupId, genIdentityCommitment());
        uint256 root = semaphore.getRoot(groupId);
        semaphore.addMember(groupId, 1);

        hevm.warp(block.timestamp + 2 hours);

        (uint256 nullifierHash, uint256[8] memory proof) = genProof();
        hevm.expectRevert(Semaphore.InvalidRoot.selector);
        airdrop.claim(address(this), root, nullifierHash, proof);

        assertEq(token.balanceOf(address(this)), 0);
    }

    function testCannotDoubleClaim() public {
        assertEq(token.balanceOf(address(this)), 0);

        semaphore.createGroup(groupId, 20, 0);
        semaphore.addMember(groupId, genIdentityCommitment());

        (uint256 nullifierHash, uint256[8] memory proof) = genProof();
        airdrop.claim(address(this), semaphore.getRoot(groupId), nullifierHash, proof);

        assertEq(token.balanceOf(address(this)), airdrop.airdropAmount());

        uint256 root = semaphore.getRoot(groupId);
        hevm.expectRevert(SemaphoreAirdrop.InvalidNullifier.selector);
        airdrop.claim(address(this), root, nullifierHash, proof);

        assertEq(token.balanceOf(address(this)), airdrop.airdropAmount());
    }

    function testCannotClaimIfNotMember() public {
        assertEq(token.balanceOf(address(this)), 0);

        semaphore.createGroup(groupId, 20, 0);
        semaphore.addMember(groupId, 1);

        uint256 root = semaphore.getRoot(groupId);
        (uint256 nullifierHash, uint256[8] memory proof) = genProof();

        hevm.expectRevert(abi.encodeWithSignature('InvalidProof()'));
        airdrop.claim(address(this), root, nullifierHash, proof);

        assertEq(token.balanceOf(address(this)), 0);
    }

    function testCannotClaimWithInvalidSignal() public {
        assertEq(token.balanceOf(address(this)), 0);

        semaphore.createGroup(groupId, 20, 0);
        semaphore.addMember(groupId, genIdentityCommitment());

        (uint256 nullifierHash, uint256[8] memory proof) = genProof();

        uint256 root = semaphore.getRoot(groupId);
        hevm.expectRevert(abi.encodeWithSignature('InvalidProof()'));
        airdrop.claim(address(user), root, nullifierHash, proof);

        assertEq(token.balanceOf(address(this)), 0);
    }

    function testCannotClaimWithInvalidProof() public {
        assertEq(token.balanceOf(address(this)), 0);

        semaphore.createGroup(groupId, 20, 0);
        semaphore.addMember(groupId, genIdentityCommitment());

        (uint256 nullifierHash, uint256[8] memory proof) = genProof();
        proof[0] ^= 42;

        uint256 root = semaphore.getRoot(groupId);
        hevm.expectRevert(abi.encodeWithSignature('InvalidProof()'));
        airdrop.claim(address(this), root, nullifierHash, proof);

        assertEq(token.balanceOf(address(this)), 0);
    }

    function testUpdateAirdropAmount() public {
        assertEq(airdrop.airdropAmount(), 1 ether);

        hevm.expectEmit(false, false, false, true);
        emit AmountUpdated(2 ether);
        airdrop.updateAmount(2 ether);

        assertEq(airdrop.airdropAmount(), 2 ether);
    }

    function testCannotUpdateAirdropAmountIfNotManager() public {
        assertEq(airdrop.airdropAmount(), 1 ether);

        hevm.expectRevert(SemaphoreAirdrop.Unauthorized.selector);
        hevm.prank(address(user));
        airdrop.updateAmount(2 ether);

        assertEq(airdrop.airdropAmount(), 1 ether);
    }
}
