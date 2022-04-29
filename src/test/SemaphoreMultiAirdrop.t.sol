// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import { Vm } from 'forge-std/Vm.sol';
import { DSTest } from 'ds-test/test.sol';
import { Semaphore } from '../Semaphore.sol';
import { TestERC20, ERC20 } from './mock/TestERC20.sol';
import { TypeConverter } from './utils/TypeConverter.sol';
import { SemaphoreMultiAirdrop } from '../SemaphoreMultiAirdrop.sol';

contract User {}

contract SemaphoreMultiAirdropTest is DSTest {
    using TypeConverter for address;

    event AirdropClaimed(uint256 indexed airdropId, address receiver);
    event AirdropCreated(uint256 airdropId, SemaphoreMultiAirdrop.Airdrop airdrop);
    event AirdropUpdated(uint256 indexed airdropId, SemaphoreMultiAirdrop.Airdrop airdrop);

    User internal user;
    uint256 internal groupId;
    TestERC20 internal token;
    Semaphore internal semaphore;
    SemaphoreMultiAirdrop internal airdrop;
    Vm internal hevm = Vm(HEVM_ADDRESS);

    function setUp() public {
        groupId = 1;
        user = new User();
        token = new TestERC20();
        semaphore = new Semaphore();
        airdrop = new SemaphoreMultiAirdrop(semaphore);

        hevm.label(address(this), 'Sender');
        hevm.label(address(user), 'Holder');
        hevm.label(address(token), 'Token');
        hevm.label(address(semaphore), 'Semaphore');
        hevm.label(address(airdrop), 'SemaphoreMultiAirdrop');

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
        ffiArgs[2] = 'src/test/scripts/generate-proof-multiple.js';
        ffiArgs[3] = address(airdrop).toString();
        ffiArgs[4] = address(this).toString();

        bytes memory returnData = hevm.ffi(ffiArgs);

        return abi.decode(returnData, (uint256, uint256[8]));
    }

    function testCanCreateAirdrop() public {
        hevm.expectEmit(false, false, false, true);
        emit AirdropCreated(1, SemaphoreMultiAirdrop.Airdrop({
            groupId: groupId,
            token: token,
            manager: address(this),
            holder: address(user),
            amount: 1 ether
        }));
        airdrop.createAirdrop(groupId, token, address(user), 1 ether);

        (uint256 _groupId, ERC20 _token, address manager, address _holder, uint256 amount) = airdrop.getAirdrop(1);

        assertEq(_groupId, groupId);
        assertEq(address(_token), address(token));
        assertEq(manager, address(this));
        assertEq(_holder, address(user));
        assertEq(amount, 1 ether);
    }

    function testCanClaim() public {
        assertEq(token.balanceOf(address(this)), 0);

        airdrop.createAirdrop(groupId, token, address(user), 1 ether);
        semaphore.createGroup(groupId, 20, 0);
        semaphore.addMember(groupId, genIdentityCommitment());

        (uint256 nullifierHash, uint256[8] memory proof) = genProof();
        uint256 root = semaphore.getRoot(groupId);

        hevm.expectEmit(true, false, false, true);
        emit AirdropClaimed(1, address(this));
        airdrop.claim(1, address(this), root, nullifierHash, proof);

        assertEq(token.balanceOf(address(this)), 1 ether);
    }

    function testCannotClaimNonExistantAirdrop() public {
        assertEq(token.balanceOf(address(this)), 0);

        semaphore.createGroup(groupId, 20, 0);
        semaphore.addMember(groupId, genIdentityCommitment());

        (uint256 nullifierHash, uint256[8] memory proof) = genProof();
        uint256 root = semaphore.getRoot(groupId);

        hevm.expectRevert(SemaphoreMultiAirdrop.InvalidAirdrop.selector);
        airdrop.claim(1, address(this), root, nullifierHash, proof);

        assertEq(token.balanceOf(address(this)), 0);
    }

    function testCanClaimAfterNewMemberAdded() public {
        assertEq(token.balanceOf(address(this)), 0);

        airdrop.createAirdrop(groupId, token, address(user), 1 ether);
        semaphore.createGroup(groupId, 20, 0);
        semaphore.addMember(groupId, genIdentityCommitment());
        uint256 root = semaphore.getRoot(groupId);
        semaphore.addMember(groupId, 1);

        (uint256 nullifierHash, uint256[8] memory proof) = genProof();
        airdrop.claim(1, address(this), root, nullifierHash, proof);

        assertEq(token.balanceOf(address(this)), 1 ether);
    }

    function testCannotClaimHoursAfterNewMemberAdded() public {
        assertEq(token.balanceOf(address(this)), 0);

        airdrop.createAirdrop(groupId, token, address(user), 1 ether);
        semaphore.createGroup(groupId, 20, 0);
        semaphore.addMember(groupId, genIdentityCommitment());
        uint256 root = semaphore.getRoot(groupId);
        semaphore.addMember(groupId, 1);

        hevm.warp(block.timestamp + 2 hours);

        (uint256 nullifierHash, uint256[8] memory proof) = genProof();
        hevm.expectRevert(Semaphore.InvalidRoot.selector);
        airdrop.claim(1, address(this), root, nullifierHash, proof);

        assertEq(token.balanceOf(address(this)), 0);
    }

    function testCannotDoubleClaim() public {
        assertEq(token.balanceOf(address(this)), 0);

        airdrop.createAirdrop(groupId, token, address(user), 1 ether);
        semaphore.createGroup(groupId, 20, 0);
        semaphore.addMember(groupId, genIdentityCommitment());

        (uint256 nullifierHash, uint256[8] memory proof) = genProof();
        airdrop.claim(1, address(this), semaphore.getRoot(groupId), nullifierHash, proof);

        assertEq(token.balanceOf(address(this)), 1 ether);

        uint256 root = semaphore.getRoot(groupId);
        hevm.expectRevert(SemaphoreMultiAirdrop.InvalidNullifier.selector);
        airdrop.claim(1, address(this), root, nullifierHash, proof);

        assertEq(token.balanceOf(address(this)), 1 ether);
    }

    function testCannotClaimIfNotMember() public {
        assertEq(token.balanceOf(address(this)), 0);

        airdrop.createAirdrop(groupId, token, address(user), 1 ether);
        semaphore.createGroup(groupId, 20, 0);
        semaphore.addMember(groupId, 1);

        uint256 root = semaphore.getRoot(groupId);
        (uint256 nullifierHash, uint256[8] memory proof) = genProof();

        hevm.expectRevert(abi.encodeWithSignature('InvalidProof()'));
        airdrop.claim(1, address(this), root, nullifierHash, proof);

        assertEq(token.balanceOf(address(this)), 0);
    }

    function testCannotClaimWithInvalidSignal() public {
        assertEq(token.balanceOf(address(this)), 0);

        airdrop.createAirdrop(groupId, token, address(user), 1 ether);
        semaphore.createGroup(groupId, 20, 0);
        semaphore.addMember(groupId, genIdentityCommitment());

        (uint256 nullifierHash, uint256[8] memory proof) = genProof();

        uint256 root = semaphore.getRoot(groupId);
        hevm.expectRevert(abi.encodeWithSignature('InvalidProof()'));
        airdrop.claim(1, address(user), root, nullifierHash, proof);

        assertEq(token.balanceOf(address(this)), 0);
    }

    function testCannotClaimWithInvalidProof() public {
        assertEq(token.balanceOf(address(this)), 0);

        airdrop.createAirdrop(groupId, token, address(user), 1 ether);
        semaphore.createGroup(groupId, 20, 0);
        semaphore.addMember(groupId, genIdentityCommitment());

        (uint256 nullifierHash, uint256[8] memory proof) = genProof();
        proof[0] ^= 42;

        uint256 root = semaphore.getRoot(groupId);
        hevm.expectRevert(abi.encodeWithSignature('InvalidProof()'));
        airdrop.claim(1, address(this), root, nullifierHash, proof);

        assertEq(token.balanceOf(address(this)), 0);
    }

    function testCanUpdateAirdropDetails() public {
        airdrop.createAirdrop(groupId, token, address(user), 1 ether);

        (uint256 oldGroupId, ERC20 oldToken, address oldManager, address oldHolder, uint256 oldAmount) = airdrop.getAirdrop(1);

        assertEq(oldGroupId, groupId);
        assertEq(address(oldToken), address(token));
        assertEq(oldManager, address(this));
        assertEq(oldHolder, address(user));
        assertEq(oldAmount, 1 ether);

        SemaphoreMultiAirdrop.Airdrop memory newDetails = SemaphoreMultiAirdrop.Airdrop({
            groupId: groupId + 1,
            token: token,
            manager: address(user),
            holder: address(this),
            amount: 2 ether
        });

        hevm.expectEmit(true, false, false, true);
        emit AirdropUpdated(1, newDetails);
        airdrop.updateDetails(1, newDetails);

        (uint256 _groupId, ERC20 _token, address manager, address _holder, uint256 amount) = airdrop.getAirdrop(1);

        assertEq(_groupId, newDetails.groupId);
        assertEq(address(_token), address(newDetails.token));
        assertEq(manager, newDetails.manager);
        assertEq(_holder, newDetails.holder);
        assertEq(amount, newDetails.amount);
    }

    function testNonOwnerCannotUpdateAirdropDetails() public {
        airdrop.createAirdrop(groupId, token, address(user), 1 ether);

        (uint256 oldGroupId, ERC20 oldToken, address oldManager, address oldHolder, uint256 oldAmount) = airdrop.getAirdrop(1);

        assertEq(oldGroupId, groupId);
        assertEq(address(oldToken), address(token));
        assertEq(oldManager, address(this));
        assertEq(oldHolder, address(user));
        assertEq(oldAmount, 1 ether);

        hevm.prank(address(user));
        hevm.expectRevert(SemaphoreMultiAirdrop.Unauthorized.selector);
        airdrop.updateDetails(1, SemaphoreMultiAirdrop.Airdrop({
            groupId: groupId + 1,
            token: token,
            manager: address(user),
            holder: address(this),
            amount: 2 ether
        }));

        (uint256 _groupId, ERC20 _token, address manager, address _holder, uint256 amount) = airdrop.getAirdrop(1);

        assertEq(_groupId, groupId);
        assertEq(address(_token), address(token));
        assertEq(manager, address(this));
        assertEq(_holder, address(user));
        assertEq(amount, 1 ether);
    }
}
