// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {ERC20} from "solmate/tokens/ERC20.sol";
import {ISemaphore} from "./interfaces/ISemaphore.sol";

contract SemaphoreAirdrop {
    error InvalidProof();

    ISemaphore internal immutable semaphore;
    bytes32 internal immutable groupId;
    ERC20 public immutable token;
    address public immutable holder;
    uint256 public immutable airdropAmount;

    constructor(
        ISemaphore _semaphore,
        bytes32 _groupId,
        ERC20 _token,
        address _holder,
        uint256 _airdropAmount
    ) payable {
        semaphore = _semaphore;
        groupId = _groupId;
        token = _token;
        holder = _holder;
        airdropAmount = _airdropAmount;
    }

    function claim(
        address receiver,
        uint256 nullifierHash,
        uint256[8] calldata proof
    ) public {
        if (
            !semaphore._isValidProof(
                receiver,
                semaphore.getRoot(groupId),
                nullifierHash,
                address(this),
                proof
            )
        ) revert InvalidProof();

        semaphore._saveNullifierHash(nullifierHash);

        token.transferFrom(holder, receiver, airdropAmount);
    }
}
