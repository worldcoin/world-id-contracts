// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import { ERC20 } from 'solmate/tokens/ERC20.sol';
import { ByteHasher } from './libraries/ByteHasher.sol';
import { ISemaphore } from './interfaces/ISemaphore.sol';
import { SafeTransferLib } from 'solmate/utils/SafeTransferLib.sol';

/// @title Semaphore Multiple Airdrop Manager
/// @author Miguel Piedrafita
/// @notice Template contract for managing multiple airdrops using Semaphore groups
contract SemaphoreMultiAirdrop {
    using ByteHasher for bytes;

    ///////////////////////////////////////////////////////////////////////////////
    ///                                  ERRORS                                ///
    //////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when trying to create or update airdrop details without being the manager
    error Unauthorized();

    /// @notice Thrown when attempting to reuse a nullifier
    error InvalidNullifier();

    /// @notice Thrown when attempting to claim a non-existant airdrop
    error InvalidAirdrop();

    ///////////////////////////////////////////////////////////////////////////////
    ///                                  EVENTS                                ///
    //////////////////////////////////////////////////////////////////////////////

    /// @notice Emitted when an airdrop is created
    /// @param airdropId The id of the airdrop
    /// @param airdrop The airdrop details
    event AirdropCreated(uint256 airdropId, Airdrop airdrop);

    /// @notice Emitted when an airdrop is successfully claimed
    /// @param receiver The address that received the airdrop
    event AirdropClaimed(uint256 indexed airdropId, address receiver);

    /// @notice Emitted when the airdropped amount is changed
    /// @param airdropId The id of the airdrop getting updated
    /// @param airdrop The new details for the airdrop
    event AirdropUpdated(uint256 indexed airdropId, Airdrop airdrop);

    ///////////////////////////////////////////////////////////////////////////////
    ///                                 STRUCTS                                ///
    //////////////////////////////////////////////////////////////////////////////

    /// @notice Stores the details for a specific airdrop
    /// @param groupId The ID of the Semaphore group that will be eligible to claim this airdrop
    /// @param token The ERC20 token that will be airdropped to eligible participants
    /// @param manager The address that manages this airdrop, which is allowed to update the airdrop details.
    /// @param holder The address holding the tokens that will be airdropped
    /// @param amount The amount of tokens that each participant will receive upon claiming
    struct Airdrop {
        uint256 groupId;
        ERC20 token;
        address manager;
        address holder;
        uint256 amount;
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                              CONFIG STORAGE                            ///
    //////////////////////////////////////////////////////////////////////////////

    /// @dev The Semaphore instance that will be used for managing groups and verifying proofs
    ISemaphore internal immutable semaphore;

    /// @dev Whether a nullifier hash has been used already. Used to prevent double-signaling
    mapping(uint256 => bool) internal nullifierHashes;

    uint256 internal nextAirdropId = 1;
    mapping(uint256 => Airdrop) public getAirdrop;

    ///////////////////////////////////////////////////////////////////////////////
    ///                               CONSTRUCTOR                              ///
    //////////////////////////////////////////////////////////////////////////////

    /// @notice Deploys a SemaphoreAirdrop instance
    /// @param _semaphore The Semaphore instance that will manage groups and verify proofs
    constructor(
        ISemaphore _semaphore
    ) {
        semaphore = _semaphore;
    }

    /// @notice Create a new airdrop
    /// @param groupId The ID of the Semaphore group that will be eligible to claim this airdrop
    /// @param token The ERC20 token that will be airdropped to eligible participants
    /// @param holder The address holding the tokens that will be airdropped
    /// @param amount The amount of tokens that each participant will receive upon claiming
    function createAirdrop(
        uint256 groupId,
        ERC20 token,
        address holder,
        uint256 amount
    ) public {
        Airdrop memory airdrop = Airdrop({
            groupId: groupId,
            token: token,
            manager: msg.sender,
            holder: holder,
            amount: amount
        });

        getAirdrop[nextAirdropId] = airdrop;
        emit AirdropCreated(nextAirdropId, airdrop);

        ++nextAirdropId;
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                               CLAIM LOGIC                               ///
    //////////////////////////////////////////////////////////////////////////////

    /// @notice Claim a given airdrop
    /// @param airdropId The id of the airdrop getting claimed
    /// @param receiver The address that will receive the tokens
    /// @param root The of the Merkle tree
    /// @param nullifierHash The nullifier for this proof, preventing double signaling
    /// @param proof The zero knowledge proof that demostrates the claimer is part of the Semaphore group
    function claim(
        uint256 airdropId,
        address receiver,
        uint256 root,
        uint256 nullifierHash,
        uint256[8] calldata proof
    ) public {
        if (nullifierHashes[nullifierHash]) revert InvalidNullifier();

        Airdrop memory airdrop = getAirdrop[airdropId];
        if (airdropId == 0 || airdropId >= nextAirdropId) revert InvalidAirdrop();

        semaphore.verifyProof(
            root,
            airdrop.groupId,
            abi.encodePacked(receiver).hashToField(),
            nullifierHash,
            abi.encodePacked(address(this), airdropId).hashToField(),
            proof
        );

        nullifierHashes[nullifierHash] = true;
        emit AirdropClaimed(airdropId, receiver);

        SafeTransferLib.safeTransferFrom(airdrop.token, airdrop.holder, receiver, airdrop.amount);
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                               CONFIG LOGIC                             ///
    //////////////////////////////////////////////////////////////////////////////

    /// @notice Update the details for a given airdrop, for addresses that haven't claimed already. Can only be called by the airdrop creator
    /// @param airdropId The id of the airdrop to update
    /// @param airdrop The new details for the airdrop
    function updateDetails(uint256 airdropId, Airdrop calldata airdrop) public {
        if (getAirdrop[airdropId].manager != msg.sender) revert Unauthorized();

        getAirdrop[airdropId] = airdrop;

        emit AirdropUpdated(airdropId, airdrop);
    }
}
