// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {ERC20} from "solmate/tokens/ERC20.sol";
import {ISemaphore} from "./interfaces/ISemaphore.sol";

/// @title Semaphore Airdrop Manager
/// @author Miguel Piedrafita
/// @notice Template contract for airdropping tokens to Semaphore group members
contract SemaphoreAirdrop {
    ////////////////////////////////////
    ///            ERRORS            ///
    ////////////////////////////////////

    /// @notice Thrown when the proof provided when claiming is not valid
    error InvalidProof();

    ////////////////////////////////////
    ///            EVENTS            ///
    ////////////////////////////////////

    /// @notice Emitted when an airdrop is successfully claimed
    /// @param receiver The address that received the airdrop
    event AirdropClaimed(address receiver);

    ////////////////////////////////////////////////////////////////////////////
    ///                            CONFIG STORAGE                            ///
    ////////////////////////////////////////////////////////////////////////////

    /// @dev The Semaphore instance that will be used for managing groups and verifying proofs
    ISemaphore internal immutable semaphore;

    /// @dev The Semaphore group ID whose participants can claim this airdrop
    uint256 internal immutable groupId;

    /// @notice The ERC20 token airdropped to participants
    ERC20 public immutable token;

    /// @notice The address that holds the tokens that are being airdropped
    /// @dev Make sure the holder has approved spending for this contract!
    address public immutable holder;

    /// @notice The amount of tokens that participants will receive upon claiming
    uint256 public immutable airdropAmount;

    /////////////////////////////////////////////////////////////
    ///                      CONSTRUCTOR                      ///
    /////////////////////////////////////////////////////////////

    /// @notice Deploys a SemaphoreAirdrop instance
    /// @param _semaphore The Semaphore instance that will manage groups and verify proofs
    /// @param _groupId The ID of the Semaphore group that will be elegible to claim this airdrop
    /// @param _token The ERC20 token that will be airdropped to elegible participants
    /// @param _holder The address holding the tokens that will be airdropped
    /// @param _airdropAmount The amount of tokens that each participant will receive upon claiming
    constructor(
        ISemaphore _semaphore,
        uint256 _groupId,
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

    /////////////////////////////////////////////////////////////
    ///                      CLAIM LOGIC                      ///
    /////////////////////////////////////////////////////////////

    /// @notice Claim the airdrop
    /// @param receiver The address that will receive the tokens
    /// @param nullifierHash The nullifier for this proof, preventing double signaling
    /// @param proof The zero knowledge proof that demostrates the claimer is part of the Semaphore group
    function claim(
        address receiver,
        uint256 nullifierHash,
        uint256[8] calldata proof
    ) public {
        if (
            !semaphore._isValidProof(
                string(abi.encodePacked(receiver)),
                semaphore.getRoot(groupId),
                nullifierHash,
                uint256(uint160(address(this))),
                proof
            )
        ) revert InvalidProof();

        semaphore.saveNullifierHash(nullifierHash);

        token.transferFrom(holder, receiver, airdropAmount);
    }
}
