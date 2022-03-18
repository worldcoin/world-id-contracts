// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {ISemaphore} from "./interfaces/ISemaphore.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// @title Semaphore Airdrop Manager
/// @author Miguel Piedrafita
/// @notice Template contract for airdropping tokens to Semaphore group members
contract SemaphoreAirdrop {
    ////////////////////////////////////
    ///            ERRORS            ///
    ////////////////////////////////////

    /// @notice Thrown when trying to update the airdrop amount without being the manager
    error Unauthorized();

    /// @notice Thrown when the proof provided when claiming is not valid
    error InvalidProof();

    /// @notice Thrown when attempting to reuse a nullifier
    error InvalidNullifier();

    ////////////////////////////////////
    ///            EVENTS            ///
    ////////////////////////////////////

    /// @notice Emitted when an airdrop is successfully claimed
    /// @param receiver The address that received the airdrop
    event AirdropClaimed(address receiver);

    /// @notice Emitted when the airdropped amount is changed
    /// @param amount The new amount that participants will receive
    event AmountUpdated(uint256 amount);

    ////////////////////////////////////////////////////////////////////////////
    ///                            CONFIG STORAGE                            ///
    ////////////////////////////////////////////////////////////////////////////

    /// @dev The Semaphore instance that will be used for managing groups and verifying proofs
    ISemaphore internal immutable semaphore;

    /// @dev The Semaphore group ID whose participants can claim this airdrop
    uint256 internal immutable groupId;

    /// @notice The ERC20 token airdropped to participants
    IERC20 public immutable token;

    /// @notice The address that holds the tokens that are being airdropped
    /// @dev Make sure the holder has approved spending for this contract!
    address public immutable holder;

    /// @notice The address that manages this airdrop, which is allowed to update the `airdropAmount`.
    address public immutable manager = msg.sender;

    /// @notice The amount of tokens that participants will receive upon claiming
    uint256 public airdropAmount;

    /// @dev Wether a nullifier hash has been used already. Used to prevent double-signaling
    mapping(uint256 => bool) internal nullifierHashes;

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
        IERC20 _token,
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
        if (nullifierHashes[nullifierHash]) revert InvalidNullifier();

        if (
            !semaphore.isValidProof(
                string(abi.encodePacked(receiver)),
                semaphore.getRoot(groupId),
                nullifierHash,
                uint256(uint160(address(this))),
                proof
            )
        ) revert InvalidProof();

        nullifierHashes[nullifierHash] = true;

        token.transferFrom(holder, receiver, airdropAmount);
    }

    //////////////////////////////////////////////////////////////////
    ///                        CONFIG LOGIC                        ///
    //////////////////////////////////////////////////////////////////

    /// @notice Update the number of claimable tokens, for any addresses that haven't already claimed. Can only be called by the deployer
    /// @param amount The new amount of tokens that should be airdropped
    function updateAmount(uint256 amount) public {
        if (msg.sender != manager) revert Unauthorized();

        airdropAmount = amount;
        emit AmountUpdated(amount);
    }
}
