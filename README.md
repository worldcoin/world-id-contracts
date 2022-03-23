# Zero-Knowledge Gated Airdrop

> A template to airdrop an ERC-20 token to a group of addresses, while preserving privacy for the claimers.

This repository uses [the Semaphore library](http://semaphore.appliedzkp.org) to allow members of a set to claim an ERC-20 token, preserving their privacy and removing the link between the group and the claimer address thanks to zero-knowledge proofs.

## Deployment

First, you'll need a contract that adheres to the [ISemaphore](./src/interfaces/ISemaphore.sol) interface to manage the zero-knowledge groups. If you don't have any special requirements, you can use [this one](./src/Semaphore.sol). Next, you'll need to create a Semaphore group (`Semaphore.createGroup(YOUR_GROUP_ID, 20, 0)` should do the trick). You'll also need an address that holds the tokens to be airdropped (remember to grant access to the airdrop contract after deployment by calling `ERC20.approve(AIRDROP_CONTRACT_ADDRESS, A_VERY_HIGH_NUMBER)`). Finally, deploy the `SemaphoreAirdrop` contract with the Semaphore contract address, the group id, the address of your ERC20 token, the address of the holder, and the amount of tokens to give to each claimer.

## Usage

Since only members of a group can claim the airdrop, you'll need to add some entries to your Semaphore group first. You'll need to generate an identity commitment (which you can do through the [@zk-kit/identity](https://github.com/appliedzkp/zk-kit/tree/main/packages/identity) or [semaphore-rs](https://github.com/worldcoin/semaphore-rs) SDKs). Once you have one, add it to the group by calling `Semaphore.addMember(YOUR_GROUP_ID, IDENTITY_COMMITMENT)`.

Once you have an identity that belongs to the configured group, you should generate a nullifier hash and a proof for it (you should use the [@zk-kit/protocols](https://github.com/appliedzkp/zk-kit/tree/main/packages/protocols) or [semaphore-rs](https://github.com/worldcoin/semaphore-rs) SDKs for this, making sure to use the address you want your tokens sent to as the signal). Once you have both, you can claim your aidrop by calling `SemaphoreAirdrop.claim(RECEIVER_ADDRESS, NULLIFIER_HASH, SOLIDITY_ENCODED_PROOF)`.

You can see the complete flow in action on the [SemaphoreAirdrop tests](./src/test/SemaphoreAirdrop.t.sol).

## Development

This repository uses the [Foundry](https://github.com/gakonst/foundry) smart contract toolkit. You can download the Foundry installer by running `curl -L https://foundry.paradigm.xyz | bash`, and then install the latest version by running `foundryup` on a new terminal window (additional instructions are available [on the Foundry repo](https://github.com/gakonst/foundry#installation)). You'll also need [Node.js](https://nodejs.org) if you're planning to run the automated tests.

Once you have everything installed, you can run `make` from the base directory to install all dependencies, build the smart contracts, and configure the Poseidon Solidity library.

## License

This project is open-sourced software licensed under the MIT license. See the [License file](LICENSE) for more information.
