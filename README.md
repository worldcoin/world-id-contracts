# Zero-Knowledge Gated Airdrop

> A template to airdrop an ERC-20 token to a group of addresses, while preserving privacy for the claimers.

This repository uses [the Semaphore library](http://semaphore.appliedzkp.org) to allow members of a set to claim an ERC-20 token, preserving their privacy and removing the link between the group and the claimer address thanks to zero-knowledge proofs.

## Deployment

First, you'll need a contract that adheres to the [ISemaphore](./src/interfaces/ISemaphore.sol) interface to manage the zero-knowledge groups. If you don't have any special requirements, you can use [this one](./src/Semaphore.sol). Next, you'll need to create a Semaphore group (`Semaphore.createGroup(YOUR_GROUP_ID, 20, 0)` should do the trick). You'll also need an address that holds the tokens to be airdropped (remember to grant access to the airdrop contract after deployment by calling `ERC20.approve(AIRDROP_CONTRACT_ADDRESS, A_VERY_HIGH_NUMBER)`). Finally, deploy the `SemaphoreAirdrop` contract with the Semaphore contract address, the group id, the address of your ERC20 token, the address of the holder, and the amount of tokens to give to each claimer.

## Usage

Since only members of a group can claim the airdrop, you'll need to add some entries to your Semaphore group first. End-users will need to generate an identity commitment (which can be done through the [@zk-kit/identity](https://github.com/appliedzkp/zk-kit/tree/main/packages/identity) or [semaphore-rs](https://github.com/worldcoin/semaphore-rs) SDKs). Once they have one, you can add it to the group by calling `Semaphore.addMember(YOUR_GROUP_ID, IDENTITY_COMMITMENT)`.

Once users have identities included on the configured group, they should generate a nullifier hash and a proof for it (which can be done through the [@zk-kit/protocols](https://github.com/appliedzkp/zk-kit/tree/main/packages/protocols) or [semaphore-rs](https://github.com/worldcoin/semaphore-rs) SDKs, using the address who will receive the tokens as the signal). Once they have both, they can claim the aidrop by calling `SemaphoreAirdrop.claim(RECEIVER_ADDRESS, NULLIFIER_HASH, SOLIDITY_ENCODED_PROOF)`.

You can see the complete flow in action on the [SemaphoreAirdrop tests](./src/test/SemaphoreAirdrop.t.sol).

## Usage with Worldcoin

Worldcoin will maintain a Semaphore instance with a group for all the people that have onboarded to the protocol. Once the insance is deployed, we'll provide information here so you can point your `SemaphoreAirdrop` instances to it, ensuring only unique humans can claim your airdrop.

## Development

This repository uses the [Foundry](https://github.com/gakonst/foundry) smart contract toolkit. You can download the Foundry installer by running `curl -L https://foundry.paradigm.xyz | bash`, and then install the latest version by running `foundryup` on a new terminal window (additional instructions are available [on the Foundry repo](https://github.com/gakonst/foundry#installation)). You'll also need [Node.js](https://nodejs.org) if you're planning to run the automated tests.

Once you have everything installed, you can run `make` from the base directory to install all dependencies, build the smart contracts, and configure the Poseidon Solidity library.

## License

This project is open-sourced software licensed under the MIT license. See the [License file](LICENSE) for more information.
