# WorldID Base Contracts

> These are the underlying contracts that power World ID. If you're looking to integrate with World ID, you should use the [Foundry](https://github.com/worldcoin/world-id-starter) or [Hardhat](https://github.com/worldcoin/world-id-starter-hardhat) starter kits.

This repository contains the underlying contracts that make World ID work, powered by the [Semaphore library](http://semaphore.appliedzkp.org/).

## <img align="left" width="28" height="28" src="https://github.com/worldcoin/world-id-docs/blob/main/static/img/readme-orb.png" alt="" style="margin-right: 0;" /> About World ID

World ID is a protocol that lets you **prove a human is doing an action only once without revealing any personal data**. Stop bots, stop abuse.

World ID uses a device called the [Orb](https://worldcoin.org/how-the-launch-works) which takes a picture of a person's iris to verify they are a unique and alive human. The protocol only requires a hash-equivalent (i.e. irreversible) of the iris to be stored (which happens on a blockchain). The protocol uses [Zero-knowledge proofs](https://id.worldcoin.org/zkp) so no traceable information is ever public.

World ID is meant for on-chain web3 apps, traditional Cloud applications, and even IRL verifications. Go to the [World ID app][app] to get started.

<img src="https://github.com/worldcoin/world-id-docs/blob/main/static/img/readme-diagram.png" alt="Diagram of how World ID works."  />

## Deployment

First, you'll need a contract that adheres to the [ISemaphore](./src/interfaces/ISemaphore.sol) interface to manage the zero-knowledge groups. If you don't have any special requirements, you can use [this one](./src/Semaphore.sol). Next, you'll need to create a Semaphore group (`Semaphore.createGroup(YOUR_GROUP_ID, 20, 0)` should do the trick). You'll also need an address that holds the tokens to be airdropped (remember to grant access to the airdrop contract after deployment by calling `ERC20.approve(AIRDROP_CONTRACT_ADDRESS, A_VERY_HIGH_NUMBER)`). Finally, deploy the `SemaphoreAirdrop` contract with the Semaphore contract address, the group id, the address of your ERC20 token, the address of the holder, and the amount of tokens to give to each claimer.

## Usage

> These instructions explain how to deploy your own Semaphore instance. If you just want to integrate with World ID, follow [these instructions](https://github.com/worldcoin/world-id-starter#-usage-instructions) instead.

TO add identities to your Semaphore group, end-users will need to generate an identity commitment (which can be done through the [@zk-kit/identity](https://github.com/appliedzkp/zk-kit/tree/main/packages/identity) or [semaphore-rs](https://github.com/worldcoin/semaphore-rs) SDKs). Once they have one, you can add it to the group by calling `Semaphore.addMember(YOUR_GROUP_ID, IDENTITY_COMMITMENT)`.

To verify, they should generate a nullifier hash and a proof for it (which can be done through the [@zk-kit/protocols](https://github.com/appliedzkp/zk-kit/tree/main/packages/protocols) or [semaphore-rs](https://github.com/worldcoin/semaphore-rs) SDKs, using the address who will receive the tokens as the signal). Once they have both, they should pass the nullifier hash, solidity-encoded proof (and any extra arguments used as signal) to the smart contract integrating Semaphore.

## Usage with Worldcoin

See [the starter kit](https://github.com/worldcoin/world-id-starter#-usage-instructions) for detailed instructions on how to integrate with World ID.

## Development

This repository uses the [Foundry](https://github.com/gakonst/foundry) smart contract toolkit. You can download the Foundry installer by running `curl -L https://foundry.paradigm.xyz | bash`, and then install the latest version by running `foundryup` on a new terminal window (additional instructions are available [on the Foundry repo](https://github.com/gakonst/foundry#installation)). You'll also need [Node.js](https://nodejs.org) if you're planning to run the automated tests.

Once you have everything installed, you can run `make` from the base directory to install all dependencies, build the smart contracts, and configure the Poseidon Solidity library.
