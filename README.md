# WorldID Semaphore Contracts

> These are the underlying contracts that power World ID. If you're looking to integrate with World
> ID, you should use the [Foundry](https://github.com/worldcoin/world-id-starter) or
> [Hardhat](https://github.com/worldcoin/world-id-starter-hardhat) starter kits.

This repository contains the underlying contracts that make World ID work, powered by the
[Semaphore library](http://semaphore.appliedzkp.org/).

## <img align="left" width="28" height="28" src="https://raw.githubusercontent.com/worldcoin/world-id-docs/main/public/images/shared-readme/readme-world-id.png" alt="" style="margin-right: 0;" /> About World ID

World ID is a protocol that lets you **prove a human is doing an action only once without revealing
any personal data**. Stop bots, stop abuse.

World ID uses a device called the [Orb](https://worldcoin.org/how-the-launch-works) which takes a
picture of a person's iris to verify they are a unique and alive human. The protocol only requires a
hash-equivalent (i.e. irreversible) of the iris to be stored (which happens on a blockchain). The
protocol uses [Zero-knowledge proofs](https://id.worldcoin.org/zkp) so no traceable information is
ever public.

World ID is meant for on-chain web3 apps, traditional Cloud applications, and even IRL
verifications. Go to the [World ID app](https://worldcoin.org/download-app) to get started.

<img src="https://github.com/worldcoin/world-id-docs/raw/main/public/images/docs/introduction/how-it-works-light.svg" alt="Diagram of how World ID works."  />

## Deployment

Deploying the Semaphore contract will require generating a verifier contract for our batch insertion
service. Calling `make deploy` will guide you through the process of downloading the relevant tools,
initializing and creating the required contracts.

## Testing

The prover service comes with a way to generate test parameters—a mock insertion of a batch of
consecutive commitments into the tree. Assuming you've already run `make deploy`, the prover serivce
binary should have been downloaded. To generate a test batch, run

```
./mtb/bin/mtb gen-test-params --tree-depth=... --batch-size=...
```

where the parameters MUST match the parameters passed for contract deployment. To transform these
into a proof, run the `prove` command, passing the params on stdin:

```
./mtb/bin/mtb prove --keys-file=mtb/keys < GENERATED_PARAMS
```

The output of this, together with the relevant parts of the generated test params, should constitute
a correct input to the `registerIdentities` method of the `Semaphore` contract, as long as it was
deployed using the same keys file.

## Usage with Worldcoin

See [the starter kit](https://github.com/worldcoin/world-id-starter#-usage-instructions) for
detailed instructions on how to integrate with World ID.

## Development

This repository uses the [Foundry](https://github.com/gakonst/foundry) smart contract toolkit. You
can download the Foundry installer by running `curl -L https://foundry.paradigm.xyz | bash`, and
then install the latest version by running `foundryup` on a new terminal window (additional
instructions are available [on the Foundry repo](https://github.com/gakonst/foundry#installation)).
You'll also need [Node.js](https://nodejs.org) if you're planning to run the automated tests.

Once you have everything installed, you can run `make` from the base directory to install all
dependencies and build the smart contracts.
