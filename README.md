<p align="center">
  <a href="https://worldcoin.org/world-id">
<img src="https://github.com/worldcoin/world-id-docs/raw/main/public/images/shared-readme/readme-world-id.png" alt="World ID Logo"/>
  </a>
</p>

# WorldID Semaphore Contracts

> These are the underlying contracts that power World ID. If you're looking to integrate with World
> ID, you should use the [Foundry](https://github.com/worldcoin/world-id-starter) or
> [Hardhat](https://github.com/worldcoin/world-id-starter-hardhat) starter kits.

This repository contains the underlying contracts that make World ID work, powered by the
[Semaphore library](https://semaphore.pse.dev/). These contracts are responsible for performing
identity operations on chain, and attestation of identities for the purposes of semaphore proofs.
Check out [user-flows.md](./docs/user-flows.md) for more information on how these contracts relate
to the rest of the World ID system.

## <img align="left" width="28" height="28" src="https://raw.githubusercontent.com/worldcoin/world-id-docs/main/public/images/shared-readme/readme-world-id.png" alt="World ID Logo" style="margin-right: 5;" /> About World ID

World ID is a protocol that lets you **prove a human is doing an action only once without revealing
any personal data**. Stop bots, stop abuse.

World ID uses a device called the [Orb](https://worldcoin.org/how-the-launch-works) which takes a
picture of a person's iris to verify they are a unique and alive human. The protocol only requires a
hash-equivalent (i.e. irreversible) of the iris to be stored (which happens on a blockchain). The
protocol uses
[Zero-knowledge proofs](https://docs.worldcoin.org/further-reading/zero-knowledge-proofs) so no
traceable information is ever public.

World ID is meant for on-chain web3 apps, traditional Cloud applications, and even IRL
verifications. Go to the [World ID app](https://worldcoin.org/download-app) to get started.

<img src="https://github.com/worldcoin/world-id-docs/raw/main/public/images/docs/introduction/worldcoin-sign-in.jpg" alt="Worldcoin Sign In"  />

## Privileged Actions and Trust

The WorldID Identity Manager uses a bifurcated notion of privilege in production. This operates as
follows:

- **Owner:** The owner is responsible for administrating the contract. In production, the contract's
  owner will be a multi-signature wallet.
- **Identity Operator:** The identity operator is responsible for performing identity operations
  using the contract. In production, the contract's identity operator will be a wallet associated
  with [OpenZeppelin Relay](https://docs.openzeppelin.com/defender/relay), ensuring that identities
  are submitted on-chain reliably and in order.

All other contracts use a simple notion of an "owner", that will be held by a multi-signature wallet
in production.

What follows below is a table of privileged operations in the WorldID Identity Manager contract, and
which of the _owner_ and _identity operator_ has the permission to perform these actions.

| Operation                                  | Privileges        | Description                                                                                                                           |
| :----------------------------------------- | :---------------- | :------------------------------------------------------------------------------------------------------------------------------------ |
| `acceptOwnership`                          | New Owner         | Accepts the transfer of ownership.                                                                                                    |
| `disableStateBridge`                       | Owner             | Turns off the state bridge.                                                                                                           |
| `enableStateBridge`                        | Owner             | Turns on the state bridge.                                                                                                            |
| `registerIdentities`                       | Identity Operator | Registers new identity commitments into the World ID system.                                                                          |
| `deleteIdentities`                       | Identity Operator | Registers new identity commitments into the World ID system.                                                                          |
| `setIdentityOperator`                      | Owner             | Sets the address that has permission to act as the Identity Operator.                                                                 |
| `setRegisterIdentitiesVerifierLookupTable` | Owner             | Sets the table of verifiers used to verify proofs that correspond to identity insertions.                                             |
| `setDeleteIdentitiesVerifierLookupTable`   | Owner             | Sets the table of verifiers used to verify proofs that correspond to identity insertions.                                             |
| `setRootHistoryExpiry`                     | Owner             | Sets the amount of time it takes for a non-current tree root to expire.                                                               |
| `setSemaphoreVerifier`                     | Owner             | Sets the contract used to verify semaphore proofs.                                                                                    |
| `setStateBridge`                           | Owner             | Sets the address of the state bridge. The state bridge is the contract responsible for sending identity tree updates to other chains. |
| `transferOwnership`                        | Owner             | Transfers ownership from the current owner to a new owner using a two-step process.                                                   |
| `upgradeTo`                                | Owner             | Upgrades the implementation of the identity manager to a new version.                                                                 |
| `upgradeToAndCall`                         | Owner             | Upgrades the implementation of the identity manager to a new version and executes a function call while doing so.                     |

While there have been some discussions pertaining to the implementation of _timelocks_ for sensitive
actions, many of these actions are required for administrating the contracts in conjunction with
external services (such as the [signup sequencer](https://github.com/worldcoin/signup-sequencer)).
To this end, timelocks would cause problems due to delays that could risk desynchronisation between
the contract and external services.

## Development

This repository uses the [Foundry](https://github.com/gakonst/foundry) smart contract toolkit. You
can download the Foundry installer by running `curl -L https://foundry.paradigm.xyz | bash`, and
then install the latest version by running `foundryup` on a new terminal window (additional
instructions are available [on the Foundry repo](https://github.com/gakonst/foundry#installation)).
You'll also need [Node.js](https://nodejs.org) if you're planning to run the automated tests.

Once you have everything installed, you can run `make` from the base directory to install all
dependencies and build the smart contracts.

### Testing

In order to generate valid proofs you need to first download [`semaphore-mtb`](https://github.com/worldcoin/semaphore-mtb) and build it. Then you can run the tests with:


```bash
./gnark-mbu gen-test-param --mode insertion/deletion --tree-depth=... --batch-size=...
```

where the parameters MUST match the parameters passed for contract deployment. To transform these
into a proof, run the `prove` command, passing the params on stdin:

> [!NOTE]
> In order to generate a valid keys file, you need to run `gnark-mbu setup` with the correct parameters. > The `gnark-mbu setup` command will output a `keys` file that you can use for the `prove` command.

```bash
./gnark-mbu prove --mode insertion/deletion --keys-file= ${keys_file} < GENERATED_PARAMS
```

The output of this, together with the relevant parts of the generated test params, should constitute
a correct input to the `registerIdentities` or `deleteIdentities` methods respectively of the `WorldIDIdentityManagerImplV1/V2` contracts, as long as it was
deployed using the same keys file.

Alternatively, you can take a look at pre-made tests with pre-generated valid proofs in [`WorldIDIdentityManagerTest.sol`](./src/test/identity-manager/WorldIDIdentityManagerTest.sol), [`WorldIDIdentityManagerIdentityRegistration.sol`](./src/test/identity-manager/WorldIDIdentityManagerIdentityRegistration.t.sol) and [`WorldIDIdentityManagerIdentityDeletion.sol`](./src/test/identity-manager/WorldIDIdentityManagerIdentityDeletion.t.sol).

### Deployment

In order to deploy `world-id-contracts` you need to download [`contract-deployer`](https://github.com/worldcoin/contract-deployer), build it and do the following:

1. Download the repo

```bash
git clone https://github.com/worldcoin/contract-deployer.git
cd contract-deployer
git submodule update --init --recursive
```

2. Setup your environment variables ([link](https://github.com/worldcoin/contract-deployer?tab=readme-ov-file#%EF%B8%8F-configuration))

3. Setup deployment config file ([link](https://github.com/worldcoin/contract-deployer?tab=readme-ov-file#configuration-file))

4. Deploy

> [!NOTE]
> You need to have the rust toolchain installed in order to deploy the contracts. [link](https://www.rust-lang.org/tools/install)

Run:

```bash
cargo run --release 
```



