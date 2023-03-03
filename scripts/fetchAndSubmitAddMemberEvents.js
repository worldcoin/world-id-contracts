import dotenv from 'dotenv'
import ora from 'ora'
import * as ethers from 'ethers'
import * as fs from 'fs/promises'
import yargs from 'yargs/yargs'
import axios from 'axios';

dotenv.config()

const argv = yargs(process.argv.slice(2))
    .env(true)
    .option('r', {
        alias: 'rpc-url',
        default: 'http://localhost:8545',
        desc: 'The RPC URL to connect to (supports RPC_URL env var)'
    })
    .option('s', {
        alias: 'sequencer-url',
        default: 'http://localhost:8080',
        desc: 'The sequencer url to use'
    })
    .option('a', {
        alias: 'address',
        default: '0xD81dE4BCEf43840a2883e5730d014630eA6b7c4A',
        desc: 'The address of the smart contract to read events from'
    })
    .option('f', {
        alias: 'from-block',
        default: 39186981,
        desc: 'The block to start reading events from'
    })
    .option('t', {
        alias: 'to-block',
        desc: 'If not set, will fetch the current block'
    })
    .argv

const semaphoreContract = new ethers.Interface(
    [
        // This is the MemberAdded from ISemaphoreGroups.sol
        // it seems to be the one we're actually emitting on the deployed smart contract
        "event MemberAdded(uint256 indexed groupId, uint256 identityCommitment, uint256 root)",
    ],
);

async function sendCommitmentsToSequencer(events) {
    let commitments = events.map(e => {
        const parsed = semaphoreContract.parseLog(e);
        const identityCommitment = parsed.args[1];

        return identityCommitment.toString();
    });

    await axios.post(`${argv.sequencerUrl}/tmp/insertIdentities`, { identityCommitments: commitments });
}

async function main() {
    const provider = new ethers.JsonRpcProvider(argv.rpcUrl)

    const topic = semaphoreContract.getEvent("MemberAdded").topicHash;
    const address = argv.address;

    let totalEventsFound = 0;

    let firstBlock = argv.fromBlock;
    let step = 1_000;
    let lastFullyProcessedBlock = 0;

    process.on('SIGINT', async () => {
        console.log(`Interrupted, last fully processed block: ${lastFullyProcessedBlock}`);
        process.exit();
    });

    const currentBlock = await provider.getBlockNumber();

    let n = 0;

    console.log(`Going to read events from ${address} with topic ${topic} up to block ${currentBlock}`)
    const spinner = ora(`Waiting for events...`).start()

    let serverCommitmentPromise = null;

    while (true) {
        let fromBlock = firstBlock + (n * step);
        let toBlock = fromBlock + step;
        if (toBlock > currentBlock) {
            toBlock = currentBlock;
        }

        if (fromBlock > currentBlock) {
            break;
        }


        const events = await provider.getLogs({
            fromBlock,
            toBlock,
            address,
            topics: [topic],
        });

        if (serverCommitmentPromise !== null) {
            spinner.text = `Waiting to finish submitting commitments to sequencer`;
            await serverCommitmentPromise;
        }

        lastFullyProcessedBlock = fromBlock;

        spinner.text = `Waiting for events... ${n} (blocks ${fromBlock} to ${toBlock} / ${currentBlock}, found ${totalEventsFound} events)`

        serverCommitmentPromise = sendCommitmentsToSequencer(events);

        totalEventsFound += events.length;
        n += 1;
    }

    spinner.succeed(`Found ${totalEventsFound} events`)
}

main();
