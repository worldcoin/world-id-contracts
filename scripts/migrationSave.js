import dotenv from 'dotenv'
import { JsonRpcProvider } from '@ethersproject/providers'
import ora from 'ora'
import * as ethers from 'ethers'
import * as fs from 'fs/promises'
import yargs from 'yargs/yargs'

dotenv.config()

const argv = yargs(process.argv.slice(2))
    .env(true)
    .option('r', {
        alias: 'rpc-url',
        default: 'http://localhost:8545',
        desc: 'The RPC URL to connect to (supports RPC_URL env var)'
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
    .option('o', {
        alias: 'output',
        default: 'events.json',
        desc: 'The file to write the events to'
    })
    .argv

const eventsFile = argv.output;

async function updateEventsFile(newEvents) {
    let events = [];
    try {
        const eventsString = await fs.readFile(eventsFile, 'utf8');
        events = JSON.parse(eventsString);
    } catch (e) {
        // file doesn't exist
    }

    newEvents = newEvents.map(e => {
        return {
            address: e.address,
            data: e.data,
            topics: e.topics,
            transactionHash: e.transactionHash,
            blockNumber: e.blockNumber,
        }
    });
    events = events.concat(newEvents);

    await fs.writeFile(eventsFile, JSON.stringify(events, null, 4));
}

async function main() {
    const provider = new JsonRpcProvider(argv.rpcUrl)

    const semaphoreContract = new ethers.Interface(
        [
            // This is the MemberAdded from ISemaphoreGroups.sol
            // it seems to be the one we're actually emitting on the deployed smart contract
            "event MemberAdded(uint256 indexed groupId, uint256 identityCommitment, uint256 root)",
        ],
    );

    const topic = semaphoreContract.getEvent("MemberAdded").topicHash;
    const address = argv.address;

    let totalEventsFound = 0;

    let firstBlock = argv.fromBlock;
    let step = 1_000;
    const currentBlock = await provider.getBlockNumber();

    let n = 0;

    console.log(`Going to read events from ${address} with topic ${topic} up to block ${currentBlock}`)
    const spinner = ora(`Waiting for events...`).start()

    while (true) {

        let fromBlock = firstBlock + (n * step);
        let toBlock = fromBlock + step;
        if (toBlock > currentBlock) {
            toBlock = currentBlock;
        }

        if (fromBlock > currentBlock) {
            break;
        }

        spinner.text = `Waiting for events... (blocks ${fromBlock} to ${toBlock} / ${currentBlock}, found ${totalEventsFound} events)`

        const events = await provider.getLogs({
            fromBlock,
            toBlock,
            address,
            topics: [topic],
        });

        updateEventsFile(events);

        totalEventsFound += events.length;
        n += 1;
    }

    spinner.succeed(`Found ${totalEventsFound} events`)
}

main();
