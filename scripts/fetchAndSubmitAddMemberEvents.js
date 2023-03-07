import dotenv from 'dotenv';
import ora from 'ora';
import * as ethers from 'ethers';
import * as fs from 'fs/promises';
import yargs from 'yargs/yargs';
import axios from 'axios';

dotenv.config();

const argv = yargs(process.argv.slice(2))
  // All the options can be replaced with a SCREAMING_SNAKE_CASE environment variables
  // e.g. --rpc-url can be replaced with RPC_URL
  .env(true)
  .option('r', {
    alias: 'rpc-url',
    desc: 'The RPC URL to connect to (supports RPC_URL env var)',
  })
  .option('s', {
    alias: 'sequencer-url',
    desc: 'The sequencer url to use',
  })
  .option('i', {
    alias: 'input-file',
    desc: 'If set, will read the events from a file',
  })
  .option('a', {
    alias: 'address',
    default: '0xD81dE4BCEf43840a2883e5730d014630eA6b7c4A',
    desc: 'The address of the smart contract to read events from',
  })
  .option('f', {
    alias: 'from-block',
    default: 39186981,
    desc: 'The block to start reading events from',
  })
  .option('t', {
    alias: 'to-block',
    desc: 'If not set, will fetch the current block',
  })
  .option('b', {
    alias: 'block-span',
    default: 10_000,
    desc: 'The number of blocks to read events from at a time',
  })
  .option('o', {
    alias: 'output-file',
    desc: 'If set, will write the events to a file',
  })
  .option('e', {
    alias: 'error-output-file',
    desc: 'If set, will errors that occurred during submission to a file',
  }).argv;

const semaphoreContract = new ethers.utils.Interface([
  // This is the MemberAdded from ISemaphoreGroups.sol
  // it seems to be the one we're actually emitting on the deployed smart contract
  'event MemberAdded(uint256 indexed groupId, uint256 identityCommitment, uint256 root)',
]);

// Takes in a list of commitments (as hex strings) and submits them to the sequencer and/or writes them to the output file
//
// if submitting a commitment fails - it will write the commitment and the error to the error output file or to the console if the error file is not set
async function handleCommitments(commitments) {
  return Promise.all(
    commitments.map(async commitment => {
      try {
        if (argv.sequencerUrl !== undefined) {
          await axios.post(`${argv.sequencerUrl}/insertIdentity`, {
            identityCommitment: commitment,
          });
        }

        if (argv.outputFile !== undefined) {
          await fs.appendFile(argv.outputFile, `${commitment}\n`);
        }
      } catch (err) {
        if (argv.errorOutputFile !== undefined) {
          await fs.appendFile(
            argv.errorOutputFile,
            `${commitment}\n${JSON.stringify(err.toJSON())}\n`
          );
        } else {
          console.error(`Error while submitting commitment ${commitment}: ${err}`);
        }
      }
    })
  );
}

// Extracts the identity commitments from the events and returns them as an array of hex strings
function parseLogs(eventLogs) {
  return eventLogs.map(e => {
    const parsed = semaphoreContract.parseLog(e);
    const identityCommitment = parsed.args[1];

    return identityCommitment.toHexString();
  });
}

async function getLastBlock(provider) {
  if (argv.toBlock !== undefined) {
    return argv.toBlock;
  } else {
    return await provider.getBlockNumber();
  }
}

const spinner = ora(`Fetching commitments...`).start();

async function fetchEventsFromBlockchain(handler) {
  const provider = new ethers.providers.JsonRpcProvider(argv.rpcUrl);

  const topic = semaphoreContract.getEventTopic('MemberAdded');
  const address = argv.address;

  let totalEventsFound = 0;

  let firstBlock = argv.fromBlock;
  let step = argv.blockSpan;
  let lastFullyProcessedBlock = 0;

  // Prints out the last fully processed block so that we can resume from there in case of an interruption
  process.on('SIGINT', async () => {
    console.log(`Interrupted, last fully processed block: ${lastFullyProcessedBlock}`);
    process.exit();
  });

  const lastBlock = await getLastBlock(provider);

  const maxN = lastBlock / step;

  console.log(`Going to read events from ${address} with topic ${topic} up to block ${lastBlock}`);

  // We'll likely be bottlenecked by the time it takes to submit the commitments to the sequencer
  // and we don't want to fetch too many events ahead of time
  // so we keep a promise that will resolve when the last batch of commitments has been submitted
  // and we wait for it to resolve before fetching the next batch of events
  let serverCommitmentPromise = null;

  for (let n = 0; n < maxN; n++) {
    let fromBlock = firstBlock + n * step;
    let toBlock = fromBlock + step;

    // Cap blocks to the last one
    if (toBlock > lastBlock) {
      toBlock = lastBlock;
    }

    const events = await provider.getLogs({
      fromBlock,
      toBlock,
      address,
      topics: [topic],
    });

    // Waiting to resolve the last batch of commitments
    if (serverCommitmentPromise !== null) {
      spinner.text = `Waiting to finish submitting commitments to sequencer`;
      await serverCommitmentPromise;
    }

    // We keep track of the last fully processed block in case we need to interrupt
    lastFullyProcessedBlock = fromBlock;

    spinner.text = `Waiting for events... ${n} (blocks ${fromBlock} to ${toBlock} / ${lastBlock}, found ${totalEventsFound} events)`;

    const commitments = parseLogs(events);
    serverCommitmentPromise = handler(commitments);

    totalEventsFound += events.length;
  }

  spinner.succeed(`Found ${totalEventsFound} events`);
}

async function fetchCommitmentsFromFile() {
  const commitments = await fs
    .readFile(argv.inputFile, 'utf-8')
    .then(data => data.split('\n').filter(x => x !== ''));

  await handleCommitments(commitments);

  spinner.succeed(`Found ${commitments.length} events`);
}

async function main() {
  if (argv.inputFile !== undefined && argv.rpcUrl !== undefined) {
    spinner.warn(
      'Cannot fetch from both the blockchain and file, use only one of --input-file or --rpc-url'
    );
    return;
  }

  if (argv.inputFile !== undefined) {
    await fetchCommitmentsFromFile();
  } else {
    await fetchEventsFromBlockchain(handleCommitments);
  }
}

main();
