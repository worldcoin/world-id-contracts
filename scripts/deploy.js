import fs from 'fs';
import https from 'https';
import readline from 'readline';
import { spawnSync } from 'child_process';

import dotenv from 'dotenv';
import ora from 'ora';

import solc from 'solc';
import { Contract, ContractFactory, Wallet, providers } from 'ethers';
import { Interface } from 'ethers/lib/utils.js';
import { poseidon } from 'circomlibjs';

const { JsonRpcProvider } = providers;

import Semaphore from '../out/Semaphore.sol/Semaphore.json' assert { type: 'json' };
import WorldIDIdentityManager from '../out/WorldIDIdentityManager.sol/WorldIDIdentityManager.json' assert { type: 'json' };
import WorldIDIdentityManagerImpl from '../out/WorldIDIdentityManagerImplV1.sol/WorldIDIdentityManagerImplV1.json' assert { type: 'json' };
import { BigNumber } from '@ethersproject/bignumber';

// === Constants ==================================================================================

const DEFAULT_RPC_URL = 'http://localhost:8545';
const MTB_RELEASES_URL = 'https://github.com/worldcoin/semaphore-mtb/releases/download';
const MTB_DIR = 'mtb';
const KEYS_PATH = MTB_DIR + '/keys';
const MTB_BIN_DIR = MTB_DIR + '/bin';
const MTB_BIN_PATH = MTB_BIN_DIR + '/mtb';
const MTB_CONTRACTS_DIR = MTB_DIR + '/contracts';

// These are an arbitrary choice just for ease of development.
const DEFAULT_TREE_DEPTH = 32;
const DEFAULT_BATCH_SIZE = 3;
const MTB_VERSION = '1.0.2';
const VERIFIER_SOURCE_PATH = MTB_CONTRACTS_DIR + '/Verifier.sol';
const VERIFIER_ABI_PATH = MTB_CONTRACTS_DIR + '/Verifier.json';

// === Implementation =============================================================================

/**
 * Asks the user a question and returns the answer.
 *
 * @param {string} question the question contents.
 * @param {?string} type an optional type to parse the answer as. Currently only supports 'int' for decimal integers.
 * @returns a promise resolving to user's response
 */
function ask(question, type) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    });

    return new Promise((resolve, reject) => {
        rl.question(question, input => {
            if (type === 'int' && input) {
                input = parseInt(input);
                if (isNaN(input)) {
                    reject('Invalid input');
                }
            }
            resolve(input);
            rl.close();
        });
    });
}

function newPlan() {
    let self = {
        items: [],
        add: function (label, action) {
            self.items.push({ label, action });
        },
    };
    return self;
}

async function httpsGetWithRedirects(url) {
    return new Promise((resolve, reject) => {
        const request = https.get(url, function (response) {
            if (response.statusCode == 302) {
                httpsGetWithRedirects(response.headers.location).then(resolve, reject);
            } else {
                resolve(response);
            }
        });
        request.on('error', err => {
            reject(err);
        });
    });
}

async function downloadSemaphoreMtbBinary(plan, config) {
    config.mtbBinary = MTB_BIN_PATH;
    if (process.platform == 'win32') {
        if (process.arch != 'x64') {
            throw new Error('Unsupported platform');
        }
        config.os = 'windows';
        config.arch = 'amd64';
    } else if (process.platform == 'linux') {
        if (process.arch != 'x64') {
            throw new Error('Unsupported platform');
        }
        config.os = 'linux';
        config.arch = 'amd64';
    } else if (process.platform == 'darwin') {
        config.os = 'darwin';
        config.arch = process.arch == 'arm64' ? 'arm64' : 'amd64';
    }
    plan.add('Download Semaphore-MTB binary', async config => {
        fs.mkdirSync(MTB_BIN_DIR, { recursive: true });
        const spinner = ora('Downloading Semaphore-MTB binary...').start();
        const url = `${MTB_RELEASES_URL}/${MTB_VERSION}/mtb-${config.os}-${config.arch}`;
        const response = await httpsGetWithRedirects(url)
        const done = new Promise((resolve, reject) => {
            const file = fs.createWriteStream(config.mtbBinary);
            response.pipe(file);

            file.on('finish', () => {
                file.close();
                resolve();
            });

            file.on('error', err => {
                fs.unlink(config.MTB_BINARY, () => reject(err));
            });
        });
        await done;
        if (config.os != 'windows') {
            fs.chmodSync(config.mtbBinary, '755');
        }
        spinner.succeed('Semaphore-MTB binary downloaded');
    });
}

async function ensureMtbBinary(plan, config) {
    config.mtbBinary = process.env.MTB_BINARY;
    if (!config.mtbBinary) {
        if (fs.existsSync(MTB_BIN_PATH)) {
            config.mtbBinary = MTB_BIN_PATH;
            console.log(`Using default Semaphore-MTB binary ${MTB_BIN_PATH}`);
        }
    }
    if (!config.mtbBinary) {
        config.mtbBinary = await ask(
            'Semaphore-MTB binary not found in the default location. Enter binary location, or leave empty to download it: '
        );
    }
    if (!config.mtbBinary) {
        await downloadSemaphoreMtbBinary(plan, config);
    }
}

async function ensureTreeDepth(plan, config) {
    config.treeDepth = process.env.TREE_DEPTH;
    if (!config.treeDepth) {
        config.treeDepth = await ask(`Enter tree depth: (${DEFAULT_TREE_DEPTH}) `, 'int');
    }
    if (!config.treeDepth) {
        config.treeDepth = DEFAULT_TREE_DEPTH;
    }
}

async function generateKeys(plan, config) {
    await ensureTreeDepth(plan, config);

    config.batchSize = process.env.BATCH_SIZE;
    if (!config.batchSize) {
        config.batchSize = await ask(`Enter batch size: (${DEFAULT_BATCH_SIZE}) `, 'int');
    }
    if (!config.batchSize) {
        config.batchSize = DEFAULT_BATCH_SIZE;
    }
    plan.add('Setup Semaphore-MTB keys', async config => {
        const spinner = ora('Generating prover keys').start();
        fs.mkdirSync(MTB_DIR, { recursive: true });
        let result = spawnSync(
            config.mtbBinary,
            [
                'setup',
                '--tree-depth',
                config.treeDepth,
                '--batch-size',
                config.batchSize,
                '--output',
                config.keysFile,
            ],
            { stdio: 'inherit' }
        );
        if (result.status != 0) {
            throw new Error('Failed to generate prover keys');
        }
        spinner.succeed('Prover keys generated');
    });
}

async function ensureKeysFile(plan, config) {
    config.keysFile = process.env.KEYS_FILE;
    if (!config.keysFile) {
        if (fs.existsSync(KEYS_PATH)) {
            config.keysFile = KEYS_PATH;
            console.log(`Using default Semaphore-MTB keys file (${KEYS_PATH})`);
        }
    }
    if (!config.keysFile) {
        config.keysFile = await ask(
            'Enter path to the prover/verifier keys file, or leave empty to set it up: '
        );
    }
    if (!config.keysFile) {
        config.keysFile = KEYS_PATH;
        await generateKeys(plan, config);
    }
}

async function generateVerifierContract(plan, config) {
    await ensureKeysFile(plan, config);
    plan.add('Generate Semaphore-MTB verifier contract', async () => {
        const spinner = ora('Generating verifier contract').start();
        fs.mkdirSync(MTB_CONTRACTS_DIR, { recursive: true });
        let result = spawnSync(
            config.mtbBinary,
            [
                'export-solidity',
                '--keys-file',
                config.keysFile,
                '--output',
                config.mtbVerifierContractFile,
            ],
            { stdio: 'inherit' }
        );
        if (result.status != 0) {
            throw new Error('Failed to generate verifier contract');
        }
        spinner.succeed('Verifier contract generated');
    });
}

async function ensureVerifierContractFile(plan, config) {
    config.mtbVerifierContractFile = process.env.MTB_VERIFIER_CONTRACT_FILE;
    if (!config.mtbVerifierContractFile) {
        if (fs.existsSync(VERIFIER_SOURCE_PATH)) {
            config.mtbVerifierContractFile = VERIFIER_SOURCE_PATH;
            console.log(
                `Using default Semaphore-MTB verifier contract file (${VERIFIER_SOURCE_PATH})`
            );
        }
    }
    if (!config.mtbVerifierContractFile) {
        config.mtbVerifierContractFile = await ask(
            'Enter path to the Semaphore-MTB verifier contract file, or leave empty to generate it: '
        );
    }
    if (!config.mtbVerifierContractFile) {
        await ensureMtbBinary(plan, config);
        config.mtbVerifierContractFile = VERIFIER_SOURCE_PATH;
        await generateVerifierContract(plan, config);
    }
}

async function compileVerifierContract(plan, config) {
    plan.add('Compile Semaphore-MTB verifier contract', async config => {
        let input = {
            language: 'Solidity',
            sources: {
                'Verifier.sol': {
                    content: fs.readFileSync(config.mtbVerifierContractFile).toString(),
                },
            },
            settings: {
                outputSelection: {
                    'Verifier.sol': {
                        Verifier: ['evm.bytecode.object'],
                    },
                },
            },
        };
        let output = solc.compile(JSON.stringify(input));
        fs.mkdirSync(MTB_CONTRACTS_DIR, { recursive: true });
        fs.writeFileSync(config.mtbVerifierContractOutFile, output);
    });
}

async function ensureVerifierBytecode(plan, config) {
    config.mtbVerifierContractOutFile = process.env.VERIFIER_BYTECODE_FILE;
    if (!config.mtbVerifierContractOutFile) {
        if (fs.existsSync(VERIFIER_ABI_PATH)) {
            config.mtbVerifierContractOutFile = VERIFIER_ABI_PATH;
            console.log(`Using existing Semaphore-MTB bytecode file ${VERIFIER_ABI_PATH}}`);
        }
    }
    if (!config.mtbVerifierContractOutFile) {
        await ensureVerifierContractFile(plan, config);
        config.mtbVerifierContractOutFile = VERIFIER_ABI_PATH;
        await compileVerifierContract(plan, config);
    }
}

async function deployVerifierContract(plan, config) {
    plan.add('Deploy Semaphore-MTB verifier contract', async () => {
        const spinner = ora(`Deploying MTB Verifier contract...`).start();
        let verifierBytecode = JSON.parse(
            fs.readFileSync(config.mtbVerifierContractOutFile).toString()
        );
        let factory = new ContractFactory(
            [],
            verifierBytecode.contracts['Verifier.sol'].Verifier.evm.bytecode.object,
            config.wallet
        );
        let contract = await factory.deploy();
        spinner.text = `Waiting for MTB Verifier deploy transaction (address: ${contract.address})`;
        await contract.deployTransaction.wait();
        spinner.succeed(`Deployed MTB Verifier contract to ${contract.address}`);
        config.verifierContractAddress = contract.address;
    });
}

async function ensureVerifierDeployment(plan, config) {
    config.verifierContractAddress = process.env.VERIFIER_CONTRACT_ADDRESS;
    if (!config.verifierContractAddress) {
        config.verifierContractAddress = await ask(
            'Enter batch insert verifier contract address, or leave empty to deploy it: '
        );
    }
    if (!config.verifierContractAddress) {
        await ensureVerifierBytecode(plan, config);
        await deployVerifierContract(plan, config);
    }
}

function computeRoot(depth) {
    let result = 0;
    while (depth--) {
        result = poseidon([result, result]);
    }

    return '0x' + result.toString(16);
}

async function ensureInitialRoot(plan, config) {
    config.initialRoot = process.env.INITIAL_ROOT;
    if (!config.initialRoot) {
        config.initialRoot = await ask(
            'Enter initial root, or leave empty to compute based on tree depth: '
        );
    }
    if (!config.initialRoot) {
        if (!config.treeDepth) {
            await ensureTreeDepth(plan, config);
        }
        config.initialRoot = computeRoot(config.treeDepth);
    }
}

async function deployIdentityManager(plan, config) {
    plan.add('Deploy WorldID Identity Manager Implementation', async () => {
        const spinner = ora('Deploying WorldID Identity Manager implementation...').start();
        const factory = new ContractFactory(
            WorldIDIdentityManagerImpl.abi,
            WorldIDIdentityManagerImpl.bytecode.object,
            config.wallet
        );
        const contract = await factory.deploy();
        spinner.text = `Waiting for the WorldID Identity Manager Implementation deployment transaction (address: ${contract.address})...`;
        await contract.deployTransaction.wait();
        config.identityManagerImplementationContractAddress = contract.address;
        spinner.succeed(`Deployed WorldID Identity Manager Implementation to ${contract.address}`);
    });
    plan.add('Deploy WorldID Identity Manager', async () => {
        // Encode the initializer function call.
        const spinner = ora(`Building initializer call...`).start();
        const iface = new Interface(WorldIDIdentityManagerImpl.abi);
        const callData = iface.encodeFunctionData('initialize', [
            config.initialRoot,
            config.verifierContractAddress,
        ]);

        // Deploy the proxy contract.
        spinner.text = `Deploying WorldID Identity Manager proxy...`;
        const factory = new ContractFactory(
            WorldIDIdentityManager.abi,
            WorldIDIdentityManager.bytecode.object,
            config.wallet
        );
        const contract = await factory.deploy(
            config.identityManagerImplementationContractAddress,
            callData
        );
        spinner.text = `Waiting for the WorldID Identity Manager deployment transaction (address: ${contract.address})...`;
        await contract.deployTransaction.wait();
        config.identityManagerContractAddress = contract.address;

        // Verify that the deployment went correctly.
        spinner.text = `Verifying correct deployment of the WorldID Identity Manager...`;
        // Note that here the contract is constructed with the ABI of the _delegate_, allowing us to
        // pretend that the proxy doesn't exist and yet still call through it.
        const contractWithAbi = new Contract(
            contract.address,
            WorldIDIdentityManagerImpl.abi,
            config.wallet
        );
        const latestRoot = await contractWithAbi.latestRoot();
        if (latestRoot instanceof BigNumber && latestRoot._hex === config.initialRoot) {
            // If we get the root back we know it's succeeded as if it isn't called through the
            // proxy this call will revert.
            spinner.succeed(`Deployed WorldID Identity Manager to ${contract.address}`);
        } else {
            spinner.fail(
                `Could not communicate with the WorldID Identity Manager at ${contract.address}`
            );
        }
    });
}

async function buildActionPlan(plan, config) {
    dotenv.config();

    config.privateKey = process.env.PRIVATE_KEY;
    if (!config.privateKey) {
        config.privateKey = await ask('Enter your private key: ');
    }

    config.rpcUrl = process.env.RPC_URL;
    if (!config.rpcUrl) {
        config.rpcUrl = await ask(`Enter RPC URL: (${DEFAULT_RPC_URL}) `);
    }
    if (!config.rpcUrl) {
        config.rpcUrl = DEFAULT_RPC_URL;
    }

    config.provider = new JsonRpcProvider(config.rpcUrl);
    config.wallet = new Wallet(config.privateKey, config.provider);

    await ensureVerifierDeployment(plan, config);
    await ensureInitialRoot(plan, config);
    await deployIdentityManager(plan, config);
}

async function main() {
    let plan = newPlan();
    let config = {};
    await buildActionPlan(plan, config);

    for (const item of plan.items) {
        console.log(item.label);
        await item.action(config);
    }
}

main().then(() => process.exit(0));
