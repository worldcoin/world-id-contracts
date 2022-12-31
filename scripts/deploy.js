import ora from 'ora'
import dotenv from 'dotenv'
import readline from 'readline'
import fs from 'fs'
import Semaphore from '../out/Semaphore.sol/Semaphore.json' assert { type: 'json' }
import { spawnSync } from 'child_process';
import solc from 'solc';
import { ContractFactory, Wallet, providers } from 'ethers';

const { JsonRpcProvider } = providers;

function ask(question, type) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    })

    return new Promise((resolve, reject) => {
        rl.question(question, input => {
            if (type === 'int' && input) {
                input = parseInt(input)
                if (isNaN(input)) {
                    reject('Invalid input')
                }
            }
            resolve(input)
            rl.close()
        })
    })
}

function newPlan() {
    let self = {
        items: [],
        add: function (label, action) {
            self.items.push({ label, action })
        }
    }
    return self;
}

async function downloadSemaphoreMtbBinary(plan, config) {
    config.mtbBinary = 'mtb/bin/mtb';
    plan.add('Download Semaphore-MTB binary', async () => { });
}

async function ensureMtbBinary(plan, config) {
    config.mtbBinary = process.env.MTB_BINARY;
    if (!config.mtbBinary) {
        if (fs.existsSync('mtb/bin/mtb')) {
            config.mtbBinary = 'mtb/bin/mtb'
            console.log('Using default Semaphore-MTB binary (mtb/bin/mtb)')
        }
    }
    if (!config.mtbBinary) {
        config.mtbBinary = await ask('Semaphore-MTB binary not found in the default location. Enter binary location, or leave empty to download it: ')
    }
    if (!config.mtbBinary) {
        await downloadSemaphoreMtbBinary(plan, config);
    }
}

async function generateKeys(plan, config) {
    config.treeDepth = process.env.TREE_DEPTH;
    if (!config.treeDepth) {
        config.treeDepth = await ask('Enter tree depth: (32) ', 'int')
    }
    if (!config.treeDepth) {
        config.treeDepth = 4;
    }

    config.batchSize = process.env.BATCH_SIZE;
    if (!config.batchSize) {
        config.batchSize = await ask('Enter batch size: (100) ', 'int')
    }
    if (!config.batchSize) {
        config.batchSize = 4;
    }
    plan.add('Setup Semaphore-MTB keys', async (config) => {
        const spinner = ora('Generating prover keys').start();
        fs.mkdirSync('mtb', { recursive: true });
        let result = spawnSync(config.mtbBinary, ['setup', '--tree-depth', config.treeDepth, '--batch-size', config.batchSize, '--output', config.keysFile], { stdio: 'inherit' });
        if (result.status != 0) {
            throw new Error('Failed to generate prover keys');
        }
        spinner.succeed('Prover keys generated');
    });
}

async function ensureKeysFile(plan, config) {
    config.keysFile = process.env.KEYS_FILE;
    if (!config.keysFile) {
        if (fs.existsSync('mtb/keys')) {
            config.keysFile = 'mtb/keys'
            console.log('Using default Semaphore-MTB keys file (mtb/keys)')
        }
    }
    if (!config.keysFile) {
        config.keysFile = await ask('Enter path to the prover/verifier keys file, or leave empty to set it up: ')
    }
    if (!config.keysFile) {
        config.keysFile = 'mtb/keys';
        await generateKeys(plan, config);
    }
}

async function generateVerifierContract(plan, config) {
    await ensureKeysFile(plan, config);
    plan.add('Generate Semaphore-MTB verifier contract', async () => {
        const spinner = ora('Generating verifier contract').start();
        fs.mkdirSync('mtb/contracts', { recursive: true });
        let result = spawnSync(config.mtbBinary, ['export-solidity', '--keys-file', config.keysFile, '--output', config.mtbVerifierContractFile], { stdio: 'inherit' });
        if (result.status != 0) {
            throw new Error('Failed to generate verifier contract');
        }
        spinner.succeed('Verifier contract generated');
    });
}

async function ensureVerifierContractFile(plan, config) {
    config.mtbVerifierContractFile = process.env.MTB_VERIFIER_CONTRACT_FILE;
    if (!config.mtbVerifierContractFile) {
        if (fs.existsSync('mtb/contracts/Verifier.sol')) {
            config.mtbVerifierContractFile = 'mtb/contracts/Verifier.sol'
            console.log('Using default Semaphore-MTB verifier contract file (mtb/contracts/Verifier.sol)')
        }
    }
    if (!config.mtbVerifierContractFile) {
        config.mtbVerifierContractFile = await ask('Enter path to the Semaphore-MTB verifier contract file, or leave empty to generate it: ')
    }
    if (!config.mtbVerifierContractFile) {
        await ensureMtbBinary(plan, config);
        config.mtbVerifierContractFile = 'mtb/contracts/Verifier.sol';
        await generateVerifierContract(plan, config);
    }
}

async function compileVerifierContract(plan, config) {
    plan.add('Compile Semaphore-MTB verifier contract', async (config) => {
        let input = {
            language: 'Solidity',
            sources: {
                'Verifier.sol': {
                    content: fs.readFileSync(config.mtbVerifierContractFile).toString()
                }
            },
            settings: {
                outputSelection: {
                    'Verifier.sol': {
                        'Verifier': ['evm.bytecode.object']
                    }
                }
            }
        };
        let output = solc.compile(JSON.stringify(input));
        fs.mkdirSync('mtb/contracts', { recursive: true });
        fs.writeFileSync(config.mtbVerifierContractOutFile, output);
    });
}

async function ensureVeirfierBytecode(plan, config) {
    config.mtbVerifierContractOutFile = process.env.VERIFIER_BYTECODE_FILE;
    if (!config.mtbVerifierContractOutFile) {
        if (fs.existsSync('mtb/contracts/Verifier.json')) {
            config.mtbVerifierContractOutFile = 'mtb/contracts/Verifier.json'
            console.log('Using existing Semaphore-MTB bytecode file (mtb/contracts/Verifier.json)')
        }
    }
    if (!config.mtbVerifierContractOutFile) {
        await ensureVerifierContractFile(plan, config);
        config.mtbVerifierContractOutFile = 'mtb/contracts/Verifier.json'
        await compileVerifierContract(plan, config);
    }
}

async function deployVerifierContract(plan, config) {
    plan.add('Deploy Semaphore-MTB verifier contract', async () => {
        const spinner = ora(`Deploying MTB Verifier contract...`).start();
        let verifierBytecode = JSON.parse(fs.readFileSync(config.mtbVerifierContractOutFile).toString());
        let factory = new ContractFactory([], verifierBytecode.contracts['Verifier.sol'].Verifier.evm.bytecode.object, config.wallet)
        let contract = await factory.deploy();
        spinner.text = `Waiting for MTB Verifier deploy transaction (address: ${contract.address})`;
        await contract.deployTransaction.wait();
        spinner.succeed(`Deployed MTB Verifier contract to ${contract.address}`);
        config.verifierContractAddress = contract.address;
    });
}

async function ensureVeirfierDeployment(plan, config) {
    config.verifierContractAddress = process.env.VERIFIER_CONTRACT_ADDRESS;
    if (!config.verifierContractAddress) {
        config.verifierContractAddress = await ask('Enter batch insert verifier contract address, or leave empty to deploy it: ');
    }
    if (!config.verifierContractAddress) {
        await ensureVeirfierBytecode(plan, config);
        await deployVerifierContract(plan, config);
    }
}


async function actionPlan(plan, config) {
    dotenv.config();

    config.privateKey = process.env.PRIVATE_KEY;
    if (!config.privateKey) {
        config.privateKey = await ask('Enter your private key: ')
    }

    config.rpcUrl = process.env.RPC_URL;
    if (!config.rpcUrl) {
        config.rpcUrl = await ask('Enter RPC URL: (localhost:8545) ')
    }
    if (!config.rpcUrl) {
        config.rpcUrl = 'http://localhost:8545'
    }

    config.provider = new JsonRpcProvider(config.rpcUrl);
    config.wallet = new Wallet(config.privateKey, config.provider);

    await ensureVeirfierDeployment(plan, config);

}

async function deploySemaphore(ibtAddress) {
    const spinner = ora(`Deploying Semaphore contract...`).start()
    let tx = await wallet.sendTransaction({
        data: Semaphore.bytecode.object.replace(/__\$\w*?\$__/g, ibtAddress.slice(2)),
    })
    spinner.text = `Waiting for Semaphore deploy transaction (tx: ${tx.hash})`
    tx = await tx.wait()
    spinner.succeed(`Deployed Semaphore contract to ${tx.contractAddress}`)

    return tx.contractAddress
}

async function main() {
    let plan = newPlan();
    let config = {};
    await actionPlan(plan, config);

    for (const item of plan.items) {
        console.log(item.label);
        await item.action(config);
    }
}

main().then(() => process.exit(0))
