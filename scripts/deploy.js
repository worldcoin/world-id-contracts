import fs from 'fs';
import https from 'https';
import readline from 'readline';
import { spawnSync } from 'child_process';

import dotenv from 'dotenv';
import ora from 'ora';
import { Command } from 'commander';

import solc from 'solc';
import { Contract, ContractFactory, providers, utils, Wallet } from 'ethers';
import { ErrorFragment, Interface } from 'ethers/lib/utils.js';
import { poseidon } from 'circomlibjs';
import IdentityManager from '../out/WorldIDIdentityManager.sol/WorldIDIdentityManager.json' assert { type: 'json' };
import IdentityManagerImpl from '../out/WorldIDIdentityManagerImplV1.sol/WorldIDIdentityManagerImplV1.json' assert { type: 'json' };
import UnimplementedTreeVerifier from '../out/UnimplementedTreeVerifier.sol/UnimplementedTreeVerifier.json' assert { type: 'json' };
import { default as SemaphoreVerifier } from '../out/SemaphoreVerifier.sol/SemaphoreVerifier.json' assert { type: 'json' };
import { default as SemaphorePairing } from '../out/Pairing.sol/Pairing.json' assert { type: 'json' };
import VerifierLookupTable from '../out/VerifierLookupTable.sol/VerifierLookupTable.json' assert { type: 'json' };
import Router from '../out/WorldIDRouter.sol/WorldIDRouter.json' assert { type: 'json' };
import RouterImpl from '../out/WorldIDRouterImplV1.sol/WorldIDRouterImplV1.json' assert { type: 'json' };
import { BigNumber } from '@ethersproject/bignumber';

const { JsonRpcProvider } = providers;

// === Constants ==================================================================================

const DEFAULT_RPC_URL = 'http://localhost:8545';
const MTB_RELEASES_URL = 'https://github.com/worldcoin/semaphore-mtb/releases/download';
const MTB_DIR = 'mtb';
const KEYS_PATH = MTB_DIR + '/keys';
const KEYS_META_PATH = MTB_DIR + '/keys_meta.json';
const MTB_BIN_DIR = MTB_DIR + '/bin';
const MTB_BIN_PATH = MTB_BIN_DIR + '/mtb';
const MTB_CONTRACTS_DIR = MTB_DIR + '/contracts';
const CONFIG_FILENAME = '.deploy-config.json';
const SOLIDITY_OUTPUT_DIR = 'out';
const EXTENSION_REGEX = /(\.sol$)|(\.json$)/;

// These are an arbitrary choice just for ease of development.
const DEFAULT_TREE_DEPTH = 32;
const DEFAULT_BATCH_SIZE = 3;
const MTB_VERSION = '1.0.2';
const VERIFIER_SOURCE_PATH = MTB_CONTRACTS_DIR + '/Verifier.sol';
const VERIFIER_ABI_PATH = MTB_CONTRACTS_DIR + '/Verifier.json';
const DEFAULT_IDENTITY_MANAGER_UPGRADE_CONTRACT_NAME = 'WorldIDIdentityManagerImplMock';
const DEFAULT_IDENTITY_MANAGER_UPGRADE_FUNCTION = 'initialize(uint32)';
const DEFAULT_ROUTER_UPGRADE_CONTRACT_NAME = 'WorldIDRouterImplMock';
const DEFAULT_ROUTER_UPGRADE_FUNCTION = 'initialize(uint32)';
const CONTRACT_SIZE_WARNING_THRESHOLD_BYTES = 18000;
const CONTRACT_SIZE_ERROR_THRESHOLD_BYTES = 24576;

// === Implementation =============================================================================

/**
 * Asks the user a question and returns the answer.
 *
 * @param {string} question the question contents.
 * @param {?string|undefined = undefined} type an optional type to parse the answer as. Currently
 *        only supports 'int' for decimal integers. and `bool` for booleans.
 * @returns a promise resolving to user's response
 */
function ask(question, type = undefined) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve, reject) => {
    rl.question(question, input => {
      if (type === 'int' && input) {
        input = parseInt(input.trim());
        if (isNaN(input)) {
          reject('Invalid input');
        }
      }
      if (type === 'bool') {
        if (!input) {
          input = undefined;
        } else {
          switch (input.trim()) {
            case 'y':
            case 'Y':
            case 'true':
            case 'True':
              input = true;
              break;
            case 'n':
            case 'N':
            case 'false':
            case 'False':
              input = false;
              break;
            default:
              reject('Invalid input');
              break;
          }
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
      if (response.statusCode === 302) {
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

// Function generates a warning or error depending on the contract bytecode size
// It is only approximation based on the bytecode (constructor + bytecode)
// Run forge build --sizes for stats about deployed bytecode size
// Max contract size is 24kb
// We set a warning threshold at 18kb
function checkContractSize(spinner, bytecode) {
  const size = bytecode.length / 2;
  if (size >= CONTRACT_SIZE_WARNING_THRESHOLD_BYTES && size < CONTRACT_SIZE_ERROR_THRESHOLD_BYTES)
    spinner.warn('Significant contract size : ' + size);
  else if (size >= CONTRACT_SIZE_ERROR_THRESHOLD_BYTES)
    spinner.fail('Contract size exceeds allowed maximum size: ' + size);
}

async function downloadSemaphoreMtbBinary(plan, config) {
  config.mtbBinary = MTB_BIN_PATH;
  if (process.platform === 'win32') {
    if (process.arch !== 'x64') {
      throw new Error('Unsupported platform');
    }
    config.os = 'windows';
    config.arch = 'amd64';
  } else if (process.platform === 'linux') {
    if (process.arch !== 'x64') {
      throw new Error('Unsupported platform');
    }
    config.os = 'linux';
    config.arch = 'amd64';
  } else if (process.platform === 'darwin') {
    config.os = 'darwin';
    config.arch = process.arch === 'arm64' ? 'arm64' : 'amd64';
  }
  plan.add('Download Semaphore-MTB binary', async config => {
    fs.mkdirSync(MTB_BIN_DIR, { recursive: true });
    const spinner = ora('Downloading Semaphore-MTB binary...').start();
    const url = `${MTB_RELEASES_URL}/${MTB_VERSION}/mtb-${config.os}-${config.arch}`;
    const response = await httpsGetWithRedirects(url);
    const done = new Promise((resolve, reject) => {
      const file = fs.createWriteStream(config.mtbBinary);
      response.pipe(file);

      file.on('finish', () => {
        file.close();
        resolve();
      });

      file.on('error', err => {
        fs.unlink(config.mtbBinary, () => reject(err));
      });
    });
    await done;
    if (config.os !== 'windows') {
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
    config.treeDepth = await ask(
      `Enter tree depth, where 16 <= depth <= 32: (${DEFAULT_TREE_DEPTH}) `,
      'int'
    );
  }
  if (!config.treeDepth) {
    config.treeDepth = DEFAULT_TREE_DEPTH;
  }
  if (config.treeDepth < 16) {
    console.warn('Depth less than 16 specified. Clamping depth to 16.');
    config.treeDepth = 16;
  }
  if (config.treeDepth > 32) {
    console.warn('Depth greater than 32 specified. Clamping depth to 32.');
    config.treeDepth = 32;
  }
}

async function getBatchSize(config) {
  if (!config.batchSize) {
    config.batchSize = process.env.BATCH_SIZE;
  }
  if (!config.batchSize) {
    config.batchSize = await ask(`Enter batch size: (${DEFAULT_BATCH_SIZE}) `, 'int');
  }
  if (!config.batchSize) {
    config.batchSize = DEFAULT_BATCH_SIZE;
  }
}

async function getVerifierLUTAddress(config, targetField, name) {
  if (!config[targetField]) {
    config[targetField] = process.env[`${targetField.toUpperCase()}_VERIFIER_LUT_ADDRESS`];
  }
  if (!config[targetField]) {
    config[targetField] = await ask(
      `Please provide the address of the ${name} verifier LUT (or leave blank to deploy): `
    );
  }
}

async function generateKeys(plan, config) {
  await ensureTreeDepth(plan, config);
  await getBatchSize(config);

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
    if (result.status !== 0) {
      throw new Error('Failed to generate prover keys');
    }
    const keysMeta = { batchSize: config.batchSize };
    fs.writeFileSync(KEYS_META_PATH, JSON.stringify(keysMeta));
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

async function shouldRegenerateVerifierFromScratch(plan, config) {
  if (!fs.existsSync(KEYS_META_PATH)) {
    return true;
  }
  const data = JSON.parse(fs.readFileSync(KEYS_META_PATH).toString());
  if (!data) {
    return true;
  }
  if (data.batchSize) {
    return data.batchSize !== config.batchSize;
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
    if (result.status !== 0) {
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
      console.log(`Using default Semaphore-MTB verifier contract file (${VERIFIER_SOURCE_PATH})`);
    }
  }
  if (!config.mtbVerifierContractFile) {
    config.mtbVerifierContractFile = await ask(
      'Enter path to the Semaphore-MTB verifier contract file matching your batch size, or leave empty to generate it: '
    );
  }
  if (!config.mtbVerifierContractFile) {
    await ensureMtbBinary(plan, config);
    config.mtbVerifierContractFile = VERIFIER_SOURCE_PATH;
    await generateVerifierContract(plan, config);
  }
}

async function compileVerifierContract(plan, _) {
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
      console.log(`Using existing Semaphore-MTB bytecode file (${VERIFIER_ABI_PATH})`);
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
    let bytecode = verifierBytecode.contracts['Verifier.sol'].Verifier.evm.bytecode.object;
    let factory = new ContractFactory([], bytecode, config.wallet);
    checkContractSize(spinner, bytecode);
    let contract = await factory.deploy();
    spinner.text = `Waiting for MTB Verifier deploy transaction (address: ${contract.address})...`;
    await contract.deployTransaction.wait();
    spinner.succeed(`Deployed MTB Verifier contract to ${contract.address}`);
    config.verifierContractAddress = contract.address;
  });
}

async function ensureUnimplementedTreeVerifierDeployment(plan, config) {
  plan.add('Deploy Unimplemented Tree Verifier', async () => {
    const spinner = ora('Deploying Unimplemented Tree Verifier contract...').start();
    let bytecode = UnimplementedTreeVerifier.bytecode.object;
    const factory = new ContractFactory(UnimplementedTreeVerifier.abi, bytecode, config.wallet);
    checkContractSize(spinner, bytecode);
    const contract = await factory.deploy();
    spinner.text = `Waiting for verifier deploy transaction (address: ${contract.address})...`;
    await contract.deployTransaction.wait();
    spinner.succeed(`Deployed Unimplemented Tree Verifier contract to ${contract.address}`);
    config.unimplementedTreeVerifierContractAddress = contract.address;
  });
}

// Deploying libraries, manual linking
//
// In case you encounter a compilation error that looks something like this
//   { ... reason: 'invalid bytecode', code: 'INVALID_ARGUMENT', argument: 'bytecode', ... }
// or figured out that your code or 3rd party code uses a library
// follow instructions below
//
// - In the problematic bytecode find a substring indicating a placeholder for library address that's
//   a 34 character prefix of the hex encoding of the keccak256 hash of the fully qualified library name
//   between __$ and $__
//   E.g. __$a0b3f842b95cabff7722bd983061aec5b3$__
// - Compile and deploy the library. Save the addrsss it was deployed under!
// - Compile the code that previously cause problem
// - In the bytecode manually replace placeholder with the address of library
// - Deploy the bytecode
//
// References
// - https://docs.soliditylang.org/en/v0.8.19/using-the-compiler.html#library-linking

async function ensureSemaphoreVerifierDeployment(plan, config) {
  plan.add('Deploy Semaphore Pairing Library', async () => {
    const spinner = ora('Deploying Semaphore pairing library...').start();
    const factory = new ContractFactory(
      SemaphorePairing.abi,
      SemaphorePairing.bytecode.object,
      config.wallet
    );
    const contract = await factory.deploy();
    spinner.text = `Waiting for pairing library deploy transaction (address: ${contract.address})...`;
    await contract.deployTransaction.wait();
    spinner.succeed(`Deployed Pairing Library to ${contract.address}`);
    config.semaphorePairingLibraryAddress = contract.address;
  });
  plan.add('Deploy Semaphore Verifier Contract', async () => {
    const spinner = ora('Deploying Semaphore Verifier contract...').start();
    const pairingPointer = '__$a0b3f842b95cabff7722bd983061aec5b3$__';
    const pairingLibAddressWithout0x = config.semaphorePairingLibraryAddress.substring(2);
    const newBytecode = SemaphoreVerifier.bytecode.object.replaceAll(
      pairingPointer,
      pairingLibAddressWithout0x
    );
    checkContractSize(spinner, newBytecode);
    const factory = new ContractFactory(SemaphorePairing.abi, newBytecode, config.wallet);
    const contract = await factory.deploy();
    spinner.text = `Waiting for Semaphore verifier deploy transaction (address: ${contract.address})...`;
    await contract.deployTransaction.wait();
    spinner.succeed(`Deployed Semaphore Verifier contract to ${contract.address}`);
    config.semaphoreVerifierContractAddress = contract.address;
  });
}

async function ensureVerifierDeployment(plan, config) {
  if (!config.verifierContractAddress) {
    config.verifierContractAddress = process.env.VERIFIER_CONTRACT_ADDRESS;
  }
  if (!config.verifierContractAddress) {
    config.verifierContractAddress = await ask(
      'Enter verifier contract address, or leave empty to deploy it: '
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

  return '0x0' + result.toString(16);
}

async function ensureInitialRoot(plan, config) {
  if (!config.initialRoot) {
    config.initialRoot = process.env.INITIAL_ROOT;
  }
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

async function deployRouter(plan, config) {
  if (config.enableRouter) {
    if (!config.routerContractAddress) {
      plan.add('Deploy the WorldID Router Implementation', async () => {
        const spinner = ora('Deploying WorldID Router implementation...').start();
        const factory = new ContractFactory(
          RouterImpl.abi,
          RouterImpl.bytecode.object,
          config.wallet
        );
        const contract = await factory.deploy();
        spinner.text = `Waiting for the WorldID Router implementation deployment transaction (address: ${contract.address})...`;
        await contract.deployTransaction.wait();
        config.routerImplementationContractAddress = contract.address;
        spinner.succeed(`Deployed WorldID Router Implementation to ${contract.address}`);
      });
      plan.add('Deploy the WorldID Router', async () => {
        // Build the initializer function call.
        const spinner = ora('Building initializer call...').start();
        const iface = new Interface(RouterImpl.abi);
        if (!config.routerInitialRoute) {
          spinner.fail('No identity manager address available');
          return;
        }
        spinner.text = `Using deployed identity manager at ${config.identityManagerContractAddress} as target for group 0...`;
        const callData = iface.encodeFunctionData('initialize', [config.routerInitialRoute]);

        // Deploy the proxy contract.
        spinner.text = 'Deploying the WorldID Router proxy...';
        let bytecode = Router.bytecode.object;
        checkContractSize(spinner, bytecode);
        const factory = new ContractFactory(Router.abi, bytecode, config.wallet);
        const contract = await factory.deploy(config.routerImplementationContractAddress, callData);
        spinner.text = `Waiting for the WorldID Router deployment transaction (address: ${contract.address})...`;
        await contract.deployTransaction.wait();
        config.routerContractAddress = contract.address;

        // Verify that the deployment went correctly.
        spinner.text = 'Verifying correct deployment of the WorldID Router...';
        const contractWithAbi = new Contract(contract.address, RouterImpl.abi, config.wallet);
        const routeForGroupZero = await contractWithAbi.routeFor(0);
        if (routeForGroupZero === config.routerInitialRoute) {
          spinner.succeed(`Deployed WorldID Router to ${contract.address}`);
        } else {
          spinner.fail(`Could not communicate with the WorldID Router at ${contract.address}`);
        }
      });
    } else {
      plan.add('Associating Identity Manager with Router', async () => {
        const spinner = ora('Associating manager address with router...').start();
        const contractWithAbi = new Contract(
          config.routerContractAddress,
          RouterImpl.abi,
          config.wallet
        );

        if (!config.groupNumber) {
          spinner.text = 'Obtaining next available group from router...';
          const nextGroup = await contractWithAbi.groupCount();
          if (!nextGroup instanceof BigNumber) {
            spinner.fail(
              `Could not get the next available group from the router at ${config.routerContractAddress}`
            );
            process.exit(1);
          }
          config.groupNumber = nextGroup._hex;
        }

        spinner.text = `Adding the WorldID Identity Manager for Group ${config.groupNumber}...`;
        await contractWithAbi.addGroup(config.groupNumber, config.identityManagerContractAddress);
        spinner.succeed(
          `Associated Identity Manager at address ${config.identityManagerContractAddress} with group ${config.groupNumber}`
        );
      });
    }
  }
}

/** Deploys the verifier lookup table using the specified `targetVerifierAddress` for the configured
 * batch size.
 *
 * @param {Object} plan The plan to add deployment actions to.
 * @param {Object} config The configuration object to use for the deployment.
 * @param {string} name The name of the verifier LUT being deployed.
 * @param {string} targetVerifierAddressField The field in the config object to read the target
 *        verifier address from.
 * @param {string} targetFieldName The name of the field in `config` to write the deployed address
 *        into.
 * @returns {Promise<void>} Configuration is written to the `config` object.
 */
async function deployVerifierLookupTable(
  plan,
  config,
  name,
  targetVerifierAddressField,
  targetFieldName
) {
  plan.add(`Deploy ${name} Verifier Lookup Table`, async () => {
    const spinner = ora(`Deploying ${name.toLowerCase()} verifier lookup table...`).start();
    const factory = new ContractFactory(
      VerifierLookupTable.abi,
      VerifierLookupTable.bytecode.object,
      config.wallet
    );
    const targetAddress = config[targetVerifierAddressField];
    const contract = await factory.deploy(config.batchSize, targetAddress);
    spinner.text = `Waiting for the verifier lookup table deployment transaction (address: ${contract.address})...`;
    await contract.deployTransaction.wait();
    config[targetFieldName] = contract.address;
    spinner.succeed(`Deployed ${name} Verifier Lookup Table to ${contract.address}`);
  });
}

async function addVerifierToLUT(plan, config) {
  plan.add('Add Verifier to Lookup Table', async () => {
    const spinner = ora(
      `Adding verifier to LUT at ${config.lookupTableAddress} for batch size ${config.batchSize}...`
    ).start();
    const contractWithAbi = new Contract(
      config.lookupTableAddress,
      VerifierLookupTable.abi,
      config.wallet
    );
    try {
      contractWithAbi.addVerifier(config.batchSize, config.targetVerifierAddress);
      spinner.succeed(
        `Added verifier at ${config.targetVerifierAddress} to LUT at ${config.lookupTableAddress} for batch size ${config.batchSize}`
      );
    } catch (e) {
      const body = JSON.parse(e.error.error.body);
      const decodedError = decodeContractError(contractWithAbi.interface, body.error.data);
      if (decodedError.name === 'VerifierExists') {
        spinner.fail(`The batch size of ${config.batchSize} already has an associated verifier`);
      } else if (decodedError === 'BatchTooLarge') {
        spinner.fail(`The batch size of ${config.batchSize} is too large`);
      } else {
        spinner.fail(`Could not add a verifier for the group size of ${config.batchSize}`);
        console.error(e);
      }
    }
  });
}

async function updateVerifierInLUT(plan, config) {
  plan.add('Update Verifier in Lookup Table', async () => {
    const spinner = ora(
      `Updating verifier in LUT at ${config.lookupTableAddress} for batch size of ${config.batchSize}...`
    ).start();
    const contractWithAbi = new Contract(
      config.lookupTableAddress,
      VerifierLookupTable.abi,
      config.wallet
    );
    try {
      contractWithAbi.updateVerifier(config.batchSize, config.targetVerifierAddress);
      spinner.succeed(
        `Updated batch size of ${config.batchSize} in LUT at ${config.lookupTableAddress} to use verifier at ${config.targetVerifierAddress}`
      );
    } catch (e) {
      const body = JSON.parse(e.error.error.body);
      const decodedError = decodeContractError(contractWithAbi.interface, body.error.data);
      if (decodedError.name === 'BatchTooLarge') {
        spinner.fail(`The batch size of ${config.batchSize} is too large`);
      } else {
        spinner.fail(`Could not update the verifier for the group size of ${config.batchSize}`);
        console.error(e);
      }
    }
  });
}

async function disableVerifierInLUT(plan, config) {
  plan.add('Disable Verifier in Lookup Table', async () => {
    const spinner = ora(
      `Disabling verifier in LUT at ${config.lookupTableAddress} for batch size of ${config.batchSize}`
    ).start();
    const contractWithAbi = new Contract(
      config.lookupTableAddress,
      VerifierLookupTable.abi,
      config.wallet
    );
    try {
      contractWithAbi.disableVerifier(config.batchSize);
      spinner.succeed(
        `Disabled verifier for batch size of ${config.batchSize} in LUT at ${config.lookupTableAddress}`
      );
    } catch (e) {
      const body = JSON.parse(e.error.error.body);
      const decodedError = decodeContractError(contractWithAbi.interface, body.error.data);
      if (decodedError.name === 'BatchTooLarge') {
        spinner.fail(`The batch size of ${config.batchSize} is too large`);
      } else {
        spinner.fail(`Could not update the verifier for the group size of ${config.batchSize}`);
        console.error(e);
      }
    }
  });
}

async function deployIdentityManager(plan, config, insertLUTTargetField, updateLUTTargetField) {
  plan.add('Deploy WorldID Identity Manager Implementation', async () => {
    const spinner = ora('Deploying WorldID Identity Manager implementation...').start();
    let bytecode = IdentityManagerImpl.bytecode.object;
    checkContractSize(spinner, bytecode);
    const factory = new ContractFactory(IdentityManagerImpl.abi, bytecode, config.wallet);
    const contract = await factory.deploy();
    spinner.text = `Waiting for the WorldID Identity Manager Implementation deployment transaction (address: ${contract.address})...`;
    await contract.deployTransaction.wait();
    config.identityManagerImplementationContractAddress = contract.address;
    spinner.succeed(`Deployed WorldID Identity Manager Implementation to ${contract.address}`);
  });
  plan.add('Deploy WorldID Identity Manager', async () => {
    // Encode the initializer function call.
    const spinner = ora(`Building initializer call...`).start();
    const iface = new Interface(IdentityManagerImpl.abi);
    const processedStateBridgeAddress = utils.getAddress(config.stateBridgeContractAddress);
    const callData = iface.encodeFunctionData('initialize', [
      config.treeDepth,
      config.initialRoot,
      config[insertLUTTargetField],
      config[updateLUTTargetField],
      config.semaphoreVerifierContractAddress,
      config.enableStateBridge,
      processedStateBridgeAddress,
    ]);

    // Deploy the proxy contract.
    spinner.text = `Deploying WorldID Identity Manager proxy...`;
    const factory = new ContractFactory(
      IdentityManager.abi,
      IdentityManager.bytecode.object,
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
    const contractWithAbi = new Contract(contract.address, IdentityManagerImpl.abi, config.wallet);
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

async function planRouteAdd(plan, config) {
  plan.add('Add route in WorldID Router', async () => {
    const spinner = ora('Building route add call...').start();
    const contractWithAbi = new Contract(
      config.routerContractAddress,
      RouterImpl.abi,
      config.wallet
    );
    spinner.text = `Attempting to add group ${config.routerGroupNumber} to router at ${config.routerContractAddress}...`;
    try {
      await contractWithAbi.addGroup(config.routerGroupNumber, config.routerTargetAddress);
      spinner.succeed(
        `Added group ${config.routerGroupNumber} to route to ${config.routerTargetAddress}`
      );
    } catch (e) {
      const body = JSON.parse(e.error.error.body);
      const decodedError = decodeContractError(contractWithAbi.interface, body.error.data);
      if (decodedError.name === 'DuplicateGroup') {
        spinner.fail(
          `Group ${config.routerGroupNumber} already exists in the router at ${config.routerContractAddress}`
        );
      } else if (decodedError.name === 'NonSequentialGroup') {
        spinner.fail(
          `Group ${config.routerGroupNumber} is not the next available group in the router at ${config.routerContractAddress}`
        );
      } else {
        spinner.fail(
          `Could not add group ${config.routerGroupNumber} to the router at ${config.routerContractAddress}`
        );
        console.error(e);
      }
    }
  });
}

async function planRouteUpdate(plan, config) {
  plan.add('Update route in WorldID Router', async () => {
    const spinner = ora('Building route update call...').start();
    const contractWithAbi = new Contract(
      config.routerContractAddress,
      RouterImpl.abi,
      config.wallet
    );
    spinner.text = `Updating group ${config.routerGroupNumber} to route to ${config.routerTargetAddress}...`;
    try {
      await contractWithAbi.updateGroup(config.routerGroupNumber, config.routerTargetAddress);
      spinner.succeed(
        `Updated group ${config.routerGroupNumber} to route to ${config.routerTargetAddress}`
      );
    } catch (e) {
      const body = JSON.parse(e.error.error.body);
      const decodedError = decodeContractError(contractWithAbi.interface, body.error.data);
      if (decodedError.name === 'NoSuchGroup') {
        spinner.fail(
          `Unable to update: group ${config.routerGroupNumber} does not exist in the router at ${config.routerContractAddress}`
        );
      } else {
        spinner.fail(
          `Could not update group ${config.routerGroupNumber} in the router at ${config.routerContractAddress}`
        );
        console.error(e);
      }
    }
  });
}

async function planRouteDisable(plan, config) {
  plan.add('Disable route in WorldID Router', async () => {
    const spinner = ora('Building route disable call...').start();
    const contractWithAbi = new Contract(
      config.routerContractAddress,
      RouterImpl.abi,
      config.wallet
    );
    spinner.text = `Disabling group ${config.routerGroupNumber}...`;
    try {
      await contractWithAbi.disableGroup(config.routerGroupNumber);
      spinner.succeed(`Disabled group ${config.routerGroupNumber}`);
    } catch (e) {
      const body = JSON.parse(e.error.error.body);
      const decodedError = decodeContractError(contractWithAbi.interface, body.error.data);
      if (decodedError.name === 'NoSuchGroup') {
        spinner.fail(
          `Unable to disable group ${config.routerGroupNumber}: it does not exist in the router at ${config.routerContractAddress}`
        );
      } else {
        spinner.fail(
          `Could not disable group ${config.routerGroupNumber} in the router at ${config.routerContractAddress}`
        );
        console.error(e);
      }
    }
  });
}

/** Decodes a contract error given a contract interface.
 *
 * Note that if the returned error is not part of the interface of the contract then the decoding
 * will fail. Note that errors defined in superclasses are considered to be part of the interface of
 * the contract. It will, however, decode string-encoded reverts.
 *
 * Note that errors in library code are not considered to be part of the interface. This means that
 * any strongly-typed errors that libraries revert with will not be decoded successfully here.
 *
 * @param {Interface} iface The interface that the call is decoding errors from.
 * @param {String} errorData The string containing the ABI-encoded return data.
 * @returns {{name: string, sig: string, payload: Object, error: ErrorFragment}|undefined} The
 *          decoded error if decoding is successful, otherwise `undefined`.
 */
function decodeContractError(iface, errorData) {
  const availableErrors = iface.errors;

  // The string revert is not part of the errors object by default, so we have to manually construct
  // it and add it to the object to allow decoding these.
  availableErrors['Error(string)'] = {
    type: 'error',
    name: 'Error',
    inputs: [
      {
        name: 'message',
        type: 'string',
        indexed: null,
        components: null,
        arrayLength: null,
        arrayChildren: null,
        baseType: 'string',
        _isParamType: true,
      },
    ],
    _isFragment: true,
  };

  for (let error of Object.entries(availableErrors)) {
    let errorSignature = error[0];
    let errorFragment = availableErrors[errorSignature];

    try {
      const decoded = iface.decodeErrorResult(errorFragment, errorData);
      const name = errorSignature.replace(/\(.*\)$/, '');
      return { name: name, sig: errorSignature, error: errorFragment, payload: decoded };
    } catch (e) {}
  }

  return undefined;
}

async function getPrivateKey(config) {
  if (!config.privateKey) {
    config.privateKey = process.env.PRIVATE_KEY;
  }
  if (!config.privateKey) {
    config.privateKey = await ask('Enter your private key: ');
  }
}

async function getRpcUrl(config) {
  if (!config.rpcUrl) {
    config.rpcUrl = process.env.RPC_URL;
  }
  if (!config.rpcUrl) {
    config.rpcUrl = await ask(`Enter RPC URL: (${DEFAULT_RPC_URL}) `);
  }
  if (!config.rpcUrl) {
    config.rpcUrl = DEFAULT_RPC_URL;
  }
}

async function getProvider(config) {
  config.provider = new JsonRpcProvider(config.rpcUrl);
}

async function getWallet(config) {
  config.wallet = new Wallet(config.privateKey, config.provider);
}

async function getEnableStateBridge(config) {
  if (config.enableStateBridge === undefined) {
    config.enableStateBridge = process.env.ENABLE_STATE_BRIDGE;
  }
  if (config.enableStateBridge === undefined) {
    config.enableStateBridge = await ask(`Enable State Bridge? [y/N] `, 'bool');
  }
  if (config.enableStateBridge === undefined) {
    config.enableStateBridge = false;
  }
}

/** Gets the address for the WorldID router to be modified at.
 *
 * @param {Object} config The configuration for the script.
 * @returns {Promise<void>} The route configuration is written into the `config` object.
 */
async function getRouterAddress(config) {
  if (!config.routerContractAddress) {
    config.routerContractAddress = process.env.ROUTER_CONTRACT_ADDRESS;
  }

  if (!config.routerContractAddress) {
    config.routerContractAddress = await ask('Please provide the address of the router: ');
  }

  if (!config.routerContractAddress) {
    console.error('No router address provided.');
    process.exit(1);
  }
}

async function getLookupTableAddress(config) {
  if (!config.lookupTableAddress) {
    config.lookupTableAddress = process.env.LOOKUP_TABLE_ADDRESS;
  }

  if (!config.lookupTableAddress) {
    config.lookupTableAddress = await ask(
      'Enter the address for the lookup table to add a verifier to: '
    );
  }

  if (!config.lookupTableAddress) {
    console.error('No address provided for the lookup table but one is required.');
    process.exit();
  }
}

async function getTargetVerifierAddress(config) {
  if (!config.targetVerifierAddress) {
    config.targetVerifierAddress = process.env.TARGET_VERIFIER_ADDRESS;
  }

  if (!config.targetVerifierAddress) {
    config.targetVerifierAddress = await ask(
      'Enter the address for the verifier to add to the lookup table: '
    );
  }

  if (!config.targetVerifierAddress) {
    console.error('No address provided for the target verifier but one is required.');
    process.exit();
  }
}

/** Gets the configuration required to modify a route in the WorldID router.
 *
 * @param {Object} config The configuration for the script.
 * @param {?boolean = false} isDisable Whether or not it is getting routing configuration to disable
 *        a route or not.
 * @returns {Promise<void>} The route configuration is written into the `config` object
 */
async function getRouteConfiguration(config, isDisable = false) {
  if (!config.routerGroupNumber) {
    config.routerGroupNumber = process.env.ROUTER_UPDATE_GROUP_NUMBER;
  }

  if (!config.routerGroupNumber) {
    config.routerGroupNumber = await ask(
      'Which group should be modified in the router? ',
      'number'
    );
  }

  if (!config.routerGroupNumber) {
    console.error('No group number to modify provided but such a number is required.');
    process.exit(1);
  }

  if (!isDisable) {
    if (!config.routerTargetAddress) {
      config.routerTargetAddress = process.env.ROUTER_UPDATE_TARGET_ADDRESS;
    }

    if (!config.routerTargetAddress) {
      config.routerTargetAddress = await ask(
        `Please provide the new target address for the router: `
      );
    }

    if (!config.routerTargetAddress) {
      console.error('No target for the update provided but such one is required.');
      process.exit(1);
    }
  }
}

async function getRouterJointDeployConfiguration(config) {
  if (config.enableRouter === undefined) {
    config.enableRouter = process.env.ENABLE_ROUTER;
  }

  if (config.enableRouter === undefined) {
    config.enableRouter = await ask('Enable WorldID Router? [y/N] ', 'bool');
  }

  if (config.enableRouter === undefined) {
    config.enableRouter = false;
  }

  if (config.enableRouter) {
    if (!config.routerContractAddress) {
      config.routerContractAddress = process.env.ROUTER_CONTRACT_ADDRESS;
    }

    if (!config.routerContractAddress) {
      config.routerContractAddress = await ask(
        'Enter the router address or leave blank to deploy it: '
      );
    }

    if (config.routerContractAddress) {
      config.groupNumber = await ask(
        'Enter the group number to bind the contract to (leave blank to pick next available): ',
        'number'
      );
    }
  }
}

async function getStateBridgeAddress(config) {
  const stateBridgeDefault = config.wallet.address;
  if (config.enableStateBridge) {
    if (!config.stateBridgeContractAddress) {
      config.stateBridgeContractAddress = process.env.STATE_BRIDGE_CONTRACT_ADDRESS;
    }
    if (!config.stateBridgeContractAddress) {
      config.stateBridgeContractAddress = await ask(
        `Enter state bridge contract address (${stateBridgeDefault}): `
      );
    }
    if (!config.stateBridgeContractAddress) {
      config.stateBridgeContractAddress = stateBridgeDefault;
    }
  } else {
    config.stateBridgeContractAddress = stateBridgeDefault;
  }
}

/** Gets the target address for making an upgrade.
 *
 * @param {Object} config The process configuration.
 * @param {string|undefined} defaultAddress The default address to use if none is provided.
 * @returns {Promise<void>} The results are written to the `config`.
 */
async function getUpgradeTargetAddress(config, defaultAddress) {
  if (!config.upgradeTargetAddress) {
    config.upgradeTargetAddress = process.env.UPGRADE_TARGET_ADDRESS;
  }
  if (!config.upgradeTargetAddress) {
    const message = defaultAddress ? ` (${defaultAddress})` : '';
    config.upgradeTargetAddress = await ask(`Enter upgrade target address${message}: `);
  }
  if (!config.upgradeTargetAddress) {
    config.upgradeTargetAddress = defaultAddress;
  }
  if (!config.upgradeTargetAddress) {
    console.error('Unable to detect upgrade target address. Aborting...');
    process.exit(1);
  }
}

/** Gets the initial target address for group 0 in the router.
 *
 * @param {Object} config The process configuration.
 * @returns {Promise<void>} The results are written to `config`.
 */
async function getRouterInitialRoute(config) {
  if (!config.routerInitialRoute) {
    config.routerInitialRoute = process.env.ROUTER_INITIAL_ROUTE;
  }
  if (!config.routerInitialRoute) {
    config.routerInitialRoute = await ask(
      `Enter the target address for the route for group 0 in the router: `
    );
  }
  if (!config.routerInitialRoute) {
    console.error('No initial route for group 0 provided. Aborting...');
    process.exit(1);
  }
}

/** Gets the ABI data from the implementation contract.
 *
 * @param {Object} config The configuration object.
 * @param {string} nameField The name of the field in the configuration object in which to store the
 *        implementation contract name.
 * @param {string} abiField The name of the field in the configuration object in which to store the
 *        implementation contract ABI.
 * @param {string} defaultContract The name of the default contract to use.
 * @returns {Promise<void>}
 */
async function getImplContractAbi(config, nameField, abiField, defaultContract) {
  let answer = '';
  if (!config[nameField]) {
    answer = await ask(
      `Please provide the name of the implementation contract to use for (${defaultContract}): `
    );
  }
  const spinner = ora('Obtaining contract ABI').start();

  if (!answer) {
    if (config[nameField]) {
      answer = config[nameField];
    } else {
      answer = defaultContract;
    }
  }

  answer = answer.replace(EXTENSION_REGEX, '');
  const path = `${SOLIDITY_OUTPUT_DIR}/${answer}.sol/${answer}.json`;
  spinner.text = `Loading ABI from ${path}`;

  try {
    config[abiField] = JSON.parse(fs.readFileSync(path).toString());
    let maybeAbi = config[abiField];
    if (!maybeAbi) {
      spinner.fail(`Failed to load ABI at ${path}`);
      process.exit(1);
    }
    if (
      !maybeAbi.abi ||
      !maybeAbi.bytecode ||
      !maybeAbi.deployedBytecode ||
      !maybeAbi.methodIdentifiers ||
      !maybeAbi.metadata
    ) {
      spinner.fail(`Failed to load ABI at ${path}`);
      process.exit(1);
    }
    spinner.succeed(`Loaded contract ABI from ${path}`);
  } catch {
    spinner.fail(`Failed to load ABI at ${path}`);
    process.exit(1);
  }

  config[nameField] = answer;
}

/** Encodes a function call for sending to chain.
 *
 * @param {Object} config The configuration object.
 * @param {string} targetAbiField The name of the field in the configuration object from which to
 *        read the target contract ABI.
 * @param {string} callInfoField The name of the field in the configuration object in which to store
 *        the call data.
 * @param {string} defaultFunction The default signature to use when building a call if none
 *        specified.
 * @returns {Promise<void>}
 */
async function buildCall(config, targetAbiField, callInfoField, defaultFunction) {
  let upgradeCall = config[callInfoField];
  if (!upgradeCall) {
    upgradeCall = {};
  }

  let answer = '';
  if (!upgradeCall.functionSpec) {
    answer = await ask(`Provide the signature of the function (${defaultFunction}): `);
  }

  let spinner = ora('Building upgrade call').start();

  if (!answer) {
    if (upgradeCall.functionSpec) {
      answer = upgradeCall.functionSpec;
    } else {
      answer = defaultFunction;
    }
  }

  const iface = new Interface(config[targetAbiField].abi);

  const specifiedFunction = iface.functions[answer.replace(/ +/, '')];
  if (!specifiedFunction) {
    spinner.fail(`No function with signature ${answer} found`);
    process.exit(0);
  }

  // All done, so write to config.
  upgradeCall.functionSpec = answer;
  spinner.succeed(`Using upgrade call with signature ${answer}`);

  const formatParamSpec = paramSpec => {
    return `${paramSpec.name} : ${paramSpec.type} = ${paramSpec.jsValue}`;
  };

  if (
    !upgradeCall.paramValues ||
    upgradeCall.paramValues.length !== specifiedFunction.inputs.length
  ) {
    const paramValues = [];
    for (const input of specifiedFunction.inputs) {
      const param = `\`${input.name} : ${input.type}\``;
      let answer = await ask(`Please enter value for parameter ${param}: `);
      answer = answer.trim();
      const spinner = ora(`Obtaining parameter value for ${param}`).start();
      if (answer.startsWith('config.')) {
        answer = eval(answer);
      }
      const encodedValue = iface._abiCoder.encode([input.type], [answer]);
      const paramValue = {
        name: input.name,
        type: input.type,
        jsValue: answer,
        solValue: encodedValue,
      };
      paramValues.push(paramValue);
      spinner.succeed(`Obtained value \`${formatParamSpec(paramValue)}\` for ${param}`);
    }
    upgradeCall.paramValues = paramValues;
  } else {
    const spinner = ora(`Using existing parameter values`).start();
    let display = '';
    upgradeCall.paramValues.forEach(paramSpec => {
      display = display + `${paramSpec.name} : ${paramSpec.type} = ${paramSpec.jsValue}, `;
    });
    display = display.trim();
    spinner.succeed(`Using parameter values \`${display}\` for upgrade call`);
  }

  config[callInfoField] = upgradeCall;
}

async function planDeployUpgrade(plan, config, abiFieldName, callInfoFieldName) {
  plan.add('Deploy Upgraded Implementation', async () => {
    const spinner = ora('Deploying Implementation Upgrade...').start();
    const factory = new ContractFactory(
      config[abiFieldName].abi,
      config[abiFieldName].bytecode.object,
      config.wallet
    );
    const contract = await factory.deploy();
    spinner.text = `Waiting for the implementation upgrade deployment transaction (address ${contract.address})`;
    await contract.deployTransaction.wait();
    config.upgradedImplementationContractAddress = contract.address;
    spinner.succeed(`Deployed upgraded implementation to ${contract.address}`);
  });
  plan.add('Upgrade Target Contract', async () => {
    // Encode the new initializer function call.
    const spinner = ora('Upgrading the selected contract...').start();
    const iface = new Interface(config[abiFieldName].abi);
    const callData = iface.encodeFunctionData(
      config[callInfoFieldName].functionSpec,
      config[callInfoFieldName].paramValues.map(p => p.solValue)
    );

    // Make the call.
    spinner.text = `Upgrading target implementation (address: ${config.identityManagerContractAddress})`;
    const contractWithAbi = new Contract(
      config.upgradeTargetAddress,
      IdentityManagerImpl.abi,
      config.wallet
    );
    try {
      await contractWithAbi.upgradeToAndCall(
        config.upgradedImplementationContractAddress,
        callData
      );

      spinner.succeed(
        `Upgraded target implementation to ${config.upgradedImplementationContractAddress}`
      );
    } catch (e) {
      const message = JSON.parse(e.error.error.body).error.message;
      const errString = message ? message : e.message;
      spinner.fail(`Unable to upgrade the target implementation: ${errString}`);
      process.exit(1);
    }
  });
}

async function loadConfiguration(useConfig) {
  if (!useConfig) {
    return {};
  }
  let answer = await ask(`Do you want to load configuration from prior runs? [Y/n]: `, 'bool');
  const spinner = ora('Configuration Loading').start();
  if (answer === undefined) {
    answer = true;
  }
  if (answer) {
    if (!fs.existsSync(CONFIG_FILENAME)) {
      spinner.warn('Configuration load requested but no configuration available: continuing');
      return {};
    }
    try {
      const fileContents = JSON.parse(fs.readFileSync(CONFIG_FILENAME).toString());
      if (fileContents) {
        spinner.succeed('Configuration loaded');
        return fileContents;
      } else {
        spinner.warn('Unable to parse configuration: deleting and continuing');
        fs.rmSync(CONFIG_FILENAME);
        return {};
      }
    } catch {
      spinner.warn('Unable to parse configuration: deleting and continuing');
      fs.rmSync(CONFIG_FILENAME);
      return {};
    }
  } else {
    spinner.succeed('Configuration not loaded');
    return {};
  }
}

async function saveConfiguration(config) {
  const oldData = (() => {
    try {
      return JSON.parse(fs.readFileSync(CONFIG_FILENAME).toString());
    } catch {
      return {};
    }
  })();

  const data = JSON.stringify({ ...oldData, ...config });
  fs.writeFileSync(CONFIG_FILENAME, data);
}

async function buildIdentityManagerDeploymentActionPlan(plan, config) {
  dotenv.config();

  const insertLUTTargetField = 'insertVerifierLUTAddress';
  const updateLUTTargetField = 'updateVerifierLUTAddress';

  await getPrivateKey(config);
  await getRpcUrl(config);
  await getProvider(config);
  await getWallet(config);
  await getEnableStateBridge(config);
  await getStateBridgeAddress(config);
  await getRouterJointDeployConfiguration(config);
  await getVerifierLUTAddress(config, insertLUTTargetField, 'insert');
  await getVerifierLUTAddress(config, updateLUTTargetField, 'update');
  await getBatchSize(config);

  if (await shouldRegenerateVerifierFromScratch(plan, config)) {
    console.warn(
      `Requested batch size of ${config.batchSize} does not match keys file. Keys will be regenerated.`
    );
    config.mtbVerifierContractOutFile = undefined;
    config.mtbVerifierContractFile = undefined;
    config.keysFile = undefined;
    fs.rmSync(VERIFIER_SOURCE_PATH, { force: true });
    fs.rmSync(VERIFIER_ABI_PATH, { force: true });
    fs.rmSync(KEYS_PATH, { force: true });
    fs.rmSync(KEYS_META_PATH, { force: true });
  }

  await ensureVerifierDeployment(plan, config);
  await ensureUnimplementedTreeVerifierDeployment(plan, config);
  await ensureSemaphoreVerifierDeployment(plan, config);
  await ensureInitialRoot(plan, config);
  if (!config[insertLUTTargetField]) {
    await deployVerifierLookupTable(
      plan,
      config,
      'Registration',
      'verifierContractAddress',
      insertLUTTargetField
    );
  }
  if (!config[updateLUTTargetField]) {
    await deployVerifierLookupTable(
      plan,
      config,
      'Update',
      'unimplementedTreeVerifierContractAddress',
      updateLUTTargetField
    );
  }
  await deployIdentityManager(plan, config, insertLUTTargetField, updateLUTTargetField);
  config.routerInitialRoute = config.identityManagerContractAddress;
  await deployRouter(plan, config);
}

async function buildRouterDeploymentActionPlan(plan, config) {
  dotenv.config();

  await getPrivateKey(config);
  await getRpcUrl(config);
  await getProvider(config);
  await getWallet(config);
  config.enableRouter = true;
  await getRouterInitialRoute(config);

  await deployRouter(plan, config);
}

async function buildIdentityManagerUpgradeActionPlan(plan, config) {
  await buildUpgradeActionPlan(
    plan,
    config,
    config.identityManagerContractAddress,
    'upgradeIdentityManagerImplementationAbi',
    'upgradeIdentityManagerCallInfo',
    'upgradeIdentityManagerImplementationName',
    DEFAULT_IDENTITY_MANAGER_UPGRADE_CONTRACT_NAME,
    DEFAULT_IDENTITY_MANAGER_UPGRADE_FUNCTION
  );
}

async function buildRouterUpgradeActionPlan(plan, config) {
  await buildUpgradeActionPlan(
    plan,
    config,
    config.routerTargetAddress,
    'upgradeRouterImplementationAbi',
    'upgradeRouterCallInfo',
    'upgradeRouterImplementationName',
    DEFAULT_ROUTER_UPGRADE_CONTRACT_NAME,
    DEFAULT_ROUTER_UPGRADE_FUNCTION
  );
}

/** Builds an action plan for upgrading an upgradable proxy-based contract that has already been
 *  deployed to the blockchain.
 *
 * @param {Object} plan The action plan to insert actions into.
 * @param {Object} config The configuration object for the script.
 * @param {string|undefined} targetAddressDefault The default target address to be used. Need not be
 *        specified.
 * @param {string} abiFieldName The name of the field in the `config` object in which to store the
 *        target contract ABI.
 * @param {string} callInfoFieldName The name of the field in the `config` object in which to store
 *        the upgrade function call data.
 * @param {string} nameFieldName The name of the field in the `config` object in which to store the
 *        name of the implementation to be upgraded to.
 * @param {string} defaultContractName The name of the default upgrade target contract.
 * @param {string} defaultUpgradeFunction The name of the default upgrade function to call when
 *        upgrading.
 * @returns {Promise<void>} Nothing
 */
async function buildUpgradeActionPlan(
  plan,
  config,
  targetAddressDefault,
  abiFieldName,
  callInfoFieldName,
  nameFieldName,
  defaultContractName,
  defaultUpgradeFunction
) {
  dotenv.config();

  await getPrivateKey(config);
  await getRpcUrl(config);
  await getProvider(config);
  await getWallet(config);
  await getUpgradeTargetAddress(config, targetAddressDefault);

  await getImplContractAbi(config, nameFieldName, abiFieldName, defaultContractName);
  await buildCall(config, abiFieldName, callInfoFieldName, defaultUpgradeFunction);
  await planDeployUpgrade(plan, config, abiFieldName, callInfoFieldName);
}

async function buildRouteAddActionPlan(plan, config) {
  dotenv.config();

  await getPrivateKey(config);
  await getRpcUrl(config);
  await getProvider(config);
  await getWallet(config);
  await getRouterAddress(config);
  await getRouteConfiguration(config, false);

  await planRouteAdd(plan, config);
}

async function buildRouteUpdateActionPlan(plan, config) {
  dotenv.config();

  await getPrivateKey(config);
  await getRpcUrl(config);
  await getProvider(config);
  await getWallet(config);
  await getRouterAddress(config);
  await getRouteConfiguration(config, false);

  await planRouteUpdate(plan, config);
}

async function buildRouteDisableActionPlan(plan, config) {
  dotenv.config();

  await getPrivateKey(config);
  await getRpcUrl(config);
  await getProvider(config);
  await getWallet(config);
  await getRouterAddress(config);
  await getRouteConfiguration(config, true);

  await planRouteDisable(plan, config);
}

/** Builds a verifier action plan of the specified type.
 *
 * @param {Object} plan The plan, containing actions to execute.
 * @param {Object} config The configuration for the process.
 * @param {'add' | 'update' | 'disable'} type The type of action plan to build.
 * @returns {Promise<void>}
 */
async function buildVerifierActionPlan(plan, config, type) {
  dotenv.config();

  await getPrivateKey(config);
  await getRpcUrl(config);
  await getProvider(config);
  await getWallet(config);
  await getLookupTableAddress(config);
  await getBatchSize(config);
  if (type !== 'disable') {
    await getTargetVerifierAddress(config);
  }

  if (type === 'add') {
    await addVerifierToLUT(plan, config);
  } else if (type === 'update') {
    await updateVerifierInLUT(plan, config);
  } else if (type === 'disable') {
    await disableVerifierInLUT(plan, config);
  } else {
    console.error(`INTERNAL ERROR: Unrecognised type of verifier action plan: ${type}`);
    process.exit(0);
  }
}

/** Builds a plan using the provided function and then executes the plan.
 *
 * @param {(plan: Object, config: Object) => Promise<void>} planner The function that performs the
 *        planning process.
 * @param {Object} config The configuration object for the plan.
 * @returns {Promise<void>}
 */
async function buildAndRunPlan(planner, config) {
  let plan = newPlan();
  await planner(plan, config);

  for (const item of plan.items) {
    console.log(item.label);
    await item.action(config);
  }
}

async function main() {
  const program = new Command();

  program
    .name('deploy')
    .description('A CLI interface for deploying the WorldID identity manager during development.')
    .option('--no-config', 'Do not use any existing configuration.');

  program
    .command('deploy')
    .description('Interactively deploys a new version of the WorldID identity manager.')
    .action(async () => {
      const options = program.opts();
      let config = await loadConfiguration(options.config);
      await buildAndRunPlan(buildIdentityManagerDeploymentActionPlan, config);
      await saveConfiguration(config);
    });

  program
    .command('upgrade')
    .description('Interactively upgrades the deployed WorldID identity manager.')
    .action(async () => {
      const options = program.opts();
      let config = await loadConfiguration(options.config);
      await buildAndRunPlan(buildIdentityManagerUpgradeActionPlan, config);
      await saveConfiguration(config);
    });

  program
    .command('deploy-router')
    .description('Interactively deploys the WorldID router.')
    .action(async () => {
      const options = program.opts();
      let config = await loadConfiguration(options.config);
      await buildAndRunPlan(buildRouterDeploymentActionPlan, config);
      await saveConfiguration(config);
    });

  program
    .command('upgrade-router')
    .description('Interactively upgrades the WorldID router.')
    .action(async () => {
      const options = program.opts();
      let config = await loadConfiguration(options.config);
      await buildAndRunPlan(buildRouterUpgradeActionPlan, config);
      await saveConfiguration(config);
    });

  program
    .command('route-add')
    .description('Interactively adds a route for a group to the WorldID router.')
    .action(async () => {
      const options = program.opts();
      let config = await loadConfiguration(options.config);
      await buildAndRunPlan(buildRouteAddActionPlan, config);
      await saveConfiguration(config);
    });

  program
    .command('route-update')
    .description('Interactively updates the route in the router.')
    .action(async () => {
      const options = program.opts();
      let config = await loadConfiguration(options.config);
      await buildAndRunPlan(buildRouteUpdateActionPlan, config);
      await saveConfiguration(config);
    });

  program
    .command('route-disable')
    .description('Interactively disables a group in the router.')
    .action(async () => {
      const options = program.opts();
      let config = await loadConfiguration(options.config);
      await buildAndRunPlan(buildRouteDisableActionPlan, config);
      await saveConfiguration(config);
    });

  program
    .command('verifier-add')
    .description('Adds a verifier to the specified verifier lookup table.')
    .action(async () => {
      const options = program.opts();
      let config = await loadConfiguration(options.config);
      await buildAndRunPlan((plan, config) => buildVerifierActionPlan(plan, config, 'add'), config);
      await saveConfiguration(config);
    });

  program
    .command('verifier-update')
    .description('Updates the verifier for a given batch size.')
    .action(async () => {
      const options = program.opts();
      let config = await loadConfiguration(options.config);
      await buildAndRunPlan(
        (plan, config) => buildVerifierActionPlan(plan, config, 'update'),
        config
      );
      await saveConfiguration(config);
    });

  program
    .command('verifier-disable')
    .description('Updates the verifier for a given batch size.')
    .action(async () => {
      const options = program.opts();
      let config = await loadConfiguration(options.config);
      await buildAndRunPlan(
        (plan, config) => buildVerifierActionPlan(plan, config, 'disable'),
        config
      );
      await saveConfiguration(config);
    });

  await program.parseAsync();
}

main().then(() => process.exit(0));
