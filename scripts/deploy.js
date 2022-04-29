import ora from 'ora'
import dotenv from 'dotenv'
import readline from 'readline'
import { Wallet } from '@ethersproject/wallet'
import { poseidon_gencontract } from 'circomlibjs'
import { hexlify, concat } from '@ethersproject/bytes'
import { JsonRpcProvider } from '@ethersproject/providers'
import { defaultAbiCoder as abi } from '@ethersproject/abi'
import Semaphore from '../out/Semaphore.sol/Semaphore.json' assert { type: 'json' }
import SemaphoreAirdrop from '../out/SemaphoreAirdrop.sol/SemaphoreAirdrop.json' assert { type: 'json' }
import SemaphoreMultiAirdrop from '../out/SemaphoreMultiAirdrop.sol/SemaphoreMultiAirdrop.json' assert { type: 'json' }
import IncrementalBinaryTree from '../out/IncrementalBinaryTree.sol/IncrementalBinaryTree.json' assert { type: 'json' }
dotenv.config()

let validConfig = true
if (process.env.RPC_URL === undefined) {
    console.log('Missing RPC_URL')
    validConfig = false
}
if (process.env.PRIVATE_KEY === undefined) {
    console.log('Missing PRIVATE_KEY')
    validConfig = false
}
if (!validConfig) process.exit(1)

const provider = new JsonRpcProvider(process.env.RPC_URL)
const wallet = new Wallet(process.env.PRIVATE_KEY, provider)

const ask = async question => {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    })

    return new Promise(resolve => {
        rl.question(question, input => {
            resolve(input)
            rl.close()
        })
    })
}

async function deployPoseidon() {
    const spinner = ora(`Deploying Poseidon library...`).start()
    let tx = await wallet.sendTransaction({ data: poseidon_gencontract.createCode(2) })
    spinner.text = `Waiting for Poseidon deploy transaction (tx: ${tx.hash})`
    tx = await tx.wait()
    spinner.succeed(`Deployed Poseidon library to ${tx.contractAddress}`)

    return tx.contractAddress
}

async function deployIBT(poseidonAddress) {
    const spinner = ora(`Deploying IncrementalBinaryTree library...`).start()
    let tx = await wallet.sendTransaction({
        data: IncrementalBinaryTree.bytecode.object.replace(
            /__\$\w*?\$__/g,
            poseidonAddress.slice(2)
        ),
    })
    spinner.text = `Waiting for IncrementalBinaryTree deploy transaction (tx: ${tx.hash})`
    tx = await tx.wait()
    spinner.succeed(`Deployed IncrementalBinaryTree library to ${tx.contractAddress}`)

    return tx.contractAddress
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

async function deployAirdrop(semaphoreAddress) {
    const [groupId, erc20Address, holderAddress, airdropAmount] = [
        await ask('Semaphore group id: '),
        await ask('ERC20 address: '),
        await ask('ERC20 holder address: '),
        await ask('Amount to airdrop: '),
    ]

    const spinner = ora(`Deploying SemaphoreAirdrop contract...`).start()

    let tx = await wallet.sendTransaction({
        data: hexlify(
            concat([
                SemaphoreAirdrop.bytecode.object,
                abi.encode(SemaphoreAirdrop.abi[0].inputs, [
                    semaphoreAddress,
                    groupId,
                    erc20Address,
                    holderAddress,
                    airdropAmount,
                ]),
            ])
        ),
    })
    spinner.text = `Waiting for SemaphoreAirdrop deploy transaction (tx: ${tx.hash})`
    tx = await tx.wait()
    spinner.succeed(`Deployed SemaphoreAirdrop contract to ${tx.contractAddress}`)

    return tx.contractAddress
}

async function deployMultiAirdrop(semaphoreAddress) {
    const spinner = ora(`Deploying SemaphoreMultiAirdrop contract...`).start()

    let tx = await wallet.sendTransaction({
        data: hexlify(
            concat([
                SemaphoreMultiAirdrop.bytecode.object,
                abi.encode(SemaphoreMultiAirdrop.abi[0].inputs, [semaphoreAddress]),
            ])
        ),
    })
    spinner.text = `Waiting for SemaphoreMultiAirdrop deploy transaction (tx: ${tx.hash})`
    tx = await tx.wait()
    spinner.succeed(`Deployed SemaphoreMultiAirdrop contract to ${tx.contractAddress}`)

    return tx.contractAddress
}

async function main(poseidonAddress, ibtAddress, semaphoreAddress) {
    if (!poseidonAddress) poseidonAddress = await deployPoseidon()
    if (!ibtAddress) poseidonAddress = await deployIBT(poseidonAddress)
    if (!semaphoreAddress) semaphoreAddress = await deploySemaphore(ibtAddress)

    const option = await ask('Deploy SemaphoreAirdrop (1) or SemaphoreMultiAirdrop (2)?: ').then(
        answer => answer.trim()
    )

    switch (option) {
        case '1':
            await deployAirdrop(semaphoreAddress)
            break
        case '2':
            await deployMultiAirdrop(semaphoreAddress)
            break

        default:
            console.log('Please enter either 1 or 2. Exiting...')
            process.exit(1)
            break
    }
}

main(...process.argv.splice(2)).then(() => process.exit(0))
