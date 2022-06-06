import ora from 'ora'
import dotenv from 'dotenv'
import readline from 'readline'
import { Wallet } from '@ethersproject/wallet'
import { poseidon_gencontract } from 'circomlibjs'
import { JsonRpcProvider } from '@ethersproject/providers'
import Semaphore from '../out/Semaphore.sol/Semaphore.json' assert { type: 'json' }
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

async function main(poseidonAddress, ibtAddress) {
    if (!poseidonAddress) poseidonAddress = await deployPoseidon()
    if (!ibtAddress) poseidonAddress = await deployIBT(poseidonAddress)

    await deploySemaphore(ibtAddress)
}

main(...process.argv.splice(2)).then(() => process.exit(0))
