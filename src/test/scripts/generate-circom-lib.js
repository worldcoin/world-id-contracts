import fs from 'fs'
import { poseidon_gencontract } from 'circomlibjs'

// Circom doesn't provide a Solidity implementation of the Poseidon library, and instead expects
// you to generate one at runtime. To make this system work with Foundry, we first compile
// the interface included in Semaphore, then inject the bytecode on the cache file.
function main() {
    const poseidonT3Bytecode = poseidon_gencontract.createCode(2)
    const poseidonT3Abi = poseidon_gencontract.generateABI(2)

    fs.writeFileSync(
        './out/Hashes.sol/PoseidonT3.json',
        JSON.stringify({
            abi: poseidonT3Abi,
            bytecode: {
                object: poseidonT3Bytecode,
                sourceMap: '',
                linkReferences: {},
            },
            deployedBytecode: {
                object: poseidonT3Bytecode,
                sourceMap: '',
                linkReferences: {},
            },
        })
    )

    console.log('Poseidon library injected.')
}

main()
