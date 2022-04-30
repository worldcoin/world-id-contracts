import { keccak256, pack } from '@ethersproject/solidity'
import { ZkIdentity, Strategy } from '@zk-kit/identity'
import { defaultAbiCoder as abi } from '@ethersproject/abi'
import { Semaphore, generateMerkleProof } from '@zk-kit/protocols'
import verificationKey from '../../../lib/semaphore/build/snark/verification_key.json' assert { type: 'json' }

function hashBytes(signal) {
    return BigInt(keccak256(['bytes'], [signal])) >> BigInt(8)
}

function generateSemaphoreWitness(
    identityTrapdoor,
    identityNullifier,
    merkleProof,
    externalNullifier,
    signal
) {
    return {
        identityNullifier: identityNullifier,
        identityTrapdoor: identityTrapdoor,
        treePathIndices: merkleProof.pathIndices,
        treeSiblings: merkleProof.siblings,
        externalNullifier: externalNullifier,
        signalHash: hashBytes(signal),
    }
}

async function main(airdropAddress, receiverAddress) {
    const identity = new ZkIdentity(Strategy.MESSAGE, 'test-identity')
    const identityCommitment = identity.genIdentityCommitment()

    const witness = generateSemaphoreWitness(
        identity.getTrapdoor(),
        identity.getNullifier(),
        generateMerkleProof(20, BigInt(0), [identityCommitment], identityCommitment),
        hashBytes(pack(['address', 'uint256'], [airdropAddress, 1])),
        receiverAddress
    )

    const { proof, publicSignals } = await Semaphore.genProof(
        witness,
        './lib/semaphore/build/snark/semaphore.wasm',
        './lib/semaphore/build/snark/semaphore_final.zkey'
    )

    await Semaphore.verifyProof(verificationKey, { proof, publicSignals }).then(isValid => {
        if (!isValid) console.error('Generated proof failed to verify')
    })

    process.stdout.write(
        abi.encode(
            ['uint256', 'uint256[8]'],
            [publicSignals.nullifierHash, Semaphore.packToSolidityProof(proof)]
        )
    )
}

main(...process.argv.splice(2)).then(() => process.exit(0))
