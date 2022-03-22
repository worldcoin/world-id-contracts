const { keccak256 } = require('@ethersproject/solidity')
const { ZkIdentity, Strategy } = require('@zk-kit/identity')
const { defaultAbiCoder: abi } = require('@ethersproject/abi')
const { Semaphore, generateMerkleProof } = require('@zk-kit/protocols')
const verificationKey = require('../../../lib/semaphore/build/snark/verification_key.json')

function genSignalHash(signal) {
	return BigInt(keccak256(['bytes32'], [signal])) >> BigInt(8)
}

function generateSemaphoreWitness(identityTrapdoor, identityNullifier, merkleProof, externalNullifier, signal) {
	return {
		identityNullifier: identityNullifier,
		identityTrapdoor: identityTrapdoor,
		treePathIndices: merkleProof.pathIndices,
		treeSiblings: merkleProof.siblings,
		externalNullifier: externalNullifier,
		signalHash: genSignalHash(signal),
	}
}

async function main(airdropAddress, receiverAddress) {
	const identity = new ZkIdentity(Strategy.MESSAGE, 'test-identity')
	const identityCommitment = identity.genIdentityCommitment()

	const witness = generateSemaphoreWitness(
		identity.getTrapdoor(),
		identity.getNullifier(),
		generateMerkleProof(20, BigInt(0), [identityCommitment], identityCommitment),
		airdropAddress,
		abi.encode(['address'], [receiverAddress])
	)

	const { proof, publicSignals } = await Semaphore.genProof(
		witness,
		'./lib/semaphore/build/snark/semaphore.wasm',
		'./lib/semaphore/build/snark/semaphore_final.zkey'
	)

	// Exit if the generated proof isn't valid, since Foundry won't show logs on failure.
	await Semaphore.verifyProof(verificationKey, { proof, publicSignals }).then(isValid => {
		if (!isValid) process.exit(1)
	})

	process.stdout.write(
		abi.encode(['uint256', 'uint256[8]'], [publicSignals.nullifierHash, Semaphore.packToSolidityProof(proof)])
	)
}

main(...process.argv.splice(2)).then(() => process.exit(0))
