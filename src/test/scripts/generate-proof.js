const { keccak256 } = require("@ethersproject/solidity");
const { ZkIdentity, Strategy } = require("@zk-kit/identity");
const { defaultAbiCoder: abi } = require("@ethersproject/abi");
const { Semaphore, generateMerkleProof } = require("@zk-kit/protocols");

function genSignalHash(signal) {
	return BigInt(keccak256(["bytes32"], [signal])) >> BigInt(8);
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
		signalHash: genSignalHash(signal),
	};
}

async function main() {
	const airdropAddress = process.argv[2];
	const signal = abi.encode(["address"], [process.argv[3]]);

	const identity = new ZkIdentity(Strategy.MESSAGE, "test-identity");
	const identityCommitment = identity.genIdentityCommitment();

	const merkleProof = generateMerkleProof(
		20,
		BigInt(0),
		[identityCommitment, BigInt(1)],
		identityCommitment
	);

	const witness = generateSemaphoreWitness(
		identity.getTrapdoor(),
		identity.getNullifier(),
		merkleProof,
		airdropAddress,
		signal
	);

	const {
		proof,
		publicSignals: { nullifierHash },
	} = await Semaphore.genProof(
		witness,
		"./src/test/scripts/vendor/semaphore.wasm",
		"./src/test/scripts/vendor/semaphore_final.zkey"
	);

	process.stdout.write(
		abi.encode(
			["uint256", "uint256[8]"],
			[nullifierHash, Semaphore.packToSolidityProof(proof)]
		)
	);
}

main().then(() => process.exit(0));
