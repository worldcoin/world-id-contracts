const { ZkIdentity, Strategy } = require("@zk-kit/identity");
const { defaultAbiCoder: abi } = require("@ethersproject/abi");
const { Semaphore, generateMerkleProof } = require("@zk-kit/protocols");

async function main() {
	const airdropAddress = process.argv[2];
	const signal = abi.encode(["address"], [process.argv[3]]);

	const identity = new ZkIdentity(Strategy.MESSAGE, "test-identity");
	const identityCommitments = [
		BigInt(1),
		identity.genIdentityCommitment(),
		BigInt(2),
	];

	const merkleProof = generateMerkleProof(
		20,
		BigInt(0),
		identityCommitments,
		1
	);

	const witness = Semaphore.genWitness(
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
		"./src/test/scripts/vendor/semaphore.zkey"
	);

	process.stdout.write(
		abi.encode(
			["uint256", "uint256[8]"],
			[nullifierHash, Semaphore.packToSolidityProof(proof)]
		)
	);
}

main().then(() => process.exit(0));
