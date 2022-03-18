const ethers = require("ethers");
const { ZkIdentity, Strategy } = require("@zk-kit/identity");
const { Semaphore, generateMerkleProof } = require("@zk-kit/protocols");

async function main() {
	const airdropAddress = process.argv[2];
	const signal = Buffer.from(process.argv[3].slice(2), "hex").toString("utf-8");

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
		ethers.utils.defaultAbiCoder.encode(
			["uint256", "uint256[8]"],
			[nullifierHash, Semaphore.packToSolidityProof(proof)]
		)
	);
}

main().then(() => process.exit(0));
