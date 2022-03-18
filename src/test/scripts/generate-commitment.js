const ethers = require("ethers");
const { ZkIdentity, Strategy } = require("@zk-kit/identity");

function main() {
	const identity = new ZkIdentity(Strategy.MESSAGE, "test-identity");

	process.stdout.write(
		ethers.utils.defaultAbiCoder.encode(
			["uint256"],
			[identity.genIdentityCommitment()]
		)
	);
}

main();
