const { ZkIdentity, Strategy } = require("@zk-kit/identity");
const { defaultAbiCoder: abi } = require("@ethersproject/abi");

function main() {
	const identity = new ZkIdentity(Strategy.MESSAGE, "test-identity");

	process.stdout.write(
		abi.encode(["uint256"], [identity.genIdentityCommitment()])
	);
}

main();
