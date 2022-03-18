const fs = require("fs");
const { ethers } = require("ethers");
const { poseidonContract } = require("circomlibjs");
const { defaultAbiCoder: abi, Interface } = require("@ethersproject/abi");

function main() {
	const poseidonT3Bytecode = poseidonContract.createCode(2);
	const poseidonT3Abi = poseidonContract.generateABI(2);

	fs.writeFileSync(
		"./out/Hashes.sol/PoseidonT3.json",
		JSON.stringify({
			abi: poseidonT3Abi,
			bytecode: {
				object: poseidonT3Bytecode,
				sourceMap: "",
				linkReferences: {},
			},
			deployedBytecode: {
				object: poseidonT3Bytecode,
				sourceMap: "",
				linkReferences: {},
			},
		})
	);
}

main();
