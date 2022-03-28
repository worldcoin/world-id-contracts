import { ZkIdentity, Strategy } from '@zk-kit/identity'
import { defaultAbiCoder as abi } from '@ethersproject/abi'

function main() {
    const identity = new ZkIdentity(Strategy.MESSAGE, 'test-identity')

    process.stdout.write(abi.encode(['uint256'], [identity.genIdentityCommitment()]))
}

main()
