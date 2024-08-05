// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "forge-std/Script.sol";
import "../src/WorldIDRouter.sol";
import "../src/WorldIDRouterImplV1.sol";
import "../src/WorldIDIdentityManager.sol";
import "../src/WorldIDIdentityManagerImplV1.sol";
import "../src/WorldIDIdentityManagerImplV2.sol";
import "../src/SemaphoreVerifier.sol";

import {Verifier as InsertionB10} from "../src/verifiers/insertion/b10.sol";
import {Verifier as InsertionB100} from "../src/verifiers/insertion/b100.sol";
import {Verifier as InsertionB600} from "../src/verifiers/insertion/b600.sol";
import {Verifier as InsertionB1200} from "../src/verifiers/insertion/b1200.sol";

import {Verifier as DeletionB10} from "../src/verifiers/deletion/b10.sol";
import {Verifier as DeletionB100} from "../src/verifiers/deletion/b100.sol";

contract Deploy is Script {
    uint8 constant TREE_DEPTH = 30;
    uint256 constant INITIAL_ROOT =
        0x918D46BF52D98B034413F4A1A1C41594E7A7A3F6AE08CB43D1A2A230E1959EF;

    address semaphoreVerifier = address(0);

    address batchInsertionVerifiers = address(0);
    address batchDeletionVerifiers = address(0);

    function run() external returns (address, address) {
        console.log("Deploying WorldIDRouter, WorldIDOrb");

        WorldIDIdentityManager worldIDOrb = deployWorldID(INITIAL_ROOT);
        console.log("WorldIDOrb:", address(worldIDOrb));

        WorldIDRouter router = deployWorldIDRouter(IWorldID(address(worldIDOrb)));
        console.log("WorldIDRouter:", address(router));

        // Add WorldIDOrb to the router again for backwards compatibility
        // a lot of services assume it's at group id 1
        updateGroup(address(router), 1, address(worldIDOrb));

        return (address(router), address(worldIDOrb));
    }

    function deployWorldID(uint256 _initalRoot) public returns (WorldIDIdentityManager) {
        VerifierLookupTable batchInsertionVerifiers_ = deployInsertionVerifiers();
        VerifierLookupTable batchUpdateVerifiers = deployVerifierLookupTable();
        VerifierLookupTable batchDeletionVerifiers_ = deployDeletionVerifiers();

        SemaphoreVerifier semaphoreVerifier_ = deploySemaphoreVerifier();

        beginBroadcast();
        // Encode:
        // 'initialize(
        //    uint8 _treeDepth,
        //    uint256 initialRoot,
        //    address _batchInsertionVerifiers,
        //    address _batchUpdateVerifiers,
        //    address _semaphoreVerifier
        //  )'
        bytes memory initializeCall = abi.encodeWithSignature(
            "initialize(uint8,uint256,address,address,address)",
            TREE_DEPTH,
            _initalRoot,
            batchInsertionVerifiers_,
            batchUpdateVerifiers,
            semaphoreVerifier_
        );

        // Encode:
        // 'initializeV2(VerifierLookupTable _batchDeletionVerifiers)'
        bytes memory initializeV2Call =
            abi.encodeWithSignature("initializeV2(address)", batchDeletionVerifiers_);

        WorldIDIdentityManagerImplV1 impl1 = new WorldIDIdentityManagerImplV1();
        WorldIDIdentityManagerImplV2 impl2 = new WorldIDIdentityManagerImplV2();

        WorldIDIdentityManager worldID = new WorldIDIdentityManager(address(impl1), initializeCall);

        // Recast to access api
        WorldIDIdentityManagerImplV1 worldIDImplV1 = WorldIDIdentityManagerImplV1(address(worldID));
        worldIDImplV1.upgradeToAndCall(address(impl2), initializeV2Call);

        vm.stopBroadcast();

        return worldID;
    }

    function deployWorldIDRouter(IWorldID initialGroupIdentityManager)
        public
        returns (WorldIDRouter router)
    {
        beginBroadcast();

        // Encode:
        // 'initialize(IWorldID initialGroupIdentityManager)'
        bytes memory initializeCall =
            abi.encodeWithSignature("initialize(address)", address(initialGroupIdentityManager));

        WorldIDRouterImplV1 impl = new WorldIDRouterImplV1();
        router = new WorldIDRouter(address(impl), initializeCall);

        vm.stopBroadcast();

        return router;
    }

    function deployVerifierLookupTable() public returns (VerifierLookupTable lut) {
        beginBroadcast();

        lut = new VerifierLookupTable();

        vm.stopBroadcast();

        return lut;
    }

    function deploySemaphoreVerifier() public returns (SemaphoreVerifier) {
        if (semaphoreVerifier == address(0)) {
            beginBroadcast();

            SemaphoreVerifier verifier = new SemaphoreVerifier();
            semaphoreVerifier = address(verifier);

            vm.stopBroadcast();
        }

        return SemaphoreVerifier(semaphoreVerifier);
    }

    function deployInsertionVerifiers() public returns (VerifierLookupTable lut) {
        if (batchInsertionVerifiers == address(0)) {
            lut = deployVerifierLookupTable();
            batchInsertionVerifiers = address(lut);

            beginBroadcast();

            lut.addVerifier(10, ITreeVerifier(address(new InsertionB10())));
            lut.addVerifier(100, ITreeVerifier(address(new InsertionB100())));
            lut.addVerifier(600, ITreeVerifier(address(new InsertionB600())));
            lut.addVerifier(1200, ITreeVerifier(address(new InsertionB1200())));

            vm.stopBroadcast();
        }

        return VerifierLookupTable(batchInsertionVerifiers);
    }

    function deployDeletionVerifiers() public returns (VerifierLookupTable lut) {
        if (batchDeletionVerifiers == address(0)) {
            lut = deployVerifierLookupTable();
            batchDeletionVerifiers = address(lut);

            beginBroadcast();

            lut.addVerifier(10, ITreeVerifier(address(new DeletionB10())));
            lut.addVerifier(100, ITreeVerifier(address(new DeletionB100())));

            vm.stopBroadcast();
        }

        return VerifierLookupTable(batchDeletionVerifiers);
    }

    function updateGroup(address router, uint256 groupNumber, address worldID) public {
        WorldIDRouterImplV1 routerImpl = WorldIDRouterImplV1(router);

        beginBroadcast();

        uint256 groupCount = routerImpl.groupCount();
        if (groupCount == groupNumber) {
            routerImpl.addGroup(IWorldID(worldID));
        } else if (groupCount < groupNumber) {
            routerImpl.updateGroup(groupNumber, IWorldID(worldID));
        } else {
            revert("Cannot update group number - group must be added first");
        }

        vm.stopBroadcast();
    }

    function beginBroadcast() internal {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
    }
}
