// Deploys the settlement stack to a local chain (anvil) and writes the
// deployment manifest the node and the wallet read.
//
//   anvil --chain-id 31337 &
//   forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 \
//        --broadcast --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
//
// The genesis leaves come from the SAME proof run as the block vectors
// (block_genesis.json, emitted by the prover export), so the first block the
// node settles applies cleanly against this deployment.
//
// Writes contracts/deployments/local.json: { verifier, pool, deployer, chainId }.
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {WhirVerifier} from "../src/verifier/WhirVerifier.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";

contract Deploy is Script {
    function run() external {
        // GENESIS_FILE overrides the genesis source: the node e2e deploys
        // with the node's own demo genesis (node genesis --out ...), which
        // differs from the prover-vector genesis. The pool enforces
        // rootBefore == currentRoot, so the deployment must start at exactly
        // the tree the block was witnessed against.
        string memory genesis_path = vm.envOr("GENESIS_FILE", string("test/vectors/block_genesis.json"));
        string memory genesis = vm.readFile(genesis_path);
        bytes32[] memory leaves = vm.parseJsonBytes32Array(genesis, ".genesis_leaves");
        require(leaves.length > 0, "genesis leaves required");

        // The broadcast context comes from the CLI (--private-key or
        // --unlocked --sender); msg.sender inside run() is that account.
        address deployer = msg.sender;
        vm.startBroadcast();
        WhirVerifier verifier = new WhirVerifier();
        // The nullifier root: bytes32(0) makes ShieldedPool compute the empty
        // sparse-tree root itself; the genesis file may pin one explicitly.
        bytes32 nullifierRoot = bytes32(0);
        ShieldedPool pool = new ShieldedPool(verifier, deployer, leaves, nullifierRoot);
        vm.stopBroadcast();

        string memory manifest = string.concat(
            "{\n",
            '  "verifier": "', vm.toString(address(verifier)), '",\n',
            '  "pool": "', vm.toString(address(pool)), '",\n',
            '  "deployer": "', vm.toString(deployer), '",\n',
            '  "chainId": ', vm.toString(block.chainid), "\n",
            "}\n");
        vm.createDir("deployments", true);
        vm.writeFile("deployments/local.json", manifest);
        console.log("verifier", address(verifier));
        console.log("pool", address(pool));
        console.log("genesis leaves", leaves.length);
    }
}
