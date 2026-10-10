// Deploys the settlement stack to a local chain (anvil) and writes the
// deployment manifest the node and the wallet read.
//
//   anvil --chain-id 31337 &
//   forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 \
//        --broadcast --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
//
// The genesis root comes from the SAME proof run as the block vectors
// (block_genesis.json, emitted by the prover export), so the first block the
// node settles applies cleanly against this deployment. D-088: the pool is
// seeded with the Poseidon2 root of the genesis tree, not the leaves.
//
// Writes contracts/deployments/local.json: { verifier, pool, deployer, chainId }.
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {WhirVerifier} from "../src/verifier/WhirVerifier.sol";
import {TerminalWeight} from "../src/verifier/TerminalWeight.sol";
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
        // D-088: the pool starts at an attested ROOT, not a leaf list it
        // re-hashes. Genesis files carry `genesis_root_hex` (0x-prefixed).
        bytes32 genesisRoot = vm.parseJsonBytes32(genesis, ".genesis_root_hex");

        // V-01: the verifier pins keccak256 of the CONFIG section - the whole
        // circuit description (seed, degree, preprocessed digest, round
        // schedules, constraint programs) - so a proof of some other circuit
        // can never pass as a proof of this block shape. The default is the
        // digest of the committed block vectors' CONFIG; CONFIG_DIGEST
        // overrides for a different canonical shape (the node must prove
        // under the same WHIR parameters the vectors were generated with).
        bytes32 configDigest = vm.envOr(
            "CONFIG_DIGEST",
            bytes32(0x9d97d95258b8958f5c194cdcbc6051e30be940fef38d9e4a68a135fc95673c69)
        );

        // The broadcast context comes from the CLI (--private-key or
        // --unlocked --sender); msg.sender inside run() is that account.
        address deployer = msg.sender;
        vm.startBroadcast();
        // D-086 step A: the terminal-weight satellite first - the verifier
        // pins its codehash at construction and re-checks it before every call.
        TerminalWeight terminalWeight = new TerminalWeight();
        WhirVerifier verifier = new WhirVerifier(address(terminalWeight), configDigest);
        // The nullifier root: bytes32(0) makes ShieldedPool compute the empty
        // sparse-tree root itself; the genesis file may pin one explicitly.
        bytes32 nullifierRoot = bytes32(0);
        ShieldedPool pool = new ShieldedPool(verifier, deployer, genesisRoot, nullifierRoot);
        vm.stopBroadcast();

        string memory manifest = string.concat(
            "{\n",
            '  "verifier": "', vm.toString(address(verifier)), '",\n',
            '  "terminalWeight": "', vm.toString(address(terminalWeight)), '",\n',
            '  "pool": "', vm.toString(address(pool)), '",\n',
            '  "deployer": "', vm.toString(deployer), '",\n',
            '  "chainId": ', vm.toString(block.chainid), "\n",
            "}\n");
        vm.createDir("deployments", true);
        vm.writeFile("deployments/local.json", manifest);
        console.log("verifier", address(verifier));
        console.log("terminal weight", address(terminalWeight));
        console.log("pool", address(pool));
        console.log("genesis root", vm.toString(genesisRoot));
    }
}
