// Settles a block on the local chain: reads the deployment manifest, the
// block statement and the WBND bundle, ABI-encodes ShieldedPool.applyBlock
// and sends it over JSON-RPC from an unlocked account (anvil dev mode: the
// node holds no keys; a production relayer signs externally).
//
//   node contracts/scripts/settle_block.mjs [bundle.bin] [genesis.json]
//
// Defaults: contracts/test/vectors/block_composed_bundle.bin and the
// statement from block_genesis.json (the same proof run). Paths resolve from
// the repo root regardless of the caller's cwd.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const at = (p) => path.join(ROOT, p);

// applyBlock(uint256[],bytes) - the first four bytes of the EVM-native
// keccak256 of the signature. Pinned by test/SelectorPins.t.sol against the
// same opcode the contract dispatches on, so this constant cannot drift.
const SELECTOR = Buffer.from("0cb000b5", "hex");

function encUint(x) {
  const b = Buffer.alloc(32);
  let v = BigInt(x);
  for (let i = 31; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n; }
  return b;
}
function encDynArray(words) {
  return Buffer.concat([encUint(words.length), ...words.map(encUint)]);
}
function encBytes(buf) {
  const pad = Buffer.alloc(Math.ceil(buf.length / 32) * 32);
  buf.copy(pad);
  return Buffer.concat([encUint(buf.length), pad]);
}

// --- JSON-RPC ---------------------------------------------------------------
const RPC = process.env.RPC_URL ?? "http://127.0.0.1:8545";
let id = 0;
async function rpc(method, params) {
  const res = await fetch(RPC, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }),
  });
  const j = await res.json();
  if (j.error) throw new Error(method + ": " + JSON.stringify(j.error));
  return j.result;
}

const BUNDLE = process.argv[2] ?? "contracts/test/vectors/block_composed_bundle.bin";
const GENESIS = process.argv[3] ?? "contracts/test/vectors/block_genesis.json";
const manifest = JSON.parse(fs.readFileSync(at("contracts/deployments/local.json"), "utf8"));
const statement = JSON.parse(fs.readFileSync(at(GENESIS), "utf8")).statement;
const proof = fs.readFileSync(at(BUNDLE));

const stmtTail = encDynArray(statement);
const proofTail = encBytes(proof);
const head = Buffer.concat([encUint(0x40), encUint(0x40 + stmtTail.length)]);
const calldata = Buffer.concat([SELECTOR, head, stmtTail, proofTail]);

const from = manifest.deployer;
const tx = { from, to: manifest.pool, data: "0x" + calldata.toString("hex"), gas: "0x" + (20_000_000_000).toString(16) };
console.log("sending applyBlock:", statement.length, "limbs,", proof.length, "proof bytes");
const t0 = Date.now();
const hash = await rpc("eth_sendTransaction", [tx]);
for (;;) {
  const rc = await rpc("eth_getTransactionReceipt", [hash]);
  if (rc) {
    console.log("tx", hash, "status", rc.status, "gas", parseInt(rc.gasUsed, 16).toLocaleString(), "in", ((Date.now() - t0) / 1000).toFixed(1) + "s");
    if (rc.status !== "0x1") {
      console.log("eth_call probe:", await rpc("eth_call", [{ to: manifest.pool, data: tx.data }, "latest"]));
      process.exit(1);
    }
    console.log("block number now", parseInt(await rpc("eth_blockNumber", []), 16));
    break;
  }
  await new Promise((r) => setTimeout(r, 500));
}
