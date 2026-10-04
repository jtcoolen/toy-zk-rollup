// Reads ShieldedPool state over JSON-RPC: blockNumber, currentRoot,
// currentNullifierRoot, and the BlockApplied events of a settlement tx.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const at = (p) => path.join(ROOT, p);
const RPC = process.env.RPC_URL ?? "http://127.0.0.1:8545";
let id = 0;
async function rpc(method, params) {
  const res = await fetch(RPC, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }) });
  const j = await res.json();
  if (j.error) throw new Error(method + ": " + JSON.stringify(j.error));
  return j.result;
}
const manifest = JSON.parse(fs.readFileSync(at("contracts/deployments/local.json"), "utf8"));
const SEL = { blockNumber: "57e871e7", currentRoot: "fdab463d", currentNullifierRoot: "222d1bed" };
for (const [name, sel] of Object.entries(SEL)) {
  console.log(name, await rpc("eth_call", [{ to: manifest.pool, data: "0x" + sel }, "latest"]));
}
const txh = process.argv[2];
if (txh) {
  const rc = await rpc("eth_getTransactionReceipt", [txh]);
  console.log("status", rc.status, "gas", parseInt(rc.gasUsed, 16).toLocaleString(), "logs", rc.logs.length);
  for (const log of rc.logs) console.log(" event topic0", log.topics[0]);
}
