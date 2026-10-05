// node-client.js - minimal HTTP client for the rollup node's API.
//
// Every endpoint requires a Bearer token (the node's ACL, D-082). The token
// is entered by the operator via `node token --role submitter` and lives in
// chrome.storage.local only as long as the user keeps it there; the extension
// never logs it and never sends it anywhere but the configured node origin
// (manifest host_permissions pin that to localhost).
//
// Endpoints used:
//   GET  /v1/roots     (ReadOnly)  -> {root, nullifier_root}
//   POST /v1/transfer  (Submitter) -> validates the SPHINCS+ envelope, then
//                                     501: remote proof admission is deferred
//                                     (D-083). The 501 is a *success* signal
//                                     for the envelope: it means the
//                                     signature verified on the node.
//   POST /v1/demo/transfer (Admin) -> the working demo prover path.

'use strict';

export class NodeError extends Error {
  constructor(status, body) {
    super(`node returned ${status}: ${body.slice(0, 300)}`);
    this.name = 'NodeError';
    this.status = status;
    this.body = body;
  }
}

/**
 * @param {() => {baseUrl: string, token: string}} config live config getter
 *   (re-read per call so a settings change takes effect immediately).
 */
export function makeNodeClient(config) {
  async function req(method, path, body) {
    const { baseUrl, token } = config();
    if (!baseUrl) throw new Error('node URL not set (open Settings)');
    const headers = { authorization: `Bearer ${token}` };
    if (body !== undefined) headers['content-type'] = 'application/json';
    const res = await fetch(baseUrl.replace(/\/+$/, '') + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) throw new NodeError(res.status, text);
    return text === '' ? {} : JSON.parse(text);
  }

  return {
    /** Current commitment + nullifier roots (ReadOnly token). */
    roots() {
      return req('GET', '/v1/roots');
    },

    /**
     * Submit a signed envelope. Resolves {verified: true} on 501 (envelope
     * verified, admission deferred) and throws on any other non-2xx.
     */
    async submit(envelope) {
      try {
        await req('POST', '/v1/transfer', envelope);
        return { verified: true, admitted: true };
      } catch (e) {
        if (e instanceof NodeError && e.status === 501) {
          return { verified: true, admitted: false, note: e.body };
        }
        throw e;
      }
    },

    /** The demo prover path (Admin token): node builds, proves and admits. */
    demoTransfer(inputIndex, outValue, fee) {
      return req('POST', '/v1/demo/transfer', {
        input_index: inputIndex,
        out_value: outValue,
        fee,
      });
    },
  };
}
