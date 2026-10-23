"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const test = require("node:test");
const { createOpaqueSyncAdapter } = require("../public/client/rootark-sync-adapter");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");

async function server(t, handler) {
  const value = http.createServer(handler);
  await new Promise((resolve, reject) => {
    value.once("error", reject);
    value.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    value.closeAllConnections();
    await new Promise((resolve) => value.close(resolve));
  });
  return `http://127.0.0.1:${value.address().port}`;
}

test("Sync v2 must never forward signed ciphertext on cross-origin HTTP 307", {
  timeout: 15000,
}, async (t) => {
  const attackerRequests = [];
  const foreign = await server(t, (req, res) => {
    const chunks = [];
    req.on("data", (part) => chunks.push(part));
    req.on("end", () => {
      attackerRequests.push({ method: req.method, body: Buffer.concat(chunks).toString("utf8"),
        authorization: req.headers.authorization });
      res.writeHead(201, { "content-type": "application/json" });
      res.end('{"operationId":"attacker-ack"}');
    });
  });
  let redirects = 0;
  const trusted = await server(t, (req, res) => {
    redirects++;
    req.resume();
    res.writeHead(307, { location: `${foreign}/exfiltrate` });
    res.end();
  });
  const operation = protocol.createOperation({
    operation: "create", objectId: "opaque-object", fileId: "opaque-file",
    versionId: "opaque-version", operationId: "opaque-operation",
    deviceId: "owner-device", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "owner-device" },
    metadata: { path: "confidential-filename.txt" },
    plaintext: Buffer.from("synthetic-private-content-only"),
    fileKey: crypto.randomBytes(32),
  });
  const keys = crypto.generateKeyPairSync("ed25519");
  operation.authorization = await createAuthorizationProof(operation, {
    username: "synthetic-owner", privateKey: keys.privateKey,
    publicKey: keys.publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
  });
  assert.ok(operation.authorization.signature, "fixture must carry genuine device signature");
  const adapter = createOpaqueSyncAdapter({
    baseUrl: trusted,
    fetchImpl: (url, options = {}) => fetch(url, {
      ...options,
      headers: { Authorization: "Bearer synthetic-owner-token", ...(options.headers || {}) },
    }),
  });
  const outcome = await adapter.push(operation).then(() => "accepted", () => "rejected");
  assert.equal(redirects, 1, "the trusted Root.ark origin must receive the POST");
  assert.equal(attackerRequests.length, 0,
    "redirects must never forward signed ciphertext, AAD filenames, or device proofs");
  assert.equal(outcome, "rejected", "a fake ACK from any redirect may not commit the operation");
});
