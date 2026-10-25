"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const express = require("express");
const { createRequirePermission } = require("../src/middlewares/permissions");
const { registerSyncRoutes } = require("../src/routes/sync");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } =
  require("../sync-client/rootark-sync-authorization");

function send(port, method, route, operation) {
  return new Promise((resolve, reject) => {
    const body = Buffer.from(JSON.stringify(operation));
    const request = http.request({ hostname: "127.0.0.1", port,
      method, path: route, headers: { "content-type": "application/json",
        "content-length": body.length } }, (response) => {
      response.resume();
      response.once("end", () => resolve(response.statusCode));
    });
    request.once("error", reject);
    request.end(body);
  });
}

test("upload-only account cannot delete sync ciphertext through POST, PUT or DELETE", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-sync-delete-permission-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const publicSpki = publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const fileKey = crypto.randomBytes(32);
  const account = { username: "alice", permissions: {
    upload: true, delete: false, listFiles: true } };
  const app = express();
  app.use(express.json());
  const route = registerSyncRoutes({ app,
    storagePath: path.join(directory, "objects.json"),
    authenticate: (req, _res, next) => { req.user = account; next(); },
    requirePermission: createRequirePermission(),
    requireDeviceAuthorization: true,
    deviceAuthorization: ({ username, operation, proof }) => verifyAuthorizationProof(
      proof, operation, { username, trustedDevicePublicKeys: { "device-a": publicSpki } }),
  });
  await route.ready;
  const server = await new Promise((resolve) => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const signed = async (kind, suffix, counter, baseRevision) => {
    const operation = createOperation({ operation: kind,
      operationId: `operation-${suffix}`, objectId: "object-one",
      fileId: "file-one", versionId: `version-${suffix}`,
      deviceId: "device-a", compartmentId: "private", keyEpoch: "epoch-1",
      revision: { counter, deviceId: "device-a" }, baseRevision,
      metadata: { path: "object.txt" },
      plaintext: Buffer.from("opaque encrypted fixture"), fileKey });
    operation.authorization = await createAuthorizationProof(operation, {
      username: "alice", privateKey, publicKey: publicSpki });
    return operation;
  };
  const created = await signed("create", "create", 1, null);
  const port = server.address().port;
  assert.equal(await send(port, "POST", "/sync/v1/objects", created), 201);
  const deletion = await signed("delete", "delete", 2, created.revision);

  for (const [method, endpoint] of [
    ["POST", "/sync/v1/objects"],
    ["PUT", "/sync/v1/objects/object-one"],
    ["DELETE", "/sync/v1/objects/object-one"],
  ]) {
    assert.equal(await send(port, method, endpoint, deletion), 403,
      `${method} may not bypass the account's independent delete permission`);
    assert.equal(route.store.list("alice", "object-one")[0].tombstone, false,
      "a denied deletion must not mutate the durable sync record");
  }

  account.permissions.delete = true;
  assert.equal(await send(port, "POST", "/sync/v1/objects", deletion), 201,
    "a permitted signed device may still delete its own synced object");
  assert.equal(route.store.list("alice", "object-one")[0].tombstone, true);
});
