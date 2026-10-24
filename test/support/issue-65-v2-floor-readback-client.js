"use strict";

// Disposable child for testing the HTTPS/mTLS signed floor readback using an
// independently selected Node runtime (Node 22 as well as Node 24). The SQLite
// authority remains a different OS process with its own native-addon ABI.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { Zk1V2CheckpointFloorHttpsClient } =
  require("../../src/services/zk1V2CheckpointFloorHttps");
process.once("message", async (request) => {
  try {
    if (request?.type !== "read" || !path.isAbsolute(request.directory)
      || !Number.isSafeInteger(request.port)) throw Error();
    const read = (name) => fs.readFileSync(path.join(request.directory, name));
    const client = new Zk1V2CheckpointFloorHttpsClient({
      endpoint: `https://127.0.0.1:${request.port}/`,
      ca: read("ca.pem"), clientKey: read("client.key"), clientCert: read("client.pem"),
      serverFingerprint256: request.serverPin,
      pinnedFloorPublicKey: crypto.createPublicKey({
        key: Buffer.from(request.floorKey, "base64url"), type: "spki", format: "der" }),
      pinnedOwnerPublicKey: crypto.createPublicKey({
        key: Buffer.from(request.ownerKey, "base64url"), type: "spki", format: "der" }),
      scope: Object.fromEntries(Object.entries(request.scope)
        .map(([name, value]) => [name, Buffer.from(value, "base64url")])),
      minimum: { sequence: request.minimum.sequence, epoch: request.minimum.epoch,
        ...Object.fromEntries(["chainHash", "headDigest", "checkpointDigest",
          "operationId", "casReceiptHash", "floorReceiptHash",
          "casReceiptIdentityHash", "floorReceiptIdentityHash"].map((name) =>
          [name, Buffer.from(request.minimum[name], "base64url")])) },
    });
    const head = await client.freshHead();
    process.send({ kind: "checked", sequence: head.sequence, epoch: head.epoch });
    process.disconnect();
  } catch (_) {
    process.send({ kind: "failed" });
    process.disconnect();
  }
});
