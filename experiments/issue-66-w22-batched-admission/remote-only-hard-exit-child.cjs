"use strict";

// Disposable, inert crash fixture only. An explicit script replaces a
// dynamically generated `node -e` program, avoiding executable code built
// from runtime values or shell interpolation.
const fs = require("node:fs");
const { SyncEngine } = require("../../sync-client/rootark-sync-engine");
const { verifyAuthorizationProof, verifyHistoricalAuthorizationProof } =
  require("../../sync-client/rootark-sync-authorization");
const { probeStrictRemoteOnlyBatch } = require("./remote-only-full-source");

const fixtureFile = process.argv[2];
const phase = process.argv[3];
if (!fixtureFile || !["afterObserve", "afterSnapshot"].includes(phase)) process.exit(92);

let data;
try { data = JSON.parse(fs.readFileSync(fixtureFile, "utf8")); }
catch { process.exit(91); }

const expected = { username: "alice",
  trustedDevicePublicKeys: { "device-signer": data.publicKey },
  revokedDeviceIds: [] };
const trusted = { minEpoch: 7, keyEpoch: "epoch-1", username: "alice",
  trustedDevicePublicKeys: expected.trustedDevicePublicKeys,
  currentPolicyProvider: () => ({ epoch: 7, keyEpoch: "epoch-1", ...expected }) };

new SyncEngine({
  rootDir: data.rootDir,
  adapter: { list: async () => data.records,
    push: async () => { throw new Error("Inert fixture must not push"); } },
  deviceId: "device-reader", keyEpoch: "epoch-1",
  compartmentId: "private", excludedPaths: ["private"],
  requireAuthorization: true,
  fileKeyResolver: () => Buffer.from(data.key, "base64url"),
  verifyIncoming: async (operation, { locallyAdmitted = false } = {}) =>
    (locallyAdmitted ? verifyHistoricalAuthorizationProof : verifyAuthorizationProof)(
      operation.authorization, operation, expected),
}).open().then((engine) => probeStrictRemoteOnlyBatch(engine, trusted, {
  [phase]: async () => process.exit(73),
})).then(() => process.exit(91)).catch(() => process.exit(90));
