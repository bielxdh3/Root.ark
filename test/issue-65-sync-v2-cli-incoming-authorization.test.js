"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const protocol = require("../sync-client/rootark-sync-protocol");
const authorization = require("../sync-client/rootark-sync-authorization");

test("Sync v2 CLI verifies real signed incoming operations and rejects absent or forged authorization", async () => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const revokedKeys = crypto.generateKeyPairSync("ed25519");
  const revokedPublicKey = revokedKeys.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const operation = protocol.createOperation({ operation: "create", objectId: "signed-incoming",
    deviceId: "device1", keyEpoch: "epoch1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device1" },
    metadata: { path: "signed.txt" }, plaintext: Buffer.from("ciphertext-protected"),
    fileKey: crypto.randomBytes(32) });
  const signature = await authorization.createAuthorizationProof(operation, {
    username: "alice", privateKey: keys.privateKey, publicKey });
  const signedIncoming = { ...operation, authorization: signature };
  assert.equal(await authorization.verifyAuthorizationProof(signature, signedIncoming,
    { username: "alice", trustedDevicePublicKeys: { device1: publicKey } }), true,
  "test fixture must have a genuine Ed25519 proof from the separately pinned device");
  await assert.rejects(authorization.verifyAuthorizationProof(signature, signedIncoming,
    { username: "alice" }), { code: "authorization_device_untrusted" },
  "a valid self-signed proof must not confer authorization without a pre-provisioned device pin");

  const config = { serverUrl: "https://unused.invalid", localFolder: path.resolve("unused-sync-v2"),
    token: "not-used", username: "alice", deviceId: "device1", keyEpoch: "epoch1",
    trustedDevicePublicKeys: { device1: publicKey, revoked1: revokedPublicKey },
    revokedDeviceIds: ["revoked1"] };
  let engineOptions = null;
  class FakeEngine {
    constructor(options) { engineOptions = options; }
    async open() { return this; }
    async syncOnce() { return { pushed: 0, pulled: 0, conflicts: [], offline: false }; }
  }
  const imports = {
    "node:crypto": crypto,
    "node:fs/promises": { readFile: async () => JSON.stringify(config) },
    "node:path": path,
    "./rootark-sync-engine": { SyncEngine: FakeEngine },
    "../public/client/rootark-sync-adapter": { createOpaqueSyncAdapter: () => ({}) },
    "./rootark-sync-authorization": authorization,
  };
  let historicalVerifierArgs = null;
  imports["./rootark-sync-zk1-physical-binding"] = {
    snapshotLocalDevicePolicy: (policy) => ({ username: policy.username,
      trustedDevicePublicKeys: { ...policy.trustedDevicePublicKeys },
      revokedDeviceIds: [...policy.revokedDeviceIds] }),
    verifySyncV2HistoricalWitnessAdmission: async (input) => {
      historicalVerifierArgs = input;
      return { authorizesHistoricalRead: true };
    },
  };
  const source = fs.readFileSync(path.join(__dirname, "../sync-client/rootark-sync-v2.js"), "utf8");
  const sandboxModule = { exports: {} };
  vm.runInNewContext(source, {
    module: sandboxModule, exports: sandboxModule.exports,
    require(name) {
      if (!Object.hasOwn(imports, name)) throw Error("Unexpected Sync v2 import: " + name);
      return imports[name];
    },
    process: { env: { ROOTARK_SYNC_FILE_KEY: crypto.randomBytes(32).toString("base64url"),
      ROOTARK_SYNC_DEVICE_PRIVATE_KEY: keys.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url"),
      ROOTARK_SYNC_DEVICE_PUBLIC_KEY: publicKey }, cwd: () => process.cwd(), argv: [] },
    Buffer, Date, console: { log() {} }, setTimeout,
  }, { filename: "sync-client/rootark-sync-v2.js" });
  await sandboxModule.exports.start({ config: "not-opened.json", once: true });
  assert.ok(engineOptions && engineOptions.requireAuthorization === true);
  assert.equal(await engineOptions.verifyIncoming(signedIncoming), true);
  const now = Date.now;
  try {
    Date.now = () => signature.expiresAt + 1;
    assert.equal(await engineOptions.verifyIncoming(signedIncoming), false,
      "the CLI must reject a first-ever expired signed record lacking local admission");
    assert.equal(await engineOptions.verifyIncoming(signedIncoming, {
      locallyAdmitted: true }), true,
    "a previously admitted exact envelope may remain readable after expiry");
  } finally { Date.now = now; }
  // A perfectly valid Ed25519 signature by an attacker must not enroll its
  // self-asserted public key as the trusted device1 authority.
  const attacker = crypto.generateKeyPairSync("ed25519");
  const attackerPublicKey = attacker.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const impostor = await authorization.createAuthorizationProof(operation, {
    username: "alice", privateKey: attacker.privateKey, publicKey: attackerPublicKey });
  await assert.rejects(engineOptions.verifyIncoming({ ...operation, authorization: impostor }),
    { code: "authorization_device_untrusted" });
  const revokedOperation = protocol.createOperation({ operation: "create", objectId: "revoked-incoming",
    deviceId: "revoked1", keyEpoch: "epoch1", compartmentId: "private",
    revision: { counter: 1, deviceId: "revoked1" },
    metadata: { path: "revoked.txt" }, plaintext: Buffer.from("denied"),
    fileKey: crypto.randomBytes(32) });
  const revokedSignature = await authorization.createAuthorizationProof(revokedOperation, {
    username: "alice", privateKey: revokedKeys.privateKey, publicKey: revokedPublicKey });
  await assert.rejects(engineOptions.verifyIncoming({
    ...revokedOperation, authorization: revokedSignature }),
  { code: "authorization_device_revoked" });
  assert.equal(await engineOptions.verifyIncoming({ ...operation }), false,
    "missing authorization must fail closed");
  await assert.rejects(engineOptions.verifyIncoming({ ...signedIncoming,
    authorization: { ...signature, signature: crypto.randomBytes(64).toString("base64url") } }),
  /Authorization signature invalid/);
  await assert.rejects(engineOptions.verifyIncoming({ ...signedIncoming,
    metadata: { ...signedIncoming.metadata, path: "forged.txt" } }),
  /Authorization payload mismatch/);

  // Strict opt-in must ignore the forgeable on-disk local journal admission.
  config.historicalAdmissionMode = "independent-physical-witness-v1";
  await assert.rejects(sandboxModule.exports.start({ config: "not-opened.json",
    once: true }), /Independent witness evidence provider/);
  const externalPins = Object.freeze({ pinnedWitnessPublicKey: "trusted-witness-key",
    pinnedInventoryPublicKey: "trusted-inventory-key", trustedMinimumFloor: {
      sequence: 9, lastHash: "externally-pinned" },
    localTrustedDevicePolicy: { username: "alice",
      trustedDevicePublicKeys: { device1: publicKey }, revokedDeviceIds: [] } });
  let challenge;
  await sandboxModule.exports.start({ config: "not-opened.json", once: true,
    trustedHistoricalAdmission: externalPins,
    historicalEvidenceProvider: async (_operation, args) => {
      challenge = args.nonce;
      return { scope: "untrusted-scope", expectedSequence: 2,
        expectedRoot: "untrusted-root", receipt: "untrusted-receipt",
        physicalAttestation: "untrusted-physical", admission: "untrusted-admission",
        freshFloor: "untrusted-floor", pinnedWitnessPublicKey: "rogue-key" };
    } });
  assert.equal(engineOptions.reverifySeenIncoming, true,
    "a mutable legacy seen journal must not suppress witness checks");
  try {
    Date.now = () => signature.expiresAt + 1;
    assert.equal(await engineOptions.verifyIncoming(signedIncoming, {
      locallyAdmitted: false }), true);
    assert.ok(Buffer.isBuffer(challenge) && challenge.length === 32);
    assert.deepEqual(historicalVerifierArgs.nonce, challenge,
      "independent challenge must be verifier-owned");
    assert.equal(historicalVerifierArgs.pinnedWitnessPublicKey, "trusted-witness-key",
      "untrusted provider cannot overwrite the provisioned signer");
    assert.equal(historicalVerifierArgs.localTrustedDevicePolicy.username, "alice");
  } finally { Date.now = now; }
  // The mutable JSON policy can be rolled back or poisoned independently of
  // the protected external minimum; it must have no effect on strict checks.
  config.revokedDeviceIds.push("device1");
  config.trustedDevicePublicKeys.device1 = attackerPublicKey;
  assert.equal(await engineOptions.verifyIncoming(signedIncoming), true,
    "strict mode uses independently pinned device keys, not the altered JSON");
  assert.equal(await engineOptions.authorizeOutgoing({ deviceId: "device1" }), true);
  config.revokedDeviceIds.pop();
  config.trustedDevicePublicKeys.device1 = publicKey;
  // Verification can finish after its authorization expires. Strict mode
  // re-checks the clock and refuses to promote this as a fresh acceptance.
  let releaseVerification;
  imports["./rootark-sync-authorization"] = { ...authorization,
    verifyAuthorizationProof: async (...args) => {
      const verified = await authorization.verifyAuthorizationProof(...args);
      await new Promise((resolve) => { releaseVerification = resolve; });
      return verified;
    },
  };
  const delayedModule = { exports: {} };
  // Use a second script instance so its destructured verification function
  // is the deliberately delayed signer fixture.
  vm.runInNewContext(source, {
    module: delayedModule, exports: delayedModule.exports,
    require(name) { if (!Object.hasOwn(imports, name)) throw Error(name); return imports[name]; },
    process: { env: { ROOTARK_SYNC_FILE_KEY: crypto.randomBytes(32).toString("base64url"),
      ROOTARK_SYNC_DEVICE_PRIVATE_KEY: keys.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url"),
      ROOTARK_SYNC_DEVICE_PUBLIC_KEY: publicKey }, cwd: () => process.cwd(), argv: [] },
    Buffer, Date, console: { log() {} }, setTimeout,
  }, { filename: "sync-client/rootark-sync-v2.js" });
  await delayedModule.exports.start({ config: "not-opened.json", once: true,
    requireIndependentHistoricalAdmission: true, trustedHistoricalAdmission: externalPins,
    historicalEvidenceProvider: async () => ({}) });
  const freshNow = Date.now;
  try {
    Date.now = () => signature.expiresAt - 1;
    const verifying = engineOptions.verifyIncoming(signedIncoming);
    for (let attempt = 0; !releaseVerification && attempt < 20; attempt += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(typeof releaseVerification, "function");
    Date.now = () => signature.expiresAt + 1;
    releaseVerification();
    assert.equal(await verifying, false, "expiry during Ed25519 must fail closed");
  } finally { Date.now = freshNow; }
  // An attacker rolling the JSON config back cannot disable an externally
  // enforced historical policy, even when the old journal claims admission.
  delete config.historicalAdmissionMode;
  await assert.rejects(sandboxModule.exports.start({ config: "not-opened.json",
    once: true, requireIndependentHistoricalAdmission: true }),
  /Independent witness evidence provider/);
});
