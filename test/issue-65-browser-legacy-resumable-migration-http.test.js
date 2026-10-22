"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const express = require("express");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const file = require("../public/client/rootark-zk1-file-content");
const signedRoots = require("../public/client/rootark-zk1-owner-ciphertext-root-checkpoint");
const history = require("../public/client/rootark-zk1-owner-signed-checkpoint");
const migration = require("../public/client/rootark-zk1-legacy-migration-workflow");
const { Zk1ProtectedObjectStore } = require("../src/services/zk1ProtectedObjectStore");
const { registerZk1ProtectedObjectRoutes } = require("../src/routes/zk1ProtectedObjectRoutes");

const id = () => crypto.randomBytes(16).toString("base64url");
const b64 = (raw) => Buffer.from(raw).toString("base64url");
const digest = (raw) => crypto.createHash("sha256").update(Buffer.from(raw)).digest();
const fault = /ZK_LEGACY_MIGRATION_AMBIGUOUS/;
const headDomain = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");

// Minimal disposable IndexedDB transaction model, with committed records
// surviving multiple open/close cycles. No browser database is modified.
function indexedDbFixture() {
  const records = new Map();
  let created = false;
  const db = {
    objectStoreNames: { contains(name) { return name === "migration_intents" && created; } },
    createObjectStore() { created = true; },
    close() {},
    transaction(_store, mode) {
      let aborted = false;
      const tx = {
        oncomplete: null, onabort: null, onerror: null,
        abort() { aborted = true; queueMicrotask(() => tx.onabort?.()); },
        objectStore() {
          return {
            get(key) {
              const request = { result: undefined, onsuccess: null };
              queueMicrotask(() => {
                request.result = records.has(key) ? structuredClone(records.get(key)) : undefined;
                request.onsuccess?.();
                queueMicrotask(() => { if (!aborted) tx.oncomplete?.(); });
              });
              return request;
            },
            put(value, key) {
              assert.equal(mode, "readwrite");
              records.set(key, structuredClone(value));
            },
          };
        },
      };
      return tx;
    },
  };
  return { records, api: {
    open() {
      const request = { result: db, onupgradeneeded: null, onsuccess: null };
      queueMicrotask(() => {
        if (!created) request.onupgradeneeded?.();
        request.onsuccess?.();
      });
      return request;
    },
  } };
}

async function importedPair(keyPair) {
  return {
    publicKey: await crypto.webcrypto.subtle.importKey("spki",
      keyPair.publicKey.export({ format: "der", type: "spki" }), "Ed25519", true, ["verify"]),
    privateKey: await crypto.webcrypto.subtle.importKey("pkcs8",
      keyPair.privateKey.export({ format: "der", type: "pkcs8" }), "Ed25519", false, ["sign"]),
  };
}

async function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-resume-"));
  const state = await fixtures.createInitialState(2);
  const manifest = state.headManifest;
  const manifestDigest = await v2.recoveryManifestDigestV2(manifest);
  const scope = state.scope;
  const scopeWire = Object.fromEntries(Object.entries(scope).map(([key, value]) => [key, b64(value)]));
  const witnessKey = crypto.generateKeyPairSync("ed25519");
  const witnessId = crypto.randomBytes(16);
  let original = Buffer.from("Synthetic old-server plaintext: confidential file contents.");
  let legacyType = "text/plain";
  let legacyReads = 0;
  let writes = 0;
  let reads = 0;
  const app = express();
  app.get("/files/:name", (req, res) => {
    if (req.headers["x-lab-session"] !== "owner") return res.sendStatus(401);
    if (req.params.name !== "legacy.txt") return res.sendStatus(404);
    legacyReads++;
    res.set("content-disposition", 'attachment; filename="legacy.txt"');
    res.type(legacyType);
    res.status(200).send(original);
  });
  const witnessProvider = {
    async freshHead({ nonce }) {
      const payload = { type: "rootark-recovery-witness-head/v1",
        witness_key_id: witnessId, ...scope, nonce,
        current_revision: manifest.revision, current_manifest_digest: manifestDigest,
        witness_sequence: manifest.revision, observed_at: 1400,
        status: "committed", pending_reservation_id: null };
      const signed = crypto.sign(null, Buffer.concat([headDomain,
        Buffer.from(await z.encodeDeterministic(payload))]), witnessKey.privateKey);
      return z.encodeDeterministic({ ...payload, signature: signed });
    },
    async beginIoAdmission() { return { admissionId: crypto.randomBytes(16), proceed: true }; },
    async finishIoAdmission() { return { status: "FINISHED" }; },
  };
  const store = new Zk1ProtectedObjectStore(path.join(root, "db.sqlite"), {
    trustedScope: scope, bootstrapNew: true, admissionRequired: true,
    minimumHead: { revision: 1, witnessSequence: 1,
      digest: await v2.recoveryManifestDigestV2(state.baseManifest) },
    witnessProvider, witnessPinned: { keyId: witnessId, publicKey: witnessKey.publicKey },
    manifestProvider: () => z.encodeDeterministic(manifest), nowSeconds: () => 1400,
  });
  const authenticate = (req, res, next) => {
    if (req.headers["x-lab-session"] !== "owner") return res.sendStatus(401);
    req.user = { username: "owner" }; next();
  };
  registerZk1ProtectedObjectRoutes({ app, store, authenticate,
    requirePermission: () => (_req, _res, next) => next(),
    resolveTrustedScope: () => scope });
  const server = await new Promise((resolve) => {
    const created = app.listen(0, "127.0.0.1", () => resolve(created));
  });
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    store.close(); fs.rmSync(root, { recursive: true, force: true });
  });
  const origin = `http://127.0.0.1:${server.address().port}/`;
  const realFetch = (url, options) => {
    if (url.endsWith("/content/put")) writes++;
    if (url.endsWith("/content/read")) reads++;
    return fetch(url.startsWith("/") ? origin.slice(0, -1) + url : url, {
      ...options, headers: { ...options.headers, "x-lab-session": "owner" },
    });
  };
  const ownerPair = await importedPair(crypto.generateKeyPairSync("ed25519"));
  const device = manifest.devices[0];
  const deviceNative = state.actors.get(Buffer.from(device.authorization_key_id).toString("hex"));
  const deviceKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    deviceNative.export({ type: "pkcs8", format: "der" }), "Ed25519", false, ["sign"]);
  const devicePublicKey = await crypto.webcrypto.subtle.importKey("spki",
    crypto.createPublicKey(deviceNative).export({ type: "spki", format: "der" }),
    "Ed25519", true, ["verify"]);
  const ownerRaw = await crypto.webcrypto.subtle.exportKey("raw", ownerPair.publicKey);
  const ownerSpki = await crypto.webcrypto.subtle.exportKey("spki", ownerPair.publicKey);
  const ownerSignerId = crypto.randomBytes(16);
  const ownerHistoryCheckpoint = await history.signOwnerCheckpoint({
    scope: scopeWire, signerKey: ownerPair.privateKey, signerPublicKey: ownerPair.publicKey,
    signerKeyId: ownerSignerId, deviceId: "owner-offline", revision: manifest.revision,
    manifestDigest, issuedAt: 1390, previous: null,
  });
  const grant = {
    schema: "rootark-zk1-browser-owner-device-grant/v1", ...scopeWire,
    device_id: device.device_id, authorization_key_id: b64(device.authorization_key_id),
    authorization_public_key: b64(await crypto.webcrypto.subtle.exportKey("raw", devicePublicKey)),
    manifest_revision: manifest.revision, manifest_digest: b64(manifestDigest),
    current_epoch: manifest.current_epoch, enrolled_epoch: 1, revoked_at_epoch: null,
  };
  const domain = Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0");
  const sig = await crypto.webcrypto.subtle.sign("Ed25519", ownerPair.privateKey,
    Buffer.concat([domain, Buffer.from(JSON.stringify(grant))]));
  const trust = { ownerPublicKey: ownerPair.publicKey,
    pinnedOwnerKeyHash: digest(ownerRaw), independentOwnerSpkiSha256: digest(ownerSpki),
    pinnedCurrentHead: { revision: manifest.revision, digest: manifestDigest,
      epoch: manifest.current_epoch },
    signedDeviceGrant: { ...grant, signature: b64(sig) }, ownerHistoryCheckpoint,
    previousOwnerHistoryProof: null, devicePublicKey, devicePrivateKey: deviceKey };
  const metadata = { ...scopeWire, object_id: id(), version_id: id(),
    parent_version_id: null, epoch: manifest.current_epoch, kind: "file" };
  const cek = await file.generateFileCek();
  const disk = indexedDbFixture();
  const journal = await migration.openMigrationJournal(disk.api);
  const input = { optIn: true, legacy: { name: "legacy.txt", folderId: "" },
    metadata, trust, cek, origin, fetchImpl: realFetch, journal, nowSeconds: 1400 };
  return { input, ownerPair, ownerSignerId, disk, realFetch, store, original,
    get writes() { return writes; }, get reads() { return reads; },
    get legacyReads() { return legacyReads; },
    setSource(next) { original = Buffer.from(next); },
    setMediaType(next) { legacyType = next; },
    async checkpoint(rootValue) {
      return signedRoots.signOwnerCiphertextRootCheckpoint({
        scope: scopeWire, signerKey: ownerPair.privateKey, signerKeyId: ownerSignerId,
        deviceId: "owner-offline", manifestRevision: manifest.revision,
        manifestDigest, manifestEpoch: manifest.current_epoch,
        objectId: metadata.object_id, objectRevision: 1,
        ciphertextEpoch: metadata.epoch,
        ciphertextRoot: Buffer.from(rootValue, "base64url"), issuedAt: 1401,
      });
    },
  };
}

test("explicit legacy opt-in migrates through real authenticated HTTP; owner signature is mandatory", async (t) => {
  const f = await fixture(t);
  await assert.rejects(migration.beginLegacyMigration({ ...f.input, optIn: false }), fault);
  assert.equal(f.legacyReads, 0);
  await assert.rejects(migration.beginLegacyMigration({
    ...f.input, trust: { ...f.input.trust, signedDeviceGrant: {
      ...f.input.trust.signedDeviceGrant, signature: b64(crypto.randomBytes(64)) } },
  }), fault);
  assert.equal(f.legacyReads, 0, "invalid owner authority cannot trigger legacy plaintext GET");
  const pending = await migration.beginLegacyMigration(f.input);
  assert.equal(pending.phase, "awaiting-independent-owner-checkpoint");
  assert.equal(pending.authorizesCutover, false);
  assert.equal(f.writes, 1);
  assert.ok(f.reads >= 1);
  const persisted = await f.input.journal.read(f.input.metadata.object_id);
  assert.equal(persisted.phase, "readback");
  assert.equal(JSON.stringify(persisted).includes("Synthetic old-server plaintext"), false);
  assert.equal(JSON.stringify(persisted).includes("legacy.txt"), false);
  const ciphertext = f.store.db.prepare("SELECT ciphertext FROM zk_content_object WHERE id=?")
    .get(f.input.metadata.object_id).ciphertext;
  assert.equal(ciphertext.includes(f.original), false);
  await assert.rejects(migration.finalizeLegacyMigration({
    ...f.input, signedRootCheckpoint: null }), fault);
  const finished = await migration.finalizeLegacyMigration({ ...f.input,
    signedRootCheckpoint: await f.checkpoint(pending.root) });
  assert.equal(finished.signedHistoricalCiphertextRootChecked, true);
  assert.equal(finished.independentDurableWriteProven, false);
  assert.equal(finished.externalRetentionProven, false);
  assert.equal(finished.canDeleteLegacy, false);
  assert.equal((await f.realFetch("/files/legacy.txt", { method: "GET" })).status, 200);
});

test("lost PUT ACK and subsequent GET outage remain journaled ambiguous; resume never issues another PUT", async (t) => {
  const f = await fixture(t);
  let lostAck = true;
  let lostGet = true;
  const flakyFetch = async (url, options) => {
    if (url.endsWith("/content/read") && lostGet) throw Error("network partition");
    const response = await f.realFetch(url, options);
    if (url.endsWith("/content/put") && lostAck) throw Error("lost ACK after commit");
    return response;
  };
  await assert.rejects(migration.beginLegacyMigration({
    ...f.input, fetchImpl: flakyFetch }), fault);
  const raw = await f.input.journal.read(f.input.metadata.object_id);
  assert.equal(raw.phase, "uncertain");
  assert.equal(f.writes, 1);
  f.input.journal.close();
  const journal = await migration.openMigrationJournal(f.disk.api);
  lostAck = false;
  lostGet = false;
  const recovered = await migration.beginLegacyMigration({ ...f.input, journal,
    fetchImpl: flakyFetch });
  assert.equal(recovered.verifiedLocalReadback, true);
  assert.equal(f.writes, 1, "resumed operation cannot replay a previously ambiguous PUT");
  await assert.rejects(migration.beginLegacyMigration({ ...f.input, journal,
    metadata: { ...f.input.metadata, version_id: id() } }), fault);
  assert.equal(f.writes, 1, "a foreign immutable version cannot replay the PUT");
  const signed = await f.checkpoint(recovered.root);
  assert.equal((await migration.finalizeLegacyMigration({ ...f.input, journal,
    signedRootCheckpoint: signed })).canDeleteLegacy, false);
});

test("corrupted signed GET, forged owner root, stale pin and changed legacy source all fail closed", async (t) => {
  const f = await fixture(t);
  let badRead = true;
  const wrappedFetch = async (url, options) => {
    const response = await f.realFetch(url, options);
    if (url.endsWith("/content/read") && badRead) {
      const body = await response.json();
      body.ciphertextBase64 = b64(crypto.randomBytes(80));
      return new Response(JSON.stringify(body), { status: 200,
        headers: { "content-type": "application/json" } });
    }
    return response;
  };
  await assert.rejects(migration.beginLegacyMigration({
    ...f.input, fetchImpl: wrappedFetch }), fault);
  assert.equal((await f.input.journal.read(f.input.metadata.object_id)).phase, "uncertain");
  badRead = false;
  const result = await migration.beginLegacyMigration(f.input);
  const attacker = await importedPair(crypto.generateKeyPairSync("ed25519"));
  const forged = await signedRoots.signOwnerCiphertextRootCheckpoint({
    scope: Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
      .map((key) => [key, f.input.metadata[key]])), signerKey: attacker.privateKey,
    signerKeyId: f.ownerSignerId, deviceId: "owner-offline",
    manifestRevision: f.input.trust.pinnedCurrentHead.revision,
    manifestDigest: f.input.trust.pinnedCurrentHead.digest,
    manifestEpoch: f.input.metadata.epoch, objectId: f.input.metadata.object_id,
    objectRevision: 1, ciphertextEpoch: f.input.metadata.epoch,
    ciphertextRoot: Buffer.from(result.root, "base64url"), issuedAt: 1401,
  });
  await assert.rejects(migration.finalizeLegacyMigration({
    ...f.input, signedRootCheckpoint: forged }), fault);
  const signed = await f.checkpoint(result.root);
  await assert.rejects(migration.finalizeLegacyMigration({
    ...f.input, signedRootCheckpoint: signed,
    trust: { ...f.input.trust, pinnedCurrentHead: {
      ...f.input.trust.pinnedCurrentHead, revision: 1 } } }), fault);
  f.setSource("Owner changed legacy source after journal's original digest.");
  await assert.rejects(migration.finalizeLegacyMigration({
    ...f.input, signedRootCheckpoint: signed }), fault);
  assert.notEqual((await f.input.journal.read(f.input.metadata.object_id)).phase, "owner-proven");
});

test("intent checkpoint before failed PUT remains ambiguous and never retries a potentially sent PUT", async (t) => {
  const f = await fixture(t);
  await assert.rejects(migration.beginLegacyMigration({ ...f.input,
    fetchImpl: (url, options) => {
      if (url.endsWith("/content/put") || url.endsWith("/content/read"))
        return Promise.reject(new Error("connection closed before response"));
      return f.realFetch(url, options);
    },
  }), fault);
  assert.equal((await f.input.journal.read(f.input.metadata.object_id)).phase, "uncertain");
  assert.equal(f.writes, 0, "fixture blocked before network PUT was sent");
  await assert.rejects(migration.beginLegacyMigration(f.input), fault);
  assert.equal(f.writes, 0, "retry must issue a signed GET only, even if the PUT never arrived");
  assert.equal((await f.realFetch("/files/legacy.txt", { method: "GET" })).status, 200);
});

test("changed legacy media type with identical plaintext bytes invalidates the checkpoint", async (t) => {
  const f = await fixture(t);
  const before = await migration.beginLegacyMigration(f.input);
  f.setMediaType("application/json");
  await assert.rejects(migration.finalizeLegacyMigration({ ...f.input,
    signedRootCheckpoint: await f.checkpoint(before.root) }), fault);
  assert.equal((await f.input.journal.read(f.input.metadata.object_id)).phase, "readback");
  assert.equal(f.writes, 1);
});

test("browser UMD legacy migration loads without Node require or filesystem dependencies", async () => {
  const ctx = vm.createContext({ crypto: crypto.webcrypto, TextEncoder, TextDecoder,
    Uint8Array, ArrayBuffer, URL, atob, btoa });
  for (const fileName of [
    "rootark-dev-vault-migration.js", "rootark-zk1-file-content.js",
    "rootark-zk1-ciphertext-chunk-root.js", "rootark-zk1-ciphertext-download-integrity.js",
    "rootark-zk1-owner-signed-checkpoint.js", "rootark-zk1-protected-http-client.js",
    "rootark-zk1-uncertain-put-reconciliation.js",
    "rootark-zk1-normal-browser-trust-floor.js", "rootark-zk1-normal-browser-content.js",
    "rootark-zk1-owner-ciphertext-root-checkpoint.js",
    "rootark-zk1-legacy-migration-workflow.js",
  ]) vm.runInContext(fs.readFileSync(path.join(__dirname, "../public/client", fileName), "utf8"), ctx);
  assert.equal(vm.runInContext("typeof RootarkZk1LegacyMigrationWorkflow.beginLegacyMigration", ctx), "function");
  assert.equal(vm.runInContext("typeof RootarkZk1LegacyMigrationWorkflow.finalizeLegacyMigration", ctx), "function");
  await assert.rejects(vm.runInContext(
    "RootarkZk1LegacyMigrationWorkflow.openMigrationJournal(null)", ctx), fault);
});
