"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const nodeCrypto = require("node:crypto");
const crypto = nodeCrypto.webcrypto;
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const express = require("express");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const history = require("../src/crypto/rootark-zk-recovery-history-v2");
const fixture = require("./support/issue-65-recovery-v2-fixtures");
const { Zk1ProtectedObjectStore, contentAuthorizationMessageV1 } =
  require("../src/services/zk1ProtectedObjectStore");
const { Zk1OpaqueCatalog, catalogCasDomain } = require("../src/services/zk1OpaqueCatalog");
const { registerZk1ProtectedObjectRoutes } = require("../src/routes/zk1ProtectedObjectRoutes");
const catalogBrowser = require("../public/client/rootark-zk1-browser-opaque-catalog-commit");
const opaqueSync = require("../public/client/rootark-zk1-opaque-device-delta-sync");
const { openZk1CatalogMetadataV1 } = require("../src/crypto/rootark-zk1-opaque-catalog-client-v1");

const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const digest = (bytes) => nodeCrypto.createHash("sha256").update(bytes).digest();
const rawPub = (key) => Buffer.from(key.export({ type: "spki", format: "der" })).subarray(-32);
const WITNESS = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0");
const GRANT = Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0");
const GRANT_FIELDS = ["schema", "account_id", "compartment_id", "keyring_id", "device_id",
  "authorization_key_id", "authorization_public_key", "manifest_revision", "manifest_digest",
  "current_epoch", "enrolled_epoch", "revoked_at_epoch"];
const asKey = (key, mode) => crypto.subtle.importKey(mode === "private" ? "pkcs8" : "raw",
  mode === "private" ? key.export({ type: "pkcs8", format: "der" }) : rawPub(key),
  "Ed25519", mode !== "private", [mode === "private" ? "sign" : "verify"]);

test("opaque catalog UMD boots without CommonJS or Node globals", () => {
  const context = { crypto, TextEncoder, TextDecoder, URL, Uint8Array, ArrayBuffer,
    btoa, atob, WeakMap, WeakSet };
  context.globalThis = context;
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../public/client/rootark-zk1-browser-opaque-catalog-commit.js"),
    "utf8"), context, { timeout: 1000 });
  assert.equal(typeof context.RootarkZk1BrowserOpaqueCatalogCommit.createClient, "function");
  assert.equal(typeof context.RootarkZk1BrowserOpaqueCatalogCommit.indexedDbJournalStore, "function");
});

test("browser UMD: two-device signed commit, exact GET, additive delta, ACK loss, rollback, replay, revocation and session fences", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk1-browser-catalog-commit-"));
  const state = await fixture.createInitialState(2);
  const scope = state.scope;
  let manifest = state.headManifest;
  let time = 1100;
  const ownerKeys = nodeCrypto.generateKeyPairSync("ed25519");
  const witnessKeys = nodeCrypto.generateKeyPairSync("ed25519");
  const authorityKeys = nodeCrypto.generateKeyPairSync("ed25519");
  const witnessId = nodeCrypto.randomBytes(16);
  let ownerHistory = await history.verifyRecoveryHistoryPublicV2({
    expectedScope: scope, baseManifest: state.baseManifest,
    baseReceipt: state.baseReceipt, pinnedWitness: state.pinnedWitness,
    transitions: state.transitions, packageEnvelopes: state.packageEnvelopes, now: time,
  });
  const witnessStatement = async (nonce) => {
    const stmt = { type: "rootark-recovery-witness-head/v1", witness_key_id: witnessId,
      ...scope, current_revision: Number(manifest.revision),
      current_manifest_digest: await v2.recoveryManifestDigestV2(manifest),
      witness_sequence: Number(manifest.revision), nonce: Buffer.from(nonce),
      observed_at: time, status: "committed", pending_reservation_id: null };
    return z.encodeDeterministic({ ...stmt, signature: nodeCrypto.sign(null,
      Buffer.concat([WITNESS, Buffer.from(await z.encodeDeterministic(stmt))]),
      witnessKeys.privateKey) });
  };
  const witnessProvider = { freshHead: async ({ nonce }) => witnessStatement(nonce),
    async beginIoAdmission() { return { admissionId: nodeCrypto.randomBytes(16), proceed: true }; },
    async finishIoAdmission() {} };
  const store = new Zk1ProtectedObjectStore(path.join(dir, "content.sqlite"), {
    bootstrapNew: true, witnessProvider, admissionRequired: true,
    witnessPinned: { keyId: witnessId, publicKey: witnessKeys.publicKey },
    trustedScope: scope, minimumHead: { revision: 1, witnessSequence: 1,
      digest: await v2.recoveryManifestDigestV2(state.baseManifest) },
    signedHistoryRequired: true,
    signedHistoryGenesisDigest: await v2.recoveryManifestDigestV2(state.baseManifest),
    verifiedHistoryProvider: async () => ownerHistory,
    manifestProvider: async () => z.encodeDeterministic(manifest),
    nowSeconds: () => time,
  });
  let sequence = 0;
  let currentDigest = Buffer.alloc(32);
  const signedCas = async (nonce) => {
    const stmt = { type: "rootark-zk1-opaque-catalog-cas/v1", ...scope,
      sequence, digest: Buffer.from(currentDigest), nonce: Buffer.from(nonce),
      observed_at: time };
    return z.encodeDeterministic({ ...stmt, signature: nodeCrypto.sign(null,
      Buffer.concat([catalogCasDomain, Buffer.from(await z.encodeDeterministic(stmt))]),
      authorityKeys.privateKey) });
  };
  const authority = { publicKey: authorityKeys.publicKey,
    readHead: async ({ nonce }) => signedCas(nonce),
    async compareAndSwap({ expectedSequence, expectedDigest, nextSequence, nextDigest, nonce }) {
      if (expectedSequence !== sequence || !Buffer.from(expectedDigest).equals(currentDigest)
        || nextSequence !== sequence + 1) throw Error("CAS conflict");
      sequence = nextSequence;
      currentDigest = Buffer.from(nextDigest);
      return signedCas(nonce);
    } };
  const app = express();
  const catalog = new Zk1OpaqueCatalog({ store, authority });
  registerZk1ProtectedObjectRoutes({ app, store, opaqueCatalog: catalog,
    authenticate: (req, res, next) => {
      if (req.get("x-session") !== "authenticated") return res.sendStatus(401);
      req.user = { username: "owner" }; next();
    }, requirePermission: () => (_req, _res, next) => next(),
    resolveTrustedScope: () => scope });
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    store.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  });
  const origin = `http://127.0.0.1:${server.address().port}/`;
  const grant = async (device) => {
    const data = { schema: "rootark-zk1-browser-owner-device-grant/v1",
      ...Object.fromEntries(Object.entries(scope).map(([key, value]) => [key, b64(value)])),
      device_id: device.device_id, authorization_key_id: b64(device.authorization_key_id),
      authorization_public_key: b64(device.authorization_public_key),
      manifest_revision: Number(manifest.revision),
      manifest_digest: b64(await v2.recoveryManifestDigestV2(manifest)),
      current_epoch: Number(manifest.current_epoch), enrolled_epoch: Number(device.enrolled_epoch),
      revoked_at_epoch: device.revoked_at_epoch };
    return { ...data, signature: b64(nodeCrypto.sign(null, Buffer.concat([GRANT,
      Buffer.from(JSON.stringify(Object.fromEntries(GRANT_FIELDS.map((f) => [f, data[f]]))))]),
    ownerKeys.privateKey)) };
  };
  const ownerHash = digest(rawPub(ownerKeys.publicKey));
  let active = true, csrf = "known-csrf-token", loseAck = false,
    losePutAck = false, csrfRequests = 0, commits = 0, putRequests = 0;
  const journalStore = {
    async write(key, value) {
      const pathname = path.join(dir, "intent-" + key + ".json");
      const fd = fs.openSync(pathname, "wx", 0o600);
      try {
        fs.writeFileSync(fd, JSON.stringify(value));
        fs.fsyncSync(fd);
      } finally { fs.closeSync(fd); }
    },
    async read(key) {
      const pathname = path.join(dir, "intent-" + key + ".json");
      return JSON.parse(fs.readFileSync(pathname, "utf8"));
    },
    async remove(key) { fs.unlinkSync(path.join(dir, "intent-" + key + ".json")); },
  };
  const fetchImpl = async (url, init) => {
    if (init.headers["x-csrf-token"] !== csrf || !active) {
      return { status: 403, headers: { get: () => "application/json" }, text: async () => "{}" };
    }
    csrfRequests++;
    const response = await fetch(url, { ...init, headers: { ...init.headers,
      "x-session": "authenticated" } });
    if (url.endsWith("/content/put")) {
      putRequests++;
      if (losePutAck) { losePutAck = false; await response.arrayBuffer();
        throw Error("PUT ACK lost after committed write"); }
    }
    if (url.endsWith("/catalog/commit")) {
      commits++;
      if (loseAck) { loseAck = false; throw Error("ACK lost after write"); }
    }
    return response;
  };
  async function clientOptions(i, controls = {}) {
    const device = manifest.devices[i];
    const privateKey = state.actors.get(Buffer.from(device.authorization_key_id).toString("hex"));
    const pinnedOwnerHead = { revision: Number(manifest.revision),
      digest: await v2.recoveryManifestDigestV2(manifest), epoch: Number(manifest.current_epoch) };
    return { origin, fetchImpl, ownerPublicKey: await asKey(ownerKeys.publicKey, "public"),
      pinnedOwnerKeyHash: ownerHash, pinnedOwnerHead, signedDeviceGrant: await grant(device),
      devicePublicKey: await asKey(nodeCrypto.createPublicKey(privateKey), "public"),
      devicePrivateKey: await asKey(privateKey, "private"),
      signerGrants: await Promise.all(manifest.devices.filter((d) => d.revoked_at_epoch === null).map(grant)),
      ownerWitnessPublicKey: await asKey(witnessKeys.publicKey, "public"),
      ownerWitnessKeyId: witnessId, ownerWitnessProbe: async ({ nonce }) => witnessStatement(nonce),
      catalogAuthorityPublicKey: await asKey(authorityKeys.publicKey, "public"),
      catalogProbe: async ({ nonce }) => signedCas(nonce),
      minimumCatalogHead: { sequence: 0, digest: Buffer.alloc(32) },
      csrfToken: () => csrf, isSessionCurrent: () => active,
      assertCurrent: async () => { if (!active) throw Error("session closed"); },
      nowSeconds: () => time, journalStore, ...controls };
  }
  const client = async (i, controls = {}) => catalogBrowser.createClient(
    await clientOptions(i, controls));
  const syncClient = async (i, controls = {}) => opaqueSync.createClient({
    authority: await clientOptions(i, controls),
    assertLive: () => { if (!active || csrf !== "known-csrf-token")
      throw Error("SESSION_INACTIVE"); },
  });
  const put = async (i, objectId, ciphertext, predecessor = null) => {
    const device = manifest.devices[i];
    const key = state.actors.get(Buffer.from(device.authorization_key_id).toString("hex"));
    const authorization = { ...scope, device_id: device.device_id, operation: "put",
      object_id: objectId, expected_object_revision: predecessor,
      manifest_revision: Number(manifest.revision),
      manifest_digest: await v2.recoveryManifestDigestV2(manifest),
      epoch: Number(manifest.current_epoch), nonce: nodeCrypto.randomBytes(32),
      issued_at: time, expires_at: time + 30, ciphertext_digest: digest(ciphertext) };
    const signature = nodeCrypto.sign(null, await contentAuthorizationMessageV1(authorization), key);
    const auth = Object.fromEntries(Object.entries(authorization).map(([field, value]) =>
      [["account_id", "compartment_id", "keyring_id", "manifest_digest", "nonce",
        "ciphertext_digest"].includes(field) ? field : field,
      Buffer.isBuffer(value) ? b64(value) : value]));
    const response = await fetch(origin + "zk-1/v1/content/put", { method: "POST",
      headers: { "x-session": "authenticated", "content-type": "application/json" },
      body: JSON.stringify({ authorization: auth, signatureBase64: b64(signature),
        ciphertextBase64: b64(ciphertext) }) });
    assert.equal(response.status, predecessor === null ? 201 : 200, await response.text());
  };
  const objectId = b64(nodeCrypto.randomBytes(16));
  const firstCipher = nodeCrypto.randomBytes(100);
  const metadataKey = nodeCrypto.randomBytes(32);
  const cryptoMeta = await crypto.subtle.importKey("raw", metadataKey, "AES-GCM", false, ["encrypt"]);
  const first = await client(0);
  const rowInput = { objectId, revision: 1, epoch: 1, ciphertext: firstCipher,
    name: "sensitive/private/account.txt", metadataKey: cryptoMeta };
  const firstIntent = await first.prepareIntent([{ objectId, revision: 1, epoch: 1,
    ciphertext: firstCipher }]);
  const storedIntent = await journalStore.read(firstIntent);
  assert.equal(JSON.stringify(storedIntent).includes(rowInput.name), false,
    "persisted journal cannot contain a name");
  assert.equal(JSON.stringify(storedIntent).includes(b64(firstCipher)), false,
    "persisted journal cannot contain ciphertext or key material");
  await put(0, objectId, firstCipher);
  loseAck = true;
  const created = await first.commit([rowInput], firstIntent);
  assert.equal(created.sequence, 1);
  assert.equal(created.verifiedSignedReadback, true);
  assert.equal(commits, 1, "ACK uncertainty must not retry POST");
  await assert.rejects(first.commit([rowInput]), /ZK_BROWSER_CATALOG_UNVERIFIED/);
  await assert.rejects(journalStore.read(firstIntent), /ENOENT/);
  const second = await client(1);
  const receiver = await syncClient(1);
  const receiverBefore = await receiver.readCurrent();
  const tamperedReceiver = await syncClient(1, { fetchImpl: async (url, init) => {
    const response = await fetchImpl(url, init);
    if (!url.endsWith("/content/read") || response.status !== 200) return response;
    const wire = await response.json();
    wire.ciphertextBase64 = b64(nodeCrypto.randomBytes(90));
    return new Response(JSON.stringify(wire), { status: 200,
      headers: { "content-type": "application/json" } });
  } });
  const tamperedBefore = await tamperedReceiver.readCurrent();
  const disconnectedReceiver = await syncClient(1, { fetchImpl: async (url, init) => {
    const response = await fetchImpl(url, init);
    if (url.endsWith("/content/read")) active = false;
    return response;
  } });
  const disconnectedBefore = await disconnectedReceiver.readCurrent();
  assert.equal(receiverBefore.head.sequence, 1);
  assert.equal(receiverBefore.entries.length, 1);
  assert.equal(Object.keys(receiverBefore.entries[0]).includes("name"), false);
  const listingKey = await crypto.subtle.importKey("raw", metadataKey,
    "AES-GCM", false, ["decrypt"]);
  const incorrectListingKey = await crypto.subtle.importKey("raw",
    nodeCrypto.randomBytes(32), "AES-GCM", false, ["decrypt"]);
  await assert.rejects(receiver.readPrivateListing(receiverBefore, incorrectListingKey),
    /ZK_OPAQUE_DELTA_SYNC_DENIED/, "wrong owner metadata key fails closed");
  const beforePrivateListPuts = putRequests, beforePrivateListCommits = commits;
  const privateListing = await receiver.readPrivateListing(receiverBefore, listingKey);
  assert.deepEqual(privateListing.entries.map((entry) =>
    [entry.objectId, entry.revision, entry.name]),
  [[objectId, 1, "sensitive/private/account.txt"]]);
  assert.equal(privateListing.head.sequence, 1);
  assert.equal(privateListing.plaintextSentToServer, false);
  assert.equal(putRequests, beforePrivateListPuts);
  assert.equal(commits, beforePrivateListCommits);
  assert.equal(JSON.stringify(receiverBefore).includes("sensitive/private/account.txt"),
    false, "signed opaque snapshot still exposes no filename");
  const listed = await second.readAll();
  assert.equal(listed.head.sequence, 1);
  assert.equal(listed.rows.length, 1);
  assert.deepEqual(Buffer.from(listed.rows[0].ciphertext_digest), digest(firstCipher));
  let producedBytes = 0, oversizeCancelled = false;
  const unboundedServer = await client(1, { fetchImpl: async (url, init) => {
    if (!url.endsWith("/catalog/read")) return fetchImpl(url, init);
    return new Response(new ReadableStream({
      pull(controller) {
        producedBytes += 8192;
        controller.enqueue(new Uint8Array(8192).fill(65));
      },
      cancel() { oversizeCancelled = true; },
    }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  await assert.rejects(unboundedServer.readAll(), /ZK_BROWSER_CATALOG_UNVERIFIED/,
    "infinite HTTP body must stop at the byte bound without response.text()");
  assert.equal(oversizeCancelled, true, "overflow cancels the stream");
  assert.ok(producedBytes <= 6 * 8192, "server cannot force unbounded buffering");
  let hangingCancelled = false;
  const hangingServer = await client(1, { fetchImpl: async (url, init) => {
    if (!url.endsWith("/catalog/read")) return fetchImpl(url, init);
    return new Response(new ReadableStream({
      start(controller) { controller.enqueue(new Uint8Array(7).fill(65)); },
      cancel() { hangingCancelled = true; },
    }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  const deadlineStart = Date.now();
  await assert.rejects(hangingServer.readAll(), /ZK_BROWSER_CATALOG_UNVERIFIED/,
    "a body that never closes must hit the absolute 15s HTTP deadline");
  assert.ok(Date.now() - deadlineStart >= 14000 && Date.now() - deadlineStart < 22000);
  assert.equal(hangingCancelled, true, "deadline cancels a stalled body");
  const independentGet = await second.readVerifiedCiphertext(listed, objectId, 1);
  assert.deepEqual(Buffer.from(independentGet.ciphertextBase64, "base64url"), firstCipher,
    "second device must independently sign a historically bound exact GET");
  const corruptedRead = await client(1, { fetchImpl: async (url, init) => {
    const response = await fetchImpl(url, init);
    if (!url.endsWith("/content/read")) return response;
    const json = await response.json();
    json.ciphertextBase64 = b64(nodeCrypto.randomBytes(firstCipher.length));
    return new Response(JSON.stringify(json), { status: 200,
      headers: { "content-type": "application/json" } });
  } });
  await assert.rejects(corruptedRead.readVerifiedCiphertext(listed, objectId, 1),
    /ZK_BROWSER_CATALOG_UNVERIFIED/, "forged GET bytes rejected");
  assert.equal(await openZk1CatalogMetadataV1({ scope, objectId, revision: 1, epoch: 1,
    metadataKey, ciphertext: listed.rows[0].metadata_ciphertext }), rowInput.name);
  const secondCipher = nodeCrypto.randomBytes(90);
  const producer = await syncClient(0);
  const producerBefore = await producer.readCurrent();
  const beforeDeltaPut = putRequests, beforeDeltaCommit = commits;
  losePutAck = true;
  loseAck = true;
  const secondCommit = await producer.commitVersion({ previous: producerBefore,
    objectId, expectedRevision: 1, revision: 2, epoch: 1,
    ciphertext: secondCipher, name: "sensitive/private/revision-2.txt",
    metadataKey: cryptoMeta });
  assert.equal(putRequests, beforeDeltaPut + 1,
    "one signed PUT despite lost HTTP ACK");
  assert.equal(commits, beforeDeltaCommit + 1,
    "one signed catalog CAS despite lost HTTP ACK");
  assert.equal(secondCommit.journalClearedAfterSignedProof, true);
  assert.equal(secondCommit.plaintextMetadataExposed, false);
  assert.equal((await second.readAll()).head.sequence, 2,
    "a freshly signed successor CAS advances a live reader's monotonic floor");
  assert.equal(secondCommit.sequence, 2);
  await assert.rejects(tamperedReceiver.pullDelta(tamperedBefore),
    /ZK_OPAQUE_DELTA_SYNC_DENIED/, "forged encrypted bytes cannot become verified delta");
  await assert.rejects(disconnectedReceiver.pullDelta(disconnectedBefore),
    /ZK_OPAQUE_DELTA_SYNC_DENIED/, "logout during signed ciphertext GET aborts delta");
  active = true;
  const delta = await receiver.pullDelta(receiverBefore);
  assert.equal(delta.fromSequence, 1);
  assert.equal(delta.toSequence, 2);
  assert.equal(delta.additions.length, 1);
  assert.equal(delta.additions[0].revision, 2);
  assert.equal(Buffer.from(delta.additions[0].metadataCiphertextBase64, "base64url").length,
    284, "transfer only encrypted filename metadata");
  assert.deepEqual(Buffer.from(delta.additions[0].ciphertextBase64, "base64url"),
    secondCipher, "second device GET is authenticated and digest-bound");
  assert.equal(JSON.stringify(delta).includes("sensitive/private"), false,
    "delta must not disclose plaintext filename");
  await assert.rejects(receiver.readPrivateListing(receiverBefore, listingKey),
    /ZK_OPAQUE_DELTA_SYNC_DENIED/,
  "stale CAS cannot expose an earlier private listing after a signed successor");
  await assert.rejects(receiver.pullDelta(receiverBefore), /ZK_OPAQUE_DELTA_SYNC_DENIED/,
    "consumed predecessor cannot replay/fork a signed successor");
  const conflictDevice = await syncClient(1);
  const conflictHead = await conflictDevice.readCurrent();
  const beforeConflictPuts = putRequests, beforeConflictCommits = commits;
  await assert.rejects(conflictDevice.commitVersion({ previous: conflictHead,
    objectId, expectedRevision: 1, revision: 2, epoch: 1,
    ciphertext: secondCipher, name: "stale-and-conflicting.txt",
    metadataKey: cryptoMeta }), /ZK_OPAQUE_DELTA_SYNC_DENIED/,
  "stale object revision fails before any side effect");
  assert.equal(putRequests, beforeConflictPuts);
  assert.equal(commits, beforeConflictCommits);
  const verifySecondDevice = await client(0);
  const versions = await verifySecondDevice.readAll();
  assert.equal(versions.rows.length, 2);
  assert.deepEqual(versions.rows.map((r) => r.revision), [1, 2]);
  await assert.rejects(second.readVerifiedCiphertext(listed, objectId, 1),
    /ZK_BROWSER_CATALOG_UNVERIFIED/, "old snapshot cannot authorize GET after CAS advance");
  assert.equal(JSON.stringify(versions).includes("sensitive"), false);
  assert.ok(csrfRequests >= 5);
  await assert.rejects(producer.commitVersion({ previous: producerBefore,
    objectId, expectedRevision: 1, revision: 2, epoch: 1,
    ciphertext: secondCipher, name: "private", metadataKey: cryptoMeta }),
  /ZK_OPAQUE_DELTA_SYNC_DENIED/, "never retry an already committed mutation");
  // Signed CAS rollback: the exact signed floor from a prior read must fence it.
  sequence = 1;
  currentDigest = Buffer.from(created.digest, "base64url");
  await assert.rejects(verifySecondDevice.readAll(), /ZK_BROWSER_CATALOG_UNVERIFIED/);
  sequence = 2;
  currentDigest = Buffer.from(secondCommit.digest, "base64url");
  // Cryptographically valid CAS fork with same sequence but different digest.
  currentDigest = nodeCrypto.randomBytes(32);
  await assert.rejects(verifySecondDevice.readAll(), /ZK_BROWSER_CATALOG_UNVERIFIED/);
  currentDigest = Buffer.from(secondCommit.digest, "base64url");
  active = false;
  await assert.rejects(second.readAll(), /ZK_BROWSER_CATALOG_UNVERIFIED/);
  active = true;
  csrf = "";
  await assert.rejects(second.readAll(), /ZK_BROWSER_CATALOG_UNVERIFIED/);
  csrf = "known-csrf-token";
  const midflight = await client(1, { fetchImpl: async (url, init) => {
    const response = await fetchImpl(url, init);
    active = false; // Logout races the network response.
    return response;
  } });
  await assert.rejects(midflight.readAll(), /ZK_BROWSER_CATALOG_UNVERIFIED/);
  active = true;
  // Full protected E2E: append a device-signed encrypted tombstone under the
  // current owner/witness/CAS, never removing either historical revision.
  const privateWire = [];
  const tombstoneWriter = await syncClient(0, { fetchImpl: async (url, options) => {
    if (url.endsWith("/content/put") || url.endsWith("/catalog/commit")) {
      privateWire.push(String(options.body));
    }
    return fetchImpl(url, options);
  } });
  const trashBase = await tombstoneWriter.readCurrent();
  const tombstoneReader = await syncClient(1);
  const readerBase = await tombstoneReader.readCurrent();
  assert.equal(trashBase.head.sequence, 2);
  const unprivilegedMarker = await syncClient(1);
  const markerHead = await unprivilegedMarker.readCurrent();
  const markerPutCount = putRequests;
  await assert.rejects(unprivilegedMarker.commitVersion({
    previous: markerHead, objectId, expectedRevision: 2, revision: 3, epoch: 1,
    ciphertext: nodeCrypto.randomBytes(64),
    name: "\uE000rootark-zk1-logical-trash/v1", metadataKey: cryptoMeta,
  }), /ZK_OPAQUE_DELTA_SYNC_DENIED/,
  "generic signed version PUT may never forge a reserved tombstone marker");
  assert.equal(putRequests, markerPutCount);
  const initialPutCount = putRequests, initialCommitCount = commits;
  losePutAck = true; loseAck = true;
  const trashed = await tombstoneWriter.trashVersion({ previous: trashBase,
    objectId, expectedRevision: 2,
    metadataKey: await crypto.subtle.importKey("raw", metadataKey,
      "AES-GCM", false, ["encrypt", "decrypt"]) });
  assert.equal(trashed.state, "trashed");
  assert.equal(trashed.revision, 3);
  assert.equal(trashed.journalClearedAfterSignedProof, true);
  assert.equal(putRequests, initialPutCount + 1);
  assert.equal(commits, initialCommitCount + 1);
  assert.equal(privateWire.length, 2);
  assert.doesNotMatch(privateWire.join(" "), /sensitive\/private|opaque-logical-trash|trash\/v1/,
    "server sees only encrypted payload and metadata, never filenames or lifecycle");
  const historyReader = await client(1);
  const catalogAfterTrash = await historyReader.readAll();
  assert.deepEqual(catalogAfterTrash.rows.map((row) => row.revision), [1, 2, 3],
    "append-only signed CAS retains every protected historical revision");
  assert.deepEqual(Buffer.from((await historyReader.readVerifiedCiphertext(
    catalogAfterTrash, objectId, 1)).ciphertextBase64, "base64url"), firstCipher);
  assert.deepEqual(Buffer.from((await historyReader.readVerifiedCiphertext(
    catalogAfterTrash, objectId, 2)).ciphertextBase64, "base64url"), secondCipher);
  const freshTrashReader = await syncClient(1);
  const latestTrash = await freshTrashReader.readCurrent();
  const ownerMetadataKey = await crypto.subtle.importKey("raw", metadataKey,
    "AES-GCM", false, ["encrypt", "decrypt"]);
  const signedTombstone = await freshTrashReader.readTrash({
    previous: latestTrash, objectId, metadataKey: ownerMetadataKey });
  assert.equal(signedTombstone.signedByAuthorizedDevice, true);
  assert.equal(signedTombstone.retainedHistoricalVersions, 2);
  const forgedGetReader = await syncClient(1, { fetchImpl: async (url, options) => {
    const response = await fetchImpl(url, options);
    if (!url.endsWith("/content/read") || response.status !== 200) return response;
    const wire = await response.json();
    wire.ciphertextBase64 = b64(nodeCrypto.randomBytes(110));
    return new Response(JSON.stringify(wire), { status: 200,
      headers: { "content-type": "application/json" } });
  } });
  const forgedGetHead = await forgedGetReader.readCurrent();
  await assert.rejects(forgedGetReader.readTrash({ previous: forgedGetHead,
    objectId, metadataKey: ownerMetadataKey }), /ZK_OPAQUE_DELTA_SYNC_DENIED/,
  "forged protected GET cannot turn opaque encrypted metadata into a valid trash");
  const forkReader = await syncClient(1);
  const forkBaseline = await forkReader.readCurrent();
  const realHeadDigest = Buffer.from(currentDigest);
  currentDigest = nodeCrypto.randomBytes(32);
  await assert.rejects(forkReader.readTrash({ previous: forkBaseline,
    objectId, metadataKey: ownerMetadataKey }), /ZK_OPAQUE_DELTA_SYNC_DENIED/,
  "same-sequence CAS fork must fail before archived tombstone inspection");
  currentDigest = realHeadDigest;
  const listingAfterTrash = await freshTrashReader.readPrivateListing(
    latestTrash, ownerMetadataKey);
  assert.equal(listingAfterTrash.entries[2].name, null);
  assert.equal(listingAfterTrash.entries[2].logicalTrashCandidate, true);
  const badTombstoneReader = await syncClient(1);
  const badBase = await badTombstoneReader.readCurrent();
  await assert.rejects(badTombstoneReader.readTrash({ previous: badBase, objectId,
    metadataKey: await crypto.subtle.importKey("raw", nodeCrypto.randomBytes(32),
      "AES-GCM", false, ["encrypt", "decrypt"]) }), /ZK_OPAQUE_DELTA_SYNC_DENIED/,
  "wrong owner-held key refuses the entire tombstone");
  await assert.rejects(tombstoneWriter.trashVersion({ previous: trashBase,
    objectId, expectedRevision: 2, metadataKey: ownerMetadataKey }),
  /ZK_OPAQUE_DELTA_SYNC_DENIED/, "same anchor cannot reissue a signed trash");
  const competingTrash = await syncClient(1);
  const competingTrashBase = await competingTrash.readCurrent();
  await assert.rejects(competingTrash.trashVersion({ previous: competingTrashBase,
    objectId, expectedRevision: 3, metadataKey: ownerMetadataKey }),
  /ZK_OPAQUE_DELTA_SYNC_DENIED/, "newest signed tombstone cannot be trashed twice");
  await assert.rejects(tombstoneReader.readTrash({ previous: readerBase,
    objectId, metadataKey: ownerMetadataKey }), /ZK_OPAQUE_DELTA_SYNC_DENIED/,
  "stale signed CAS must not accept a future tombstone");
  const planned = await client(1);
  const revision3 = nodeCrypto.randomBytes(90);
  const plannedIntent = await planned.prepareIntent([{ objectId, revision: 4,
    epoch: 1, ciphertext: revision3 }]);
  await put(1, objectId, revision3, 3);
  const unlistedId = b64(nodeCrypto.randomBytes(16));
  await put(1, unlistedId, nodeCrypto.randomBytes(72));
  const competing = await client(1);
  await assert.rejects(competing.commit([{ ...rowInput, revision: 4,
    ciphertext: revision3 }], plannedIntent), /ZK_BROWSER_CATALOG_UNVERIFIED/,
  "an additional PUT after the pre-write journal cannot be silently omitted");
  assert.equal(sequence, 3, "CAS must not advance when server inventory contains an unlisted write");
  await fixture.appendDeviceRevocation(state, "trusted-0");
  manifest = state.headManifest;
  ownerHistory = await history.verifyRecoveryHistoryPublicV2({
    expectedScope: scope, baseManifest: state.baseManifest,
    baseReceipt: state.baseReceipt, pinnedWitness: state.pinnedWitness,
    transitions: state.transitions, packageEnvelopes: state.packageEnvelopes, now: time,
  });
  await assert.rejects(second.readAll(), /ZK_BROWSER_CATALOG_UNVERIFIED/,
    "owner witness must reject stale grants after revocation");
  await assert.rejects(freshTrashReader.readTrash({
    previous: latestTrash, objectId, metadataKey: ownerMetadataKey }),
  /ZK_OPAQUE_DELTA_SYNC_DENIED/, "revoked owner grant cannot inspect historical tombstone");
  await assert.rejects(producer.pullDelta(producerBefore),
    /ZK_OPAQUE_DELTA_SYNC_DENIED/, "revoked source device cannot accept a later delta");
});
