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
  let active = true, csrf = "known-csrf-token", loseAck = false, csrfRequests = 0, commits = 0;
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
    if (url.endsWith("/catalog/commit")) {
      commits++;
      if (loseAck) { loseAck = false; throw Error("ACK lost after write"); }
    }
    return response;
  };
  async function client(i, controls = {}) {
    const device = manifest.devices[i];
    const privateKey = state.actors.get(Buffer.from(device.authorization_key_id).toString("hex"));
    const pinnedOwnerHead = { revision: Number(manifest.revision),
      digest: await v2.recoveryManifestDigestV2(manifest), epoch: Number(manifest.current_epoch) };
    return catalogBrowser.createClient({ origin, fetchImpl, ownerPublicKey: await asKey(ownerKeys.publicKey, "public"),
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
      nowSeconds: () => time, journalStore, ...controls });
  }
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
  const listed = await second.readAll();
  assert.equal(listed.head.sequence, 1);
  assert.equal(listed.rows.length, 1);
  assert.deepEqual(Buffer.from(listed.rows[0].ciphertext_digest), digest(firstCipher));
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
  const third = await client(1);
  const nextIntent = await third.prepareIntent([{ objectId, revision: 2,
    epoch: 1, ciphertext: secondCipher }]);
  await put(1, objectId, secondCipher, 1);
  await assert.rejects(second.readAll(), /ZK_BROWSER_CATALOG_UNVERIFIED/,
    "catalog READ must close during the PUT-before-COMMIT window");
  const secondCommit = await third.commit([{ ...rowInput, revision: 2, ciphertext: secondCipher,
    name: "sensitive/private/revision-2.txt" }], nextIntent);
  assert.equal(secondCommit.sequence, 2);
  const verifySecondDevice = await client(0);
  const versions = await verifySecondDevice.readAll();
  assert.equal(versions.rows.length, 2);
  assert.deepEqual(versions.rows.map((r) => r.revision), [1, 2]);
  await assert.rejects(second.readVerifiedCiphertext(listed, objectId, 1),
    /ZK_BROWSER_CATALOG_UNVERIFIED/, "old snapshot cannot authorize GET after CAS advance");
  assert.equal(JSON.stringify(versions).includes("sensitive"), false);
  assert.ok(csrfRequests >= 5);
  assert.throws(() => third.delete(), /ZK_BROWSER_CATALOG_UNVERIFIED/);
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
  const planned = await client(1);
  const revision3 = nodeCrypto.randomBytes(90);
  const plannedIntent = await planned.prepareIntent([{ objectId, revision: 3,
    epoch: 1, ciphertext: revision3 }]);
  await put(1, objectId, revision3, 2);
  const unlistedId = b64(nodeCrypto.randomBytes(16));
  await put(1, unlistedId, nodeCrypto.randomBytes(72));
  const competing = await client(1);
  await assert.rejects(competing.commit([{ ...rowInput, revision: 3,
    ciphertext: revision3 }], plannedIntent), /ZK_BROWSER_CATALOG_UNVERIFIED/,
  "an additional PUT after the pre-write journal cannot be silently omitted");
  assert.equal(sequence, 2, "CAS must not advance when server inventory contains an unlisted write");
  await fixture.appendDeviceRevocation(state, "trusted-0");
  manifest = state.headManifest;
  ownerHistory = await history.verifyRecoveryHistoryPublicV2({
    expectedScope: scope, baseManifest: state.baseManifest,
    baseReceipt: state.baseReceipt, pinnedWitness: state.pinnedWitness,
    transitions: state.transitions, packageEnvelopes: state.packageEnvelopes, now: time,
  });
  await assert.rejects(second.readAll(), /ZK_BROWSER_CATALOG_UNVERIFIED/,
    "owner witness must reject stale grants after revocation");
});
