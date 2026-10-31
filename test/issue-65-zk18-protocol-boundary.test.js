"use strict";

// Issue #65 ZK18: these are compatibility guards, not a native Android client
// or an implementation of future protected full-text search (#63/#64).
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const express = require("express");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");
const { registerZk1ProtectedObjectRoutes } = require("../src/routes/zk1ProtectedObjectRoutes");
const { registerSyncRoutes, SyncObjectStore } = require("../src/routes/sync");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const zkBrowser = require("../public/client/rootark-zk1-protected-http-client");
const localIndex = require("../public/client/rootark-protected-index");

const b64 = (bytes) => Buffer.from(bytes).toString("base64url");

function legacyOperation(suffix, deviceId = "device-legacy") {
  return createOperation({
    operation: "create", objectId: `object-${suffix}`, fileId: `file-${suffix}`,
    versionId: `version-${suffix}`, operationId: `operation-${suffix}`,
    deviceId, keyEpoch: "epoch-1", compartmentId: "legacy-only",
    revision: { counter: 1, deviceId }, metadata: { name: `${suffix}.txt`, path: `${suffix}.txt` },
    plaintext: Buffer.from("legacy fixture only"), fileKey: crypto.randomBytes(32),
  });
}

async function postJson(origin, endpoint, payload) {
  const res = await fetch(origin + endpoint, { method: "POST",
    headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
  return { status: res.status, body: await res.json() };
}

test("ZK18: signed zk-1 and signed legacy v2 wires cannot cross the other's HTTP route", async (t) => {
  // Reuse the private on-disk fixture convention from browser-signed-content-http.
  // That suite separately proves valid zk-1 signed PUT/GET and sealed filenames.
  const directory = createPrivateAuthorityFixture("rootark-zk18-contract-");
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const app = express();
  app.use(express.json({ limit: "1mb" }));
  const authenticate = (req, _res, next) => {
    req.user = { username: "owner", sessionVersion: 0,
      permissions: { listFiles: true, upload: true, delete: true } };
    next();
  };
  const requirePermission = () => (_req, _res, next) => next();
  const scope = { account_id: crypto.randomBytes(16), compartment_id: Buffer.from("private"),
    keyring_id: crypto.randomBytes(16) };
  let protectedAdmissions = 0;
  registerZk1ProtectedObjectRoutes({ app, authenticate, requirePermission,
    resolveTrustedScope: () => scope,
    // The request must fail its real parser BEFORE reaching the external witness.
    store: { put() {}, get() {}, runWithAdmission() { protectedAdmissions++; throw Error("unexpected zk-1 admission"); } },
  });
  const legacy = registerSyncRoutes({ app, authenticate, requirePermission,
    storagePath: path.join(directory, "legacy-http.json"),
    atomicDeviceRegistry: false, requireDeviceAuthorization: false });
  await legacy.ready;
  const server = await new Promise((resolve) => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;

  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = b64(pair.publicKey.export({ type: "spki", format: "der" }));
  const signerKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    pair.privateKey.export({ type: "pkcs8", format: "der" }), "Ed25519", false, ["sign"]);
  const sealed = await zkBrowser.signProtectedContentOperation({
    signerKey, scope: Object.fromEntries(Object.entries(scope).map(([key, value]) => [key, b64(value)])),
    deviceId: "device-legacy", operation: "put", objectId: b64(crypto.randomBytes(16)),
    expectedObjectRevision: null, manifestRevision: 1, manifestDigest: crypto.randomBytes(32),
    epoch: 1, nowSeconds: 1400, ciphertext: crypto.randomBytes(32),
  });
  const intoSync = await postJson(origin, "/sync/v1/objects", sealed);
  assert.equal(intoSync.status, 400, "a signed zk-1 wire is not a Sync v2 envelope");
  assert.deepEqual(legacy.store.list("owner"), [], "cross-protocol denial must not persist a legacy object");

  const signedLegacy = legacyOperation("signed");
  signedLegacy.authorization = await createAuthorizationProof(signedLegacy, {
    username: "owner", privateKey: pair.privateKey, publicKey,
    expiresAt: Date.now() + 60_000,
  });
  assert.equal(signedLegacy.authorization.suite, "rootark-zk-1",
    "sharing a suite identifier does not make legacy metadata server-blind");
  const intoZk = await postJson(origin, "/zk-1/v1/content/put", signedLegacy);
  assert.equal(intoZk.status, 403, "a signed Sync v2 operation is not a zk-1 protected PUT");
  assert.equal(protectedAdmissions, 0, "legacy data must not reach a protected witness admission");
  assert.deepEqual(legacy.store.list("owner"), []);

  const unsignedLegacy = await postJson(origin, "/sync/v1/objects", legacyOperation("unsigned"));
  assert.equal(unsignedLegacy.status, 201, "explicitly unprotected legacy HTTP sync remains supported");

  // Signed v2 remains usable with its *own* co-located device authority; no
  // invented global 'protected_enforced' marker or blanket legacy ban.
  const strict = await new SyncObjectStore(path.join(directory, "signed-store.json"),
    { atomicDeviceRegistry: true }).open();
  assert.deepEqual(await strict.enrollDevice({ username: "owner", deviceId: "device-legacy",
    publicKey, expectedEpoch: 0 }), { epoch: 1 });
  assert.equal((await strict.put("owner", signedLegacy)).kind, "stored");
  assert.equal(strict.list("owner").length, 1);
});

test("ZK18: the existing browser-only protected index search emits no query or filename over network", async () => {
  // This is the separate local AES-GCM index, NOT a claim of zk-1 authority
  // freshness or the full client-generated protected search planned in #63.
  const key = crypto.randomBytes(32);
  const protectedName = "zk18-fixture-offline-secret.txt";
  const protectedTerm = "zk18-fixture-offline-secret";
  const entry = await localIndex.createEntry({ id: "local-only", versionId: "v1",
    keyEpoch: "epoch1", compartmentId: "private",
    metadata: { name: protectedName } }, key);
  assert.equal(JSON.stringify(entry).includes(protectedName), false);
  const network = [];
  const forbidden = (kind) => (...args) => {
    network.push({ kind, args });
    throw Error("unexpected network use during protected local search");
  };
  const elements = {
    protectedSearchInput: { value: protectedTerm },
    protectedSearchResult: { textContent: "" },
    protectedClientStatus: { textContent: "" },
  };
  let onClick;
  let unlockedKey = key;
  const store = { async open() {}, async listIndex() { return [entry]; }, async clear() {} };
  const session = { attachStore() {}, getKey: async () => unlockedKey };
  const window = { RootarkProtectedIndex: localIndex,
    RootarkProtectedStore: { createProtectedStore: () => store },
    RootarkProtectedSession: session, addEventListener() {},
    fetch: forbidden("window.fetch"), XMLHttpRequest: forbidden("window.XMLHttpRequest") };
  const navigator = { onLine: true, serviceWorker: {},
    sendBeacon: forbidden("navigator.sendBeacon") };
  const document = {
    addEventListener(type, handler) { if (type === "click") onClick = handler; },
    getElementById(id) { return elements[id] || null; },
  };
  const source = fs.readFileSync(path.join(__dirname, "../public/client/rootark-bootstrap.js"), "utf8");
  vm.runInNewContext(source, { window, document, navigator,
    fetch: forbidden("fetch"), XMLHttpRequest: forbidden("XMLHttpRequest"),
    WebSocket: forbidden("WebSocket"), EventSource: forbidden("EventSource") });
  const click = () => onClick({ target: { closest: (selector) =>
    selector === "#protectedSearchButton" ? {} : null } });
  await click();
  assert.equal(elements.protectedSearchResult.textContent, "1 resultado(s) local(is).");
  assert.deepEqual(network, [], "protected search must not egress through legacy /files/search or other transport");

  unlockedKey = crypto.randomBytes(32);
  await click();
  assert.equal(elements.protectedSearchResult.textContent, "Indice protegido indisponivel ou chave incorreta.");
  assert.deepEqual(network, [], "failure to decrypt must not downgrade to server-side FTS");
});
