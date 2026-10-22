"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn, execFileSync } = require("node:child_process");
const express = require("express");
const jwt = require("jsonwebtoken");
const { createAuthenticate } = require("../src/middlewares/auth");
const { createRequirePermission } = require("../src/middlewares/permissions");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const normal = require("../public/client/rootark-zk1-normal-browser-content");
const portable = require("../public/client/rootark-zk1-portable-file-recovery");
const browserRestore = require("../public/client/rootark-zk1-browser-recovery-http");
const protectedHttp = require("../public/client/rootark-zk1-protected-http-client");
const ownerHistory = require("../public/client/rootark-zk1-owner-signed-checkpoint");
const ownerRoots = require("../public/client/rootark-zk1-owner-ciphertext-root-checkpoint");
const { Zk1ProtectedObjectStore } = require("../src/services/zk1ProtectedObjectStore");
const { registerZk1ProtectedObjectRoutes } = require("../src/routes/zk1ProtectedObjectRoutes");

const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const id = () => crypto.randomBytes(16).toString("base64url");
const b64 = (value) => Buffer.from(value).toString("base64url");
const grantFields = ["schema", "account_id", "compartment_id", "keyring_id",
  "device_id", "authorization_key_id", "authorization_public_key",
  "manifest_revision", "manifest_digest", "current_epoch",
  "enrolled_epoch", "revoked_at_epoch"];
const grantDomain = Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0");
const witnessDomain = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0");
const scriptNames = ["rootark-zk1-file-content", "rootark-zk1-ciphertext-chunk-root",
  "rootark-zk1-ciphertext-download-integrity", "rootark-zk1-owner-signed-checkpoint",
  "rootark-zk1-owner-ciphertext-root-checkpoint", "rootark-zk1-protected-http-client",
  "rootark-zk1-uncertain-put-reconciliation", "rootark-zk1-normal-browser-trust-floor",
  "rootark-zk1-normal-browser-content", "rootark-zk1-portable-file-recovery",
  "rootark-zk1-browser-recovery-http",
  "rootark-zk1-normal-browser-lab-ui", "rootark-zk1-portable-recovery-lab-ui"];

test("production static paths cannot disclose the opt-in normal browser laboratory", async (t) => {
  const app = express();
  app.use(express.static(path.join(__dirname, "../public")));
  const server = await new Promise((resolve) => {
    const value = app.listen(0, "127.0.0.1", () => resolve(value));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  for (const name of [
    "/zk1-protected-file-lab.html",
    "/ZK1-PROTECTED-FILE-LAB.HTML",
    "/%7ak1-protected-file-lab.html",
    "//zk1-protected-file-lab.html",
    "/zK1-protected-file-lab.html",
  ]) {
    const response = await fetch(`http://127.0.0.1:${server.address().port}${name}`);
    assert.equal(response.status, 404, `lab page leaked through static alias: ${name}`);
  }
  assert.ok(fs.existsSync(path.join(__dirname, "../dev-ui/zk1-protected-file-lab.html")),
    "opt-in page must remain available outside the public static tree");
});

async function setup(t) {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-normal-browser-"));
  const clock = Math.floor(Date.now() / 1000);
  // Keep a third still-trusted device so two independent revocations can
  // rotate epochs without illegally removing every recovery authority.
  const state = await fixtures.createInitialState(3);
  let head = state.headManifest;
  const baseDigest = await v2.recoveryManifestDigestV2(state.baseManifest);
  const witness = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const owner = crypto.generateKeyPairSync("ed25519");
  const ownerRaw = owner.publicKey.export({ type: "spki", format: "der" }).subarray(12);
  const device = head.devices[0];
  // State actor map is keyed by the hex identity, not its wire encoding.
  const devicePair = state.actors.get(Buffer.from(device.authorization_key_id).toString("hex"));
  assert.ok(devicePair);
  const privateDer = devicePair.export({ type: "pkcs8", format: "der" });
  const subtle = crypto.webcrypto.subtle;
  const devicePrivateKey = await subtle.importKey("pkcs8", privateDer, "Ed25519", false, ["sign"]);
  const devicePublicKey = await subtle.importKey("raw", device.authorization_public_key,
    "Ed25519", true, ["verify"]);
  const ownerPublicKey = await subtle.importKey("raw", ownerRaw,
    "Ed25519", true, ["verify"]);
  const scopeWire = Object.fromEntries(Object.entries(state.scope).map(([k, v]) => [k, b64(v)]));
  const makeGrant = async (overrides = {}) => {
    const digest = await v2.recoveryManifestDigestV2(head);
    const body = {
      schema: "rootark-zk1-browser-owner-device-grant/v1",
      ...scopeWire, device_id: device.device_id,
      authorization_key_id: b64(device.authorization_key_id),
      authorization_public_key: b64(device.authorization_public_key),
      manifest_revision: head.revision, manifest_digest: b64(digest),
      current_epoch: head.current_epoch, enrolled_epoch: device.enrolled_epoch,
      revoked_at_epoch: device.revoked_at_epoch, ...overrides,
    };
    const canonical = Object.fromEntries(grantFields.map((key) => [key, body[key]]));
    const signature = crypto.sign(null, Buffer.concat([
      grantDomain, Buffer.from(JSON.stringify(canonical)),
    ]), owner.privateKey);
    return { ...canonical, signature: b64(signature) };
  };
  const currentHead = async () => ({
    revision: head.revision, digest: await v2.recoveryManifestDigestV2(head),
    epoch: head.current_epoch,
  });
  const app = express();
  let putCount = 0;
  app.use((req, _res, next) => {
    if (req.path === "/zk-1/v1/content/put") putCount++;
    next();
  });
  const store = new Zk1ProtectedObjectStore(path.join(folder, "store.sqlite"), {
    trustedScope: state.scope, bootstrapNew: true, admissionRequired: true,
    minimumHead: { revision: 1, witnessSequence: 1, digest: baseDigest },
    witnessProvider: {
      async freshHead({ nonce }) {
        const unsigned = {
          type: "rootark-recovery-witness-head/v1",
          witness_key_id: witnessKeyId, ...state.scope, nonce,
          current_revision: head.revision,
          current_manifest_digest: await v2.recoveryManifestDigestV2(head),
          witness_sequence: head.revision,
          observed_at: clock, status: "committed", pending_reservation_id: null,
        };
        return z.encodeDeterministic({ ...unsigned, signature: crypto.sign(null,
          Buffer.concat([witnessDomain, Buffer.from(await z.encodeDeterministic(unsigned))]),
          witness.privateKey) });
      },
      async beginIoAdmission() { return { admissionId: crypto.randomBytes(16), proceed: true }; },
      async finishIoAdmission() { return { status: "FINISHED" }; },
    },
    witnessPinned: { keyId: witnessKeyId, publicKey: witness.publicKey },
    manifestProvider: () => z.encodeDeterministic(head),
    nowSeconds: () => clock,
  });
  registerZk1ProtectedObjectRoutes({
    app, store,
    authenticate: (req, _res, next) => { req.user = { username: "synthetic" }; next(); },
    requirePermission: () => (_req, _res, next) => next(),
    resolveTrustedScope: () => state.scope,
  });
  const html = fs.readFileSync(path.join(__dirname, "../dev-ui/zk1-protected-file-lab.html"), "utf8");
  app.get("/zk1-protected-file-lab.html", (_req, res) =>
    res.type("html").set("Content-Security-Policy", "default-src 'self'; script-src 'self'; connect-src 'self'").send(
      html.replace("</body>", '<script defer src="/__probe.js"></script></body>')));
  for (const script of scriptNames) {
    // These exact test assets live inside an isolated .worktrees ancestor.
    // Express sendFile defaults to ignoring dot-path segments and may return
    // 404 even though the allowlisted JavaScript file exists on disk.
    // Permit that ancestor only for each explicitly registered test route.
    app.get("/client/" + script + ".js", (_req, res) => res.type("application/javascript")
      .sendFile(path.join(__dirname, "../public/client", script + ".js"),
        { dotfiles: "allow" }));
  }
  let probe = "";
  app.get("/__probe.js", (_req, res) => res.type("application/javascript").send(probe));
  const server = await new Promise((resolve) => {
    const value = app.listen(0, "127.0.0.1", () => resolve(value));
  });
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    store.close();
    fs.rmSync(folder, { recursive: true, force: true });
  });
  const origin = "http://127.0.0.1:" + server.address().port;
  const fetchImpl = async (url, opts) => fetch(url, opts);
  const options = async () => ({
    ownerPublicKey, pinnedOwnerKeyHash: crypto.createHash("sha256").update(ownerRaw).digest(),
    pinnedCurrentHead: await currentHead(), signedDeviceGrant: await makeGrant(),
    devicePublicKey, devicePrivateKey,
    metadata: { ...scopeWire, object_id: id(), version_id: id(),
      parent_version_id: null, epoch: head.current_epoch, kind: "file" },
    fileName: "local-secret.txt", mediaType: "text/plain",
    data: Buffer.from("Unique browser owner plaintext is never stored on server."),
    origin, fetchImpl, nowSeconds: clock,
  });
  return { options, makeGrant, currentHead, store, ownerRaw,
    ownerPrivate: owner.privateKey, privateDer, device,
    origin, state, setHead: (next) => { head = next; },
    get putCount() { return putCount; },
    setProbe(value) { probe = value; } };
}

test("normal browser uploads ciphertext and confirms real localhost HTTP protected GET", async (t) => {
  const f = await setup(t);
  const args = await f.options();
  const result = await normal.uploadAndVerify(args);
  assert.equal(result.protectedHttpReadbackVerified, true);
  assert.equal(result.ownerAndDeviceCheckedLocally, true);
  assert.equal(result.independentDurableWriteProven, false);
  assert.equal(result.persistentKeyRecoveryAvailable, false);
  assert.equal(f.putCount, 1);
  const stored = f.store.db.prepare("SELECT ciphertext FROM zk_content_object WHERE id=?")
    .get(args.metadata.object_id).ciphertext;
  assert.ok(!stored.includes(args.data));
  assert.ok(!stored.toString().includes(args.fileName));
});

test("normal workspace capability and protected PUT/GET enforce real cookie session, CSRF, permissions, owner scope and revocation", async (t) => {
  const f = await setup(t);
  const secret = crypto.randomBytes(32).toString("hex");
  const people = new Map([
    ["owner", { username: "owner", sessionVersion: 0,
      permissions: { listFiles: true, upload: true } }],
    ["outsider", { username: "outsider", sessionVersion: 0,
      permissions: { listFiles: true, upload: true } }],
    ["viewer", { username: "viewer", sessionVersion: 0,
      permissions: { listFiles: true, upload: false } }],
  ]);
  const authenticate = createAuthenticate({ jwt, jwtSecret: secret,
    loadUser: (username) => people.get(username),
    normalizeUserPermissions: (user) => user.permissions });
  const app = express();
  registerZk1ProtectedObjectRoutes({ app, store: f.store, authenticate,
    requirePermission: createRequirePermission(),
    resolveTrustedScope: (user) => user?.username === "owner" ? f.state.scope : null });
  const server = await new Promise((resolve) => {
    const value = app.listen(0, "127.0.0.1", () => resolve(value));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const cookie = (username, version = 0) =>
    `rootark_session=${jwt.sign({ username, sessionVersion: version }, secret, { expiresIn: "10m" })}; rootark_csrf=workspace-fixture`;
  const request = (name, pathname, options = {}) => fetch(origin + pathname, {
    ...options, headers: { ...(options.headers || {}), ...(name ? { cookie: cookie(name) } : {}) },
  });
  const capabilityPath = "/zk-1/v1/workspace-capability";
  assert.equal((await request(null, capabilityPath)).status, 401);
  assert.equal((await request("outsider", capabilityPath)).status, 403);
  assert.equal((await request("viewer", capabilityPath)).status, 403);
  const ownerCapability = await request("owner", capabilityPath);
  assert.equal(ownerCapability.status, 200);
  assert.deepEqual(await ownerCapability.json(), { enabled: true });
  assert.equal(ownerCapability.headers.get("cache-control"), "no-store");
  assert.equal((await fetch(origin + capabilityPath, {
    headers: { cookie: cookie("owner", 99) } })).status, 401);
  for (const endpoint of ["put", "read"]) {
    const name = endpoint === "put" ? "/zk-1/v1/content/put" : "/zk-1/v1/content/read";
    const post = (who, csrf) => request(who, name, { method: "POST",
      headers: { "content-type": "application/json", ...(csrf ? { "X-CSRF-Token": "workspace-fixture" } : {}) },
      body: JSON.stringify({}),
    });
    assert.equal((await post(null, true)).status, 401);
    assert.equal((await post("owner", false)).status, 403);
    assert.equal((await post("outsider", true)).status, 403);
    if (endpoint === "put") assert.equal((await post("viewer", true)).status, 403);
    assert.equal((await post("owner", true)).status, 403, "invalid signed authorization rejected");
  }
  const options = await f.options();
  options.origin = origin;
  options.fetchImpl = (url, init) => fetch(url, {
    ...init, headers: { ...init.headers, "X-CSRF-Token": "workspace-fixture",
      cookie: cookie("owner") },
  });
  const verified = await normal.uploadAndVerify(options);
  assert.equal(verified.protectedHttpReadbackVerified, true,
    "real cookie-authenticated PUT + signed readback succeeded");
  const stored = f.store.db.prepare("SELECT ciphertext FROM zk_content_object WHERE id=?")
    .get(options.metadata.object_id).ciphertext;
  assert.equal(stored.includes(options.data), false);
  assert.equal(stored.toString().includes(options.fileName), false);
  const count = f.store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_object").get().n;
  const revoked = await fixtures.appendDeviceRevocation(f.state, f.device.device_id);
  f.setHead(revoked);
  await assert.rejects(normal.uploadAndVerify({ ...options,
    metadata: { ...options.metadata, object_id: id(), version_id: id() } }),
    /ZK_NORMAL_BROWSER_AUTHORITY_UNVERIFIED/);
  assert.equal(f.store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_object").get().n, count);
});

test("new browser session opens an owner-pinned ciphertext through real signed HTTP GET with only user-held secret", async (t) => {
  const f = await setup(t);
  const opts = await f.options();
  const offlineSecret = portable.generateRecoverySecret();
  const bundle = await portable.sealForUserHeldSecret({
    recoverySecret: offlineSecret, metadata: opts.metadata,
    name: opts.fileName, mediaType: opts.mediaType, data: opts.data,
  });
  const signer = {
    signerKey: opts.devicePrivateKey,
    scope: Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
      .map((key) => [key, opts.metadata[key]])),
    deviceId: opts.signedDeviceGrant.device_id,
    manifestRevision: opts.pinnedCurrentHead.revision,
    manifestDigest: opts.pinnedCurrentHead.digest,
    epoch: opts.pinnedCurrentHead.epoch,
    nowSeconds: opts.nowSeconds,
  };
  const encoded = Buffer.from(bundle.ciphertextBase64, "base64url");
  const signedPut = await protectedHttp.signProtectedContentOperation({
    ...signer, operation: "put", objectId: opts.metadata.object_id,
    expectedObjectRevision: null, ciphertext: encoded,
  });
  await protectedHttp.postProtectedCiphertextPut({
    origin: opts.origin, request: signedPut, fetchImpl: opts.fetchImpl,
  });
  const root = Buffer.from(bundle.ciphertextRoot, "base64url");
  const independentOwnerSpkiSha256 = crypto.createHash("sha256").update(
    Buffer.from(await crypto.webcrypto.subtle.exportKey("spki", opts.ownerPublicKey))).digest();
  const expected = {
    ownerPublicKey: opts.ownerPublicKey,
    pinnedOwnerKeyHash: opts.pinnedOwnerKeyHash,
    independentOwnerSpkiSha256,
    pinnedCurrentHead: opts.pinnedCurrentHead,
    signedDeviceGrant: opts.signedDeviceGrant,
    devicePublicKey: opts.devicePublicKey,
    devicePrivateKey: opts.devicePrivateKey,
    ownerHistoryCheckpoint: null,
    recoverySecret: offlineSecret, bundle,
    expectedMetadata: opts.metadata, independentlyPinnedCiphertextRoot: root,
    origin: opts.origin, fetchImpl: opts.fetchImpl, nowSeconds: opts.nowSeconds,
  };
  let wire = "";
  const recovered = await browserRestore.recoverFromProtectedGet({
    ...expected, fetchImpl: (url, request) => {
      wire = String(request.body || "");
      return opts.fetchImpl(url, request);
    },
  });
  assert.deepEqual(Buffer.from(recovered.data), Buffer.from(opts.data));
  assert.equal(recovered.historicalGetVerified, true);
  assert.equal(recovered.localUserSecretOpened, true);
  assert.equal(recovered.authorizesProductionRestore, false);
  assert.equal(wire.includes(opts.fileName), false);
  assert.equal(wire.includes(new TextDecoder().decode(opts.data)), false);
  assert.equal(wire.includes(offlineSecret.toString("base64url")), false);
  recovered.data.fill(0);
  // A separate owner-held Ed25519 signature and matching first owner-history
  // checkpoint now attest the exact archived root before plaintext release.
  const ownerSigner = await crypto.webcrypto.subtle.importKey("pkcs8",
    f.ownerPrivate.export({ format: "der", type: "pkcs8" }),
    "Ed25519", false, ["sign"]);
  const rootSignerKeyId = crypto.randomBytes(16);
  const ownerDeviceId = "offline-owner-root";
  const ownerHistoryCheckpoint = await ownerHistory.signOwnerCheckpoint({
    scope: signer.scope, signerKey: ownerSigner, signerPublicKey: opts.ownerPublicKey,
    signerKeyId: rootSignerKeyId, deviceId: ownerDeviceId,
    revision: opts.pinnedCurrentHead.revision,
    manifestDigest: opts.pinnedCurrentHead.digest,
    issuedAt: opts.nowSeconds, previous: null,
  });
  const ownerRootCheckpoint = await ownerRoots.signOwnerCiphertextRootCheckpoint({
    scope: signer.scope, signerKey: ownerSigner, signerKeyId: rootSignerKeyId,
    deviceId: ownerDeviceId,
    manifestRevision: opts.pinnedCurrentHead.revision,
    manifestDigest: opts.pinnedCurrentHead.digest,
    manifestEpoch: opts.pinnedCurrentHead.epoch,
    objectId: opts.metadata.object_id, objectRevision: 1,
    ciphertextEpoch: opts.metadata.epoch, ciphertextRoot: root,
    issuedAt: opts.nowSeconds,
  });
  const signedRequest = { ...expected, ownerHistoryCheckpoint,
    ownerRootCheckpoint, ownerSignerKeyId: rootSignerKeyId.toString("base64url"),
    ownerDeviceId, previousOwnerHistoryProof: null };
  const signedRecovery = await browserRestore.recoverFromOwnerSignedProtectedGet(signedRequest);
  assert.deepEqual(Buffer.from(signedRecovery.data), Buffer.from(opts.data));
  assert.equal(signedRecovery.ownerSignedHistoricalRootVerified, true);
  assert.equal(signedRecovery.externalOwnerKeyOriginVerifiedByModule, false);
  signedRecovery.data.fill(0);
  const firstOwnerHistoryProof = await ownerHistory.verifyOwnerCheckpoint({
    checkpoint: ownerHistoryCheckpoint, scope: signer.scope,
    signerPublicKey: opts.ownerPublicKey, signerKeyId: rootSignerKeyId,
    previous: null,
  });
  const secondOwnerHistoryCheckpoint = await ownerHistory.signOwnerCheckpoint({
    scope: signer.scope, signerKey: ownerSigner, signerPublicKey: opts.ownerPublicKey,
    signerKeyId: rootSignerKeyId, deviceId: ownerDeviceId,
    revision: opts.pinnedCurrentHead.revision,
    manifestDigest: opts.pinnedCurrentHead.digest,
    issuedAt: opts.nowSeconds + 1, previous: firstOwnerHistoryProof,
  });
  const secondHistoryRequest = { ...signedRequest,
    ownerHistoryCheckpoint: secondOwnerHistoryCheckpoint,
    previousOwnerHistoryProof: firstOwnerHistoryProof };
  const secondHistoryResult = await browserRestore.recoverFromOwnerSignedProtectedGet(
    secondHistoryRequest);
  assert.equal(secondHistoryResult.ownerSignedHistoricalRootVerified, true);
  secondHistoryResult.data.fill(0);
  let badProofReachedNetwork = 0;
  const denySignedProof = (changes) => assert.rejects(
    browserRestore.recoverFromOwnerSignedProtectedGet({
      ...signedRequest, ...changes,
      fetchImpl: (...args) => { badProofReachedNetwork++; return opts.fetchImpl(...args); },
    }), /ZK_BROWSER_RECOVERY_HTTP_DENIED/);
  await denySignedProof({ ownerRootCheckpoint: { ...ownerRootCheckpoint,
    signature: crypto.randomBytes(64).toString("base64url") } });
  await denySignedProof({ ownerDeviceId: "forged-owner" });
  await denySignedProof({ ownerSignerKeyId: crypto.randomBytes(16).toString("base64url") });
  await denySignedProof({ ownerHistoryCheckpoint: null });
  await denySignedProof({ ownerHistoryCheckpoint: secondOwnerHistoryCheckpoint,
    previousOwnerHistoryProof: null });
  await denySignedProof({ ownerHistoryCheckpoint: secondOwnerHistoryCheckpoint,
    previousOwnerHistoryProof: { signedCheckpointVerified: true } });
  await denySignedProof({ independentlyPinnedCiphertextRoot: crypto.randomBytes(32) });
  assert.equal(badProofReachedNetwork, 0, "invalid owner history/root never contacts server");
  for (const bad of [
    { recoverySecret: crypto.randomBytes(32) },
    { independentlyPinnedCiphertextRoot: crypto.randomBytes(32) },
    { expectedMetadata: { ...opts.metadata, epoch: opts.metadata.epoch + 1 } },
    { bundle: { ...bundle, ciphertextSha256: crypto.randomBytes(32).toString("base64url") } },
  ]) await assert.rejects(browserRestore.recoverFromProtectedGet({
    ...expected, ...bad,
  }), /ZK_BROWSER_RECOVERY_HTTP_DENIED/);
  // Rotating the current epoch after revoking ANOTHER device must not make
  // this device unable to read its genuine historical ciphertext/old CEK.
  const other = f.state.headManifest.devices.find((device) =>
    device.device_id !== f.device.device_id);
  assert.ok(other);
  const rotated = await fixtures.appendDeviceRevocation(f.state, other.device_id);
  f.setHead(rotated);
  const current = await f.currentHead();
  const currentGrant = await f.makeGrant();
  const reopenedAfterRotation = await browserRestore.recoverFromProtectedGet({
    ...expected, pinnedCurrentHead: current,
    signedDeviceGrant: currentGrant,
  });
  assert.deepEqual(Buffer.from(reopenedAfterRotation.data), Buffer.from(opts.data));
  reopenedAfterRotation.data.fill(0);
  const nextMetadata = { ...opts.metadata, version_id: id(),
    parent_version_id: opts.metadata.version_id, epoch: current.epoch };
  const nextFile = Buffer.from("rev2 remains protected and individually recoverable");
  const nextBundle = await portable.sealForUserHeldSecret({
    recoverySecret: offlineSecret, metadata: nextMetadata,
    objectRevision: 2, name: "revision-2.txt",
    mediaType: "text/plain", data: nextFile,
  });
  const signedSecondPut = await protectedHttp.signProtectedContentOperation({
    ...signer, manifestRevision: current.revision,
    manifestDigest: current.digest, epoch: current.epoch,
    operation: "put", objectId: opts.metadata.object_id,
    expectedObjectRevision: 1,
    ciphertext: Buffer.from(nextBundle.ciphertextBase64, "base64url"),
  });
  await protectedHttp.postProtectedCiphertextPut({
    origin: opts.origin, request: signedSecondPut, fetchImpl: opts.fetchImpl,
  });
  const revision2 = await browserRestore.recoverFromProtectedGet({
    ...expected, pinnedCurrentHead: current,
    signedDeviceGrant: currentGrant, bundle: nextBundle,
    expectedMetadata: nextMetadata,
    independentlyPinnedCiphertextRoot: Buffer.from(nextBundle.ciphertextRoot, "base64url"),
  });
  assert.equal(revision2.name, "revision-2.txt");
  assert.deepEqual(Buffer.from(revision2.data), nextFile);
  revision2.data.fill(0);
  const stillArchived = await browserRestore.recoverFromProtectedGet({
    ...expected, pinnedCurrentHead: current, signedDeviceGrant: currentGrant,
  });
  assert.deepEqual(Buffer.from(stillArchived.data), Buffer.from(opts.data));
  stillArchived.data.fill(0);
  const future = await f.currentHead();
  assert.ok(future.epoch > opts.metadata.epoch);
  await assert.rejects(browserRestore.recoverFromProtectedGet({
    ...expected, pinnedCurrentHead: current,
    signedDeviceGrant: currentGrant,
    expectedMetadata: { ...opts.metadata, epoch: future.epoch + 1 },
  }), /ZK_BROWSER_RECOVERY_HTTP_DENIED/);
  const revoked = await fixtures.appendDeviceRevocation(f.state, f.device.device_id);
  f.setHead(revoked);
  await assert.rejects(browserRestore.recoverFromProtectedGet(expected),
    /ZK_BROWSER_RECOVERY_HTTP_DENIED/,
    "a cached old signed grant cannot bypass a more recent server revocation");
  offlineSecret.fill(0);
});

test("negative owner, head, grant, active device, epoch and mutation fail before HTTP", async (t) => {
  const f = await setup(t);
  const base = await f.options();
  let calls = 0;
  const blocked = (overrides) => assert.rejects(normal.uploadAndVerify({
    ...base, ...overrides, metadata: overrides.metadata ?? { ...base.metadata },
    fetchImpl: async (...args) => { calls++; return base.fetchImpl(...args); },
  }), /ZK_NORMAL_BROWSER_AUTHORITY_UNVERIFIED/);
  await blocked({ pinnedOwnerKeyHash: crypto.randomBytes(32) });
  await blocked({ pinnedCurrentHead: { ...base.pinnedCurrentHead, revision: 1 } });
  await blocked({ pinnedCurrentHead: { ...base.pinnedCurrentHead, digest: crypto.randomBytes(32) } });
  await blocked({ pinnedCurrentHead: null });
  await blocked({ signedDeviceGrant: { ...base.signedDeviceGrant,
    revoked_at_epoch: undefined } });
  await blocked({ signedDeviceGrant: { ...base.signedDeviceGrant, signature: b64(crypto.randomBytes(64)) } });
  await blocked({ signedDeviceGrant: await f.makeGrant({ revoked_at_epoch: 2 }) });
  await blocked({ signedDeviceGrant: await f.makeGrant({ authorization_public_key: b64(crypto.randomBytes(32)) }) });
  await blocked({ metadata: { ...base.metadata, epoch: base.metadata.epoch + 1 } });
  await blocked({ metadata: { ...base.metadata, keyring_id: id() } });
  const other = crypto.generateKeyPairSync("ed25519");
  const otherPrivate = await crypto.webcrypto.subtle.importKey("pkcs8",
    other.privateKey.export({ format: "der", type: "pkcs8" }),
    "Ed25519", false, ["sign"]);
  await blocked({ devicePrivateKey: otherPrivate });
  assert.equal(calls, 0);
  assert.equal(f.putCount, 0);
});

test("server advances to revoked signed head after local pin: protected request fails closed", async (t) => {
  const f = await setup(t);
  const opts = await f.options();
  const revoked = await fixtures.appendDeviceRevocation(f.state, f.device.device_id);
  f.setHead(revoked);
  await assert.rejects(normal.uploadAndVerify(opts), /ZK_NORMAL_BROWSER_AUTHORITY_UNVERIFIED/);
  assert.equal(f.store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_object").get().n, 0);
});

test("lost PUT HTTP ACK reconciles by single historical GET without retrying PUT", async (t) => {
  const f = await setup(t);
  const opts = await f.options();
  let lost = false;
  opts.fetchImpl = async (url, options) => {
    const response = await fetch(url, options);
    if (url.endsWith("/content/put")) {
      lost = true;
      throw new Error("synthetic socket drop after commit");
    }
    return response;
  };
  const result = await normal.uploadAndVerify(opts);
  assert.equal(lost, true);
  assert.equal(result.lostPutAckReconciled, true);
  assert.equal(result.protectedHttpReadbackVerified, true);
  assert.equal(f.putCount, 1);
});

test("unexpected ciphertext and metadata in GET response never pass local readback", async (t) => {
  for (const attack of ["ciphertext", "epoch", "other-object"]) {
    const f = await setup(t);
    const opts = await f.options();
    opts.fetchImpl = async (url, options) => {
      const response = await fetch(url, options);
      if (!url.endsWith("/content/read") || response.status !== 200) return response;
      const body = await response.json();
      if (attack === "ciphertext") body.ciphertextBase64 = b64(crypto.randomBytes(64));
      if (attack === "epoch") body.epoch += 1;
      if (attack === "other-object") body.id = id();
      return new Response(JSON.stringify(body), { status: 200,
        headers: { "content-type": "application/json" } });
    };
    await assert.rejects(normal.uploadAndVerify(opts),
      /ZK_NORMAL_BROWSER_AUTHORITY_UNVERIFIED/, attack);
    assert.equal(f.putCount, 1);
  }
});

test("Edge WebCrypto executes normal file PUT/GET using actual localhost Express, under CSP", {
  timeout: 65_000,
}, async (t) => {
  if (process.platform !== "win32" || !fs.existsSync(EDGE)) {
    t.skip("Edge Windows browser unavailable");
    return;
  }
  const f = await setup(t);
  const opts = await f.options();
  for (const script of scriptNames) {
    const asset = await fetch(f.origin + "/client/" + script + ".js");
    assert.equal(asset.status, 200, "explicit browser test script " + script);
    assert.match(asset.headers.get("content-type") || "", /javascript/);
    await asset.arrayBuffer();
  }
  assert.equal((await fetch(f.origin + "/client/unlisted-fixture.js")).status, 404,
    "test Express routes expose only explicitly enumerated browser scripts");
  const values = {
    ownerRaw: b64(f.ownerRaw), ownerHash: b64(opts.pinnedOwnerKeyHash),
    ownerPrivate: b64(f.ownerPrivate.export({ type: "pkcs8", format: "der" })),
    ownerSpkiHash: b64(crypto.createHash("sha256").update(Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"), f.ownerRaw])).digest()),
    deviceRaw: b64(f.device.authorization_public_key), privateDer: b64(f.privateDer),
    pin: { revision: opts.pinnedCurrentHead.revision,
      epoch: opts.pinnedCurrentHead.epoch, digest: b64(opts.pinnedCurrentHead.digest) },
    grant: opts.signedDeviceGrant, scope: Object.fromEntries(
      ["account_id", "compartment_id", "keyring_id"].map((field) =>
        [field, opts.metadata[field]])),
    now: opts.nowSeconds, objectId: opts.metadata.object_id, versionId: opts.metadata.version_id,
  };
  // Synthetic key material is served only by this disposable browser test.
  f.setProbe(`window.addEventListener("load",async()=>{const output=document.createElement("output");
output.id="edge-normal-result";document.body.append(output);
const v=${JSON.stringify(values)};
function decode(s){return Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-s.length%4)%4)),x=>x.charCodeAt(0));}
function inputFile(id,data,name){const dt=new DataTransfer();dt.items.add(new File([data],name));
document.getElementById(id).files=dt.files;}
try {inputFile("owner-key",decode(v.ownerRaw),"owner.raw");
inputFile("device-public",decode(v.deviceRaw),"device.raw");
inputFile("device-private",decode(v.privateDer),"device.pkcs8");
inputFile("device-grant",new TextEncoder().encode(JSON.stringify(v.grant)),"grant.json");
inputFile("file",new TextEncoder().encode("WebCrypto Edge real HTTP protected content"),"edge-normal.txt");
document.getElementById("owner-hash").value=v.ownerHash;
document.getElementById("owner-spki-hash").value=v.ownerSpkiHash;
document.getElementById("head-revision").value=String(v.pin.revision);
document.getElementById("head-digest").value=v.pin.digest;
document.getElementById("head-epoch").value=String(v.pin.epoch);
document.getElementById("provision-owner").click();
for(let i=0;i<50;i++){await new Promise(resolve=>setTimeout(resolve,50));
if(document.getElementById("status").textContent.includes("Âncora local criada"))break;}
if(!document.getElementById("status").textContent.includes("Âncora local criada"))throw Error("NO_FLOOR:"+document.getElementById("status").textContent);
document.getElementById("upload").click();
for(let i=0;i<80;i++){await new Promise(resolve=>setTimeout(resolve,100));
const status=document.getElementById("status").textContent;
if(status.includes("Ciphertext conferido")){
  if(document.getElementById("device-private").files.length!==0
    || document.getElementById("file").files.length!==0)throw Error("INPUT_RETAINED");
  const portable=window.RootarkZk1PortableFileRecovery;
  const originalSeal=portable.sealForUserHeldSecret;
  let generatedBundle=null;
  window.RootarkZk1PortableFileRecovery=Object.freeze({...portable,
    sealForUserHeldSecret:async(value)=>{generatedBundle=await originalSeal(value);return generatedBundle;}});
  const secret=crypto.getRandomValues(new Uint8Array(32));
  inputFile("device-private",decode(v.privateDer),"device.pkcs8");
  inputFile("portable-secret",secret,"saved-secret.bin");
  inputFile("file",new TextEncoder().encode("Portable Edge protected content"),"recovery.txt");
  document.getElementById("portable-publish").click();
  let wrote=false;
  for(let k=0;k<80;k++){await new Promise(resolve=>setTimeout(resolve,100));
    if(document.getElementById("status").textContent.includes("Ciphertext enviado e GET autenticado")){wrote=true;break;}}
  if(!wrote || !generatedBundle)throw Error("PORTABLE_PUBLISH_FAILED:"+document.getElementById("status").textContent);
  const signer=await crypto.subtle.importKey("pkcs8",decode(v.ownerPrivate),"Ed25519",false,["sign"]);
  const signedOwnerPublic=await crypto.subtle.importKey("raw",decode(v.ownerRaw),"Ed25519",true,["verify"]);
  const ownerKeyId=crypto.getRandomValues(new Uint8Array(16));
  const historyCheckpoint=await window.RootarkZk1OwnerSignedCheckpoint.signOwnerCheckpoint({
    scope:v.scope,signerKey:signer,signerPublicKey:signedOwnerPublic,
    signerKeyId:ownerKeyId,deviceId:"test-independent-owner",revision:v.pin.revision,
    manifestDigest:decode(v.pin.digest),issuedAt:v.now,previous:null});
  const proof1=await window.RootarkZk1OwnerSignedCheckpoint.verifyOwnerCheckpoint({
    checkpoint:historyCheckpoint,scope:v.scope,signerPublicKey:signedOwnerPublic,
    signerKeyId:ownerKeyId,previous:null});
  const historyCheckpoint2=await window.RootarkZk1OwnerSignedCheckpoint.signOwnerCheckpoint({
    scope:v.scope,signerKey:signer,signerPublicKey:signedOwnerPublic,
    signerKeyId:ownerKeyId,deviceId:"test-independent-owner",revision:v.pin.revision,
    manifestDigest:decode(v.pin.digest),issuedAt:v.now+1,previous:proof1});
  const checkpoint=await window.RootarkZk1OwnerCiphertextRootCheckpoint.signOwnerCiphertextRootCheckpoint({
    scope:v.scope,signerKey:signer,signerKeyId:ownerKeyId,deviceId:"test-independent-owner",
    manifestRevision:v.pin.revision,manifestDigest:decode(v.pin.digest),
    manifestEpoch:v.pin.epoch,objectId:generatedBundle.metadata.object_id,
    objectRevision:generatedBundle.objectRevision,
    ciphertextEpoch:generatedBundle.metadata.epoch,
    ciphertextRoot:decode(generatedBundle.ciphertextRoot),issuedAt:v.now});
  inputFile("device-private",decode(v.privateDer),"device.pkcs8");
  inputFile("portable-secret",secret,"saved-secret.bin");
  inputFile("portable-bundle",new TextEncoder().encode(JSON.stringify(generatedBundle)),"bundle.json");
  inputFile("owner-history",new TextEncoder().encode(JSON.stringify([historyCheckpoint,historyCheckpoint2])),"owner-history.json");
  inputFile("portable-owner-root",new TextEncoder().encode(JSON.stringify(checkpoint)),"owner-root.json");
  document.getElementById("portable-restore").click();
  let restored=false;
  for(let k=0;k<80;k++){await new Promise(resolve=>setTimeout(resolve,100));
    if(document.getElementById("status").textContent.includes("GET protegido, assinatura da raiz do proprietário e abertura local concluídos")){restored=true;break;}}
  secret.fill(0);
  if(!restored || document.getElementById("portable-secret").files.length!==0
    || document.getElementById("device-private").files.length!==0)
      throw Error("PORTABLE_RESTORE_FAILED:"+document.getElementById("status").textContent);
  output.textContent="EDGE_NORMAL_HTTP_PASS";break;}
if(status.includes("Operação recusada")){output.textContent="EDGE_NORMAL_HTTP_FAIL";break;}}
if(!output.textContent)output.textContent="EDGE_NORMAL_HTTP_TIMEOUT";
}catch(e){output.textContent="EDGE_NORMAL_HTTP_FAIL:"+e.message;}});`);
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-edge-normal-"));
  const profile = path.join(folder, "profile");
  const args = ["--headless=new", "--disable-gpu", "--no-first-run", "--disable-extensions",
    "--remote-debugging-port=0", "--user-data-dir=" + profile, "about:blank"];
  let edge;
  let socket;
  try {
    edge = spawn(EDGE, args, { stdio: "ignore", windowsHide: true });
    const waitFor = async (fn, maxMs = 20000) => {
      const deadline = Date.now() + maxMs;
      while (Date.now() < deadline) {
        const got = await fn();
        if (got) return got;
        await new Promise((resolve) => setTimeout(resolve, 90));
      }
      throw new Error("Edge normal browser probe timeout");
    };
    const port = await waitFor(() => {
      const file = path.join(profile, "DevToolsActivePort");
      if (!fs.existsSync(file)) return null;
      const n = Number(fs.readFileSync(file, "utf8").split(/\r?\n/)[0]);
      return Number.isSafeInteger(n) && n > 0 ? n : null;
    });
    const tabs = await (await fetch("http://127.0.0.1:" + port + "/json/list")).json();
    const tab = tabs.find((item) => item.type === "page");
    assert.ok(tab?.webSocketDebuggerUrl);
    socket = new WebSocket(tab.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      socket.addEventListener("open", resolve, { once: true });
      socket.addEventListener("error", reject, { once: true });
    });
    const inflight = new Map();
    let sequence = 0;
    socket.addEventListener("message", ({ data }) => {
      const message = JSON.parse(data);
      if (!inflight.has(message.id)) return;
      const { resolve, reject } = inflight.get(message.id);
      inflight.delete(message.id);
      if (message.error) reject(new Error(message.error.message));
      else resolve(message.result);
    });
    const send = (method, params = {}) => new Promise((resolve, reject) => {
      const id = ++sequence;
      inflight.set(id, { resolve, reject });
      socket.send(JSON.stringify({ id, method, params }));
    });
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Page.navigate", { url: f.origin + "/zk1-protected-file-lab.html" });
    const evidence = await waitFor(async () => {
      const evaluated = await send("Runtime.evaluate", {
        expression: "document.getElementById('edge-normal-result')?.textContent || null",
        returnByValue: true,
      });
      const value = evaluated.result?.value;
      return typeof value === "string" && /^(EDGE_NORMAL_HTTP_PASS|EDGE_NORMAL_HTTP_FAIL|EDGE_NORMAL_HTTP_TIMEOUT)/.test(value)
        ? value : null;
    });
    assert.equal(evidence, "EDGE_NORMAL_HTTP_PASS");
    assert.equal(f.putCount, 2,
      "one ordinary PUT and one portable recovery PUT, no retry during signed GET");
  } finally {
    socket?.close();
    if (edge?.pid) {
      try { execFileSync("taskkill", ["/PID", String(edge.pid), "/T", "/F"],
        { stdio: "ignore", timeout: 10000 }); } catch (_) { edge.kill(); }
    }
    let removed = false;
    for (let attempt = 0; attempt < 20; attempt++) {
      try {
        fs.rmSync(folder, { recursive: true, force: true });
        removed = true;
        break;
      } catch (error) {
        if (!["EPERM", "EBUSY", "ENOTEMPTY"].includes(error.code)) throw error;
        await new Promise((resolve) => setTimeout(resolve, 180));
      }
    }
    if (!removed) process.stderr.write("EDGE_NORMAL_TEST_PROFILE_CLEANUP_PENDING\n");
  }
});

test("Edge normal authenticated workspace dialog provisions offline owner and PUT/GET through cookie CSRF", {
  timeout: 65_000,
}, async (t) => {
  if (process.platform !== "win32" || !fs.existsSync(EDGE)) {
    t.skip("Edge Windows browser unavailable");
    return;
  }
  const f = await setup(t);
  const opts = await f.options();
  const secret = crypto.randomBytes(32).toString("hex");
  const session = jwt.sign({ username: "owner", sessionVersion: 0 }, secret,
    { expiresIn: "10m" });
  const app = express();
  let protectedPuts = 0;
  app.use((req, _res, next) => {
    if (req.path === "/zk-1/v1/content/put") protectedPuts++;
    next();
  });
  const authenticate = createAuthenticate({ jwt, jwtSecret: secret,
    loadUser: (name) => name === "owner" ? { username: name, sessionVersion: 0,
      permissions: { listFiles: true, upload: true } } : null,
    normalizeUserPermissions: (user) => user.permissions });
  registerZk1ProtectedObjectRoutes({ app, store: f.store, authenticate,
    requirePermission: createRequirePermission(),
    resolveTrustedScope: (user) => user?.username === "owner" ? f.state.scope : null });
  const scripts = new Set(["rootark-api", "rootark-zk1-authenticated-workspace",
    ...scriptNames]);
  app.get("/client/:asset", (req, res) => {
    const name = req.params.asset.endsWith(".js") ? req.params.asset.slice(0, -3) : "";
    if (!scripts.has(name)) return res.sendStatus(404);
    return res.type("application/javascript").sendFile(path.join(
      __dirname, "../public/client", name + ".js"), { dotfiles: "allow" });
  });
  app.get("/workspace-test", authenticate, (req, res) => res.type("html")
    .set("Content-Security-Policy", "default-src 'self'; script-src 'self'; connect-src 'self'")
    .send('<!doctype html><html><head><meta charset="utf-8">'
      + '<script defer src="/client/rootark-api.js"></script>'
      + '<script defer src="/client/rootark-zk1-authenticated-workspace.js"></script>'
      + '<script defer src="/workspace-probe.js"></script></head><body>'
      + '<section class="protected-client-panel"><p id="protectedClientStatus"></p></section>'
      + '</body></html>'));
  const values = { ownerRaw: b64(f.ownerRaw), ownerHash: b64(opts.pinnedOwnerKeyHash),
    ownerSpkiHash: b64(crypto.createHash("sha256").update(Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"), f.ownerRaw])).digest()),
    deviceRaw: b64(f.device.authorization_public_key), privateDer: b64(f.privateDer),
    grant: opts.signedDeviceGrant,
    head: { revision: opts.pinnedCurrentHead.revision,
      digest: b64(opts.pinnedCurrentHead.digest), epoch: opts.pinnedCurrentHead.epoch },
  };
  app.get("/workspace-probe.js", (_req, res) => res.type("application/javascript")
    .send(`window.addEventListener("load",async()=>{
      const output=document.createElement("output"); output.id="edge-workspace-result";
      document.body.append(output);
      const values=${JSON.stringify(values)};
      const wait=async(fn)=>{for(let i=0;i<200;i++){
        const result=fn();if(result)return result;
        await new Promise(resolve=>setTimeout(resolve,50));}throw Error("UI_TIMEOUT");};
      const decode=(s)=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
      const setFile=(name,data)=>{const dt=new DataTransfer();
        dt.items.add(new File([data],"fixture.bin"));
        document.querySelector('[data-zk1-field="'+name+'"]').files=dt.files;};
      const field=(name)=>document.querySelector('[data-zk1-field="'+name+'"]');
      try {
        window.dispatchEvent(new Event("rootark:workspace-rendered"));
        (await wait(()=>document.getElementById("zk1-workspace-open"))).click();
        await wait(()=>document.querySelector("dialog[open]"));
        setFile("owner",decode(values.ownerRaw));
        field("owner-hash").value=values.ownerHash;
        field("owner-spki").value=values.ownerSpkiHash;
        field("revision").value=values.head.revision;
        field("digest").value=values.head.digest;
        field("epoch").value=values.head.epoch;
        setFile("grant",new TextEncoder().encode(JSON.stringify(values.grant)));
        document.querySelector('[data-zk1-action="provision"]').click();
        await wait(()=>field("status").textContent.includes("Âncora offline provisionada"));
        setFile("device",decode(values.deviceRaw));
        setFile("private",decode(values.privateDer));
        setFile("file",new TextEncoder().encode("Edge normal authenticated workspace plaintext"));
        document.querySelector('[data-zk1-action="upload"]').click();
        await wait(()=>field("status").textContent.includes("PUT/GET protegidos verificados")
          || field("status").textContent.includes("Operação recusada"));
        if(!field("status").textContent.includes("PUT/GET protegidos verificados"))throw Error("OP_DENIED");
        if(field("private").files.length || field("file").files.length)throw Error("KEY_RETAINED");
        field("digest").value=values.ownerHash;
        setFile("private",decode(values.privateDer));
        setFile("file",new TextEncoder().encode("Tampered browser pinned head"));
        document.querySelector('[data-zk1-action="upload"]').click();
        await wait(()=>field("status").textContent.includes("Operação recusada"));
        output.textContent="EDGE_AUTH_WORKSPACE_PASS";
      } catch(e){output.textContent="EDGE_AUTH_WORKSPACE_FAIL:"+e.message;}
    });`));
  const server = await new Promise((resolve) => {
    const value = app.listen(0, "127.0.0.1", () => resolve(value));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = "http://127.0.0.1:" + server.address().port;
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-edge-auth-workspace-"));
  const profile = path.join(folder, "profile");
  let edge;
  let socket;
  try {
    edge = spawn(EDGE, ["--headless=new", "--disable-gpu", "--no-first-run",
      "--disable-extensions", "--remote-debugging-port=0",
      "--user-data-dir=" + profile, "about:blank"],
    { stdio: "ignore", windowsHide: true });
    const wait = async (fn) => {
      for (let count = 0; count < 200; count++) {
        const value = await fn();
        if (value) return value;
        await new Promise((resolve) => setTimeout(resolve, 80));
      }
      throw new Error("Edge authenticated workspace timed out");
    };
    const port = await wait(() => {
      const file = path.join(profile, "DevToolsActivePort");
      if (!fs.existsSync(file)) return null;
      return Number(fs.readFileSync(file, "utf8").split(/\r?\n/)[0]) || null;
    });
    const pages = await (await fetch("http://127.0.0.1:" + port + "/json/list")).json();
    socket = new WebSocket(pages.find((item) => item.type === "page").webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      socket.addEventListener("open", resolve, { once: true });
      socket.addEventListener("error", reject, { once: true });
    });
    let counter = 0;
    const pending = new Map();
    socket.addEventListener("message", ({ data }) => {
      const value = JSON.parse(data);
      if (!pending.has(value.id)) return;
      const { resolve, reject } = pending.get(value.id);
      pending.delete(value.id);
      if (value.error) reject(new Error(value.error.message));
      else resolve(value.result);
    });
    const send = (method, params = {}) => new Promise((resolve, reject) => {
      const requestId = ++counter;
      pending.set(requestId, { resolve, reject });
      socket.send(JSON.stringify({ id: requestId, method, params }));
    });
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Network.enable");
    await send("Network.setCookie", { name: "rootark_session", value: session,
      url: origin, httpOnly: true, sameSite: "Strict" });
    await send("Network.setCookie", { name: "rootark_csrf", value: "workspace-fixture",
      url: origin, sameSite: "Strict" });
    await send("Page.navigate", { url: origin + "/workspace-test" });
    const observed = await wait(async () => {
      const result = await send("Runtime.evaluate", {
        expression: "document.getElementById('edge-workspace-result')?.textContent || null",
        returnByValue: true,
      });
      const value = result.result?.value;
      return typeof value === "string" && value.startsWith("EDGE_AUTH_WORKSPACE_") ? value : null;
    });
    assert.equal(observed, "EDGE_AUTH_WORKSPACE_PASS");
    assert.equal(protectedPuts, 1, "forged external head must fail before PUT");
    assert.equal(f.store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_object").get().n, 1);
  } finally {
    socket?.close();
    if (edge?.pid) {
      try { execFileSync("taskkill", ["/PID", String(edge.pid), "/T", "/F"],
        { stdio: "ignore", timeout: 10000 }); } catch (_) { edge.kill(); }
    }
    for (let i = 0; i < 20; i++) {
      try { fs.rmSync(folder, { recursive: true, force: true }); break; }
      catch (error) {
        if (!["EPERM", "EBUSY", "ENOTEMPTY"].includes(error.code)) throw error;
        await new Promise((resolve) => setTimeout(resolve, 180));
      }
    }
  }
});
