"use strict";

const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn, execFileSync } = require("node:child_process");
const vm = require("node:vm");
const { waitForEdgeDevtoolsPage } = require("./support/issue-65-edge-devtools-readiness");
const express = require("express");
const jwt = require("jsonwebtoken");
const { createAuthenticate } = require("../src/middlewares/auth");
const { createRequirePermission } = require("../src/middlewares/permissions");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const targetPop = require("../src/crypto/rootark-zk-recovery-authorization");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const normal = require("../public/client/rootark-zk1-normal-browser-content");
const portable = require("../public/client/rootark-zk1-portable-file-recovery");
const browserRestore = require("../public/client/rootark-zk1-browser-recovery-http");
const recoverableWorkspace = require("../public/client/rootark-zk1-recoverable-workspace");
const recoverableJournal = require("../public/client/rootark-zk1-recoverable-pending-journal");
const { strictIndexedDB } = require("./support/issue-65-strict-indexeddb-fixture");
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
  "rootark-zk1-persisted-portable-chunk-recovery",
  "rootark-zk1-browser-recovery-http", "rootark-zk1-recoverable-pending-journal",
  "rootark-zk1-recoverable-workspace",
  "rootark-zk1-normal-browser-lab-ui", "rootark-zk1-portable-recovery-lab-ui",
  "rootark-dev-vault-migration", "rootark-zk1-legacy-migration-workflow",
  "rootark-zk1-legacy-batch-migration",
  "rootark-zk1-v2-device-approval", "rootark-zk1-browser-authoritative-backup",
  "rootark-zk1-keyring-portable-archive", "rootark-zk1-browser-versioned-archive",
  "rootark-zk1-v2-browser-pop", "rootark-zk1-v2-committed-approval",
  "rootark-zk1-account-portable-recovery"];

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
  const folder = createPrivateAuthorityFixture("rootark-normal-browser-");
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

test("recoverable normal workspace: independent newly enrolled device, owner-approved historical root, replay and epoch fencing", async (t) => {
  const f = await setup(t);
  const first = await f.options();
  const offlineSecret = crypto.randomBytes(32);
  const spki = crypto.createHash("sha256").update(Buffer.from(
    await crypto.webcrypto.subtle.exportKey("spki", first.ownerPublicKey))).digest();
  let wire = "", lostRecoverableAck = 0;
  const firstFetch = async (url, req) => {
    wire += String(req.body || "");
    const response = await first.fetchImpl(url, req);
    if (url.endsWith("/content/put")) {
      await response.arrayBuffer();
      lostRecoverableAck++;
      throw Error("recoverable PUT ACK lost after physical SQLite commit");
    }
    return response;
  };
  const pendingDb = strictIndexedDB();
  const memoryJournal = recoverableJournal.openStore(pendingDb);
  const built = await recoverableWorkspace.createRecoverableProtectedFile({
    ownerPublicKey: first.ownerPublicKey,
    pinnedOwnerKeyHash: first.pinnedOwnerKeyHash,
    independentOwnerSpkiSha256: spki,
    pinnedCurrentHead: first.pinnedCurrentHead,
    signedDeviceGrant: first.signedDeviceGrant,
    ownerHistoryCheckpoint: null,
    devicePublicKey: first.devicePublicKey,
    devicePrivateKey: first.devicePrivateKey,
    origin: first.origin, fetchImpl: firstFetch, nowSeconds: first.nowSeconds,
    recoverySecret: offlineSecret, metadata: first.metadata,
    name: first.fileName, mediaType: first.mediaType, data: first.data,
    journal: memoryJournal,
  });
  assert.equal(built.clientReadbackVerified, true);
  assert.equal(lostRecoverableAck, 1);
  assert.equal(built.lostPutAckReconciled, true,
    "a dropped initial PUT ACK still returns the sealed recovery bundle after signed GET");
  assert.equal(built.externalOwnerRootApprovalRequiredForRestore, true);
  assert.equal(f.putCount, 1);
  assert.equal(wire.includes(first.fileName), false);
  assert.equal(wire.includes(new TextDecoder().decode(first.data)), false);
  assert.equal(wire.includes(offlineSecret.toString("base64url")), false);
  assert.equal(wire.includes(built.bundle.wrap.sealedCek), false);
  const archived = f.store.db.prepare("SELECT ciphertext FROM zk_content_object WHERE id=?")
    .get(first.metadata.object_id).ciphertext;
  assert.equal(archived.includes(first.data), false);

  // A truly DIFFERENT Ed25519 pair is enrolled in a new signed V2 manifest,
  // rather than copying the old device's private key to the fresh client.
  const head = await fixtures.appendDeviceEnrollment(f.state, 3);
  f.setHead(head);
  const newDevice = head.devices.find((d) => d.device_id === "trusted-3");
  assert.ok(newDevice);
  const newSigner = f.state.actors.get(Buffer.from(newDevice.authorization_key_id).toString("hex"));
  const subtle = crypto.webcrypto.subtle;
  const newPrivate = await subtle.importKey("pkcs8",
    newSigner.export({ format: "der", type: "pkcs8" }), "Ed25519", false, ["sign"]);
  const newPublic = await subtle.importKey("raw", newDevice.authorization_public_key,
    "Ed25519", true, ["verify"]);
  assert.notDeepEqual(Buffer.from(newDevice.authorization_public_key),
    Buffer.from(await subtle.exportKey("raw", first.devicePublicKey)));
  const grantFor = async () => {
    const currentHead = await f.currentHead();
    const body = { schema: "rootark-zk1-browser-owner-device-grant/v1",
      account_id: first.metadata.account_id,
      compartment_id: first.metadata.compartment_id,
      keyring_id: first.metadata.keyring_id,
      device_id: newDevice.device_id,
      authorization_key_id: b64(newDevice.authorization_key_id),
      authorization_public_key: b64(newDevice.authorization_public_key),
      manifest_revision: currentHead.revision,
      manifest_digest: b64(currentHead.digest),
      current_epoch: currentHead.epoch,
      enrolled_epoch: newDevice.enrolled_epoch, revoked_at_epoch: null,
    };
    const canonical = Object.fromEntries(grantFields.map((name) => [name, body[name]]));
    return { ...canonical, signature: b64(crypto.sign(null,
      Buffer.concat([grantDomain, Buffer.from(JSON.stringify(canonical))]), f.ownerPrivate)) };
  };
  const ownerPrivate = await subtle.importKey("pkcs8",
    f.ownerPrivate.export({ format: "der", type: "pkcs8" }), "Ed25519", false, ["sign"]);
  const ownerSignerKeyId = crypto.randomBytes(16);
  const ownerDeviceId = "offline-owner-root";
  const root = Buffer.from(built.bundle.ciphertextRoot, "base64url");
  const ownerProofs = async () => {
    const current = await f.currentHead();
    const scope = Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
      .map((name) => [name, first.metadata[name]]));
    const ownerHistoryCheckpoint = await ownerHistory.signOwnerCheckpoint({
      scope, signerKey: ownerPrivate, signerPublicKey: first.ownerPublicKey,
      signerKeyId: ownerSignerKeyId, deviceId: ownerDeviceId,
      revision: current.revision, manifestDigest: current.digest,
      issuedAt: first.nowSeconds, previous: null,
    });
    const ownerRootCheckpoint = await ownerRoots.signOwnerCiphertextRootCheckpoint({
      scope, signerKey: ownerPrivate, signerKeyId: ownerSignerKeyId,
      deviceId: ownerDeviceId,
      manifestRevision: current.revision, manifestDigest: current.digest,
      manifestEpoch: current.epoch,
      objectId: first.metadata.object_id, objectRevision: 1,
      ciphertextEpoch: first.metadata.epoch, ciphertextRoot: root,
      issuedAt: first.nowSeconds,
    });
    return { current, ownerHistoryCheckpoint, ownerRootCheckpoint };
  };
  let proof = await ownerProofs();
  const recoverInput = async () => ({
    ownerPublicKey: first.ownerPublicKey,
    pinnedOwnerKeyHash: first.pinnedOwnerKeyHash,
    independentOwnerSpkiSha256: spki,
    pinnedCurrentHead: proof.current, signedDeviceGrant: await grantFor(),
    ownerHistoryCheckpoint: proof.ownerHistoryCheckpoint,
    devicePublicKey: newPublic, devicePrivateKey: newPrivate,
    origin: first.origin, fetchImpl: first.fetchImpl, nowSeconds: first.nowSeconds,
    recoverySecret: offlineSecret, bundle: built.bundle,
    expectedMetadata: first.metadata, independentlyPinnedCiphertextRoot: root,
    ownerSignerKeyId: b64(ownerSignerKeyId), ownerDeviceId,
    ownerRootCheckpoint: proof.ownerRootCheckpoint, previousOwnerHistoryProof: null,
  });
  const reopened = await recoverableWorkspace.restoreOnNewDevice(await recoverInput());
  assert.deepEqual(Buffer.from(reopened.data), first.data);
  assert.equal(reopened.ownerSignedHistoricalRootVerified, true);
  reopened.data.fill(0);
  assert.equal(f.putCount, 1, "second device only performs signed GET");

  let hostileNetwork = 0;
  const rejectsOffline = async (change) => assert.rejects(
    recoverableWorkspace.restoreOnNewDevice({ ...await recoverInput(), ...change,
      fetchImpl: (...args) => { hostileNetwork++; return first.fetchImpl(...args); },
    }), /ZK_RECOVERABLE_WORKSPACE_DENIED/);
  await rejectsOffline({ pinnedOwnerKeyHash: crypto.randomBytes(32) });
  await rejectsOffline({ independentOwnerSpkiSha256: crypto.randomBytes(32) });
  await rejectsOffline({ ownerRootCheckpoint: { ...proof.ownerRootCheckpoint,
    signature: b64(crypto.randomBytes(64)) } });
  await rejectsOffline({ ownerRootCheckpoint: { ...proof.ownerRootCheckpoint,
    ciphertext_root: b64(crypto.randomBytes(32)) } });
  await rejectsOffline({ signedDeviceGrant: first.signedDeviceGrant });
  await rejectsOffline({ pinnedCurrentHead: first.pinnedCurrentHead });
  assert.equal(hostileNetwork, 0, "forged owner and replayed head/grant blocked before HTTP");
  await assert.rejects(recoverableWorkspace.restoreOnNewDevice({
    ...await recoverInput(), recoverySecret: crypto.randomBytes(32),
  }), /ZK_RECOVERABLE_WORKSPACE_DENIED/);

  // A later epoch rotation, while the fresh device remains active, continues
  // to permit the old ciphertext epoch through a fresh owner-root signature.
  const other = f.state.headManifest.devices.find((d) =>
    d.device_id !== newDevice.device_id && d.device_id !== f.device.device_id);
  const rotated = await fixtures.appendDeviceRevocation(f.state, other.device_id);
  f.setHead(rotated);
  proof = await ownerProofs();
  const afterRotation = await recoverableWorkspace.restoreOnNewDevice(await recoverInput());
  assert.deepEqual(Buffer.from(afterRotation.data), first.data);
  afterRotation.data.fill(0);
  const revoked = await fixtures.appendDeviceRevocation(f.state, newDevice.device_id);
  f.setHead(revoked);
  await assert.rejects(recoverableWorkspace.restoreOnNewDevice(await recoverInput()),
    /ZK_RECOVERABLE_WORKSPACE_DENIED/);
  offlineSecret.fill(0);
});

test("recoverable upload with lost PUT ACK and forged historical GET fails closed without replay", async (t) => {
  const f = await setup(t);
  const first = await f.options();
  const secret = crypto.randomBytes(32);
  const spki = crypto.createHash("sha256").update(Buffer.from(
    await crypto.webcrypto.subtle.exportKey("spki", first.ownerPublicKey))).digest();
  let putAckLost = 0, tamperedReads = 0;
  const fetchImpl = async (url, options) => {
    const response = await first.fetchImpl(url, options);
    if (url.endsWith("/content/put")) {
      await response.arrayBuffer();
      putAckLost++;
      throw Error("ACK_LOST_AFTER_SERVER_COMMIT");
    }
    if (url.endsWith("/content/read") && response.status === 200) {
      const forged = await response.json();
      forged.ciphertextBase64 = b64(crypto.randomBytes(64));
      tamperedReads++;
      return new Response(JSON.stringify(forged), { status: 200,
        headers: { "content-type": "application/json" } });
    }
    return response;
  };
  const pendingDb = strictIndexedDB();
  const memoryJournal = recoverableJournal.openStore(pendingDb);
  await assert.rejects(recoverableWorkspace.createRecoverableProtectedFile({
    ownerPublicKey: first.ownerPublicKey,
    pinnedOwnerKeyHash: first.pinnedOwnerKeyHash,
    independentOwnerSpkiSha256: spki,
    pinnedCurrentHead: first.pinnedCurrentHead,
    signedDeviceGrant: first.signedDeviceGrant,
    ownerHistoryCheckpoint: null,
    devicePublicKey: first.devicePublicKey,
    devicePrivateKey: first.devicePrivateKey,
    origin: first.origin, fetchImpl, nowSeconds: first.nowSeconds,
    recoverySecret: secret, metadata: first.metadata,
    name: first.fileName, mediaType: first.mediaType, data: first.data,
    journal: memoryJournal,
  }), /ZK_RECOVERABLE_WORKSPACE_DENIED/);
  assert.equal(putAckLost, 1);
  assert.equal(tamperedReads, 1,
    "uncertain PUT must actually attempt a signed exact-version readback");
  assert.equal(f.putCount, 1, "no second PUT may be issued after an ambiguous ACK");
  assert.equal(f.store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_object")
    .get().n, 1, "original ciphertext remains persisted for explicit recovery");
  secret.fill(0);
});

test("real SQLite pending recoverable intent survives lost PUT ACK + unavailable GET and resumes only signed GET", async (t) => {
  const f = await setup(t);
  const first = await f.options();
  const secret = crypto.randomBytes(32);
  const spki = crypto.createHash("sha256").update(Buffer.from(
    await crypto.webcrypto.subtle.exportKey("spki", first.ownerPublicKey))).digest();
  const pending = strictIndexedDB();
  const journal = recoverableJournal.openStore(pending);
  let lostAck = 0, offlineGets = 0, networkCalls = 0, wire = "";
  const common = { ownerPublicKey: first.ownerPublicKey,
    pinnedOwnerKeyHash: first.pinnedOwnerKeyHash,
    independentOwnerSpkiSha256: spki, pinnedCurrentHead: first.pinnedCurrentHead,
    signedDeviceGrant: first.signedDeviceGrant, ownerHistoryCheckpoint: null,
    devicePublicKey: first.devicePublicKey, devicePrivateKey: first.devicePrivateKey,
    origin: first.origin, nowSeconds: first.nowSeconds, recoverySecret: secret, journal };
  const down = async (url, options) => {
    networkCalls++;
    wire += String(options.body || "");
    if (url.endsWith("/content/put")) {
      const response = await first.fetchImpl(url, options);
      await response.arrayBuffer();
      lostAck++;
      throw Error("ACK lost after SQLite commit");
    }
    if (url.endsWith("/content/read")) { offlineGets++; throw Error("network offline"); }
    throw Error("unexpected route");
  };
  await assert.rejects(recoverableWorkspace.createRecoverableProtectedFile({
    ...common, metadata: first.metadata, name: first.fileName,
    mediaType: first.mediaType, data: first.data, fetchImpl: down,
  }), /ZK_RECOVERABLE_WORKSPACE_DENIED/);
  assert.equal(f.putCount, 1);
  assert.equal(lostAck, 1);
  assert.equal(offlineGets, 1);
  assert.equal(pending.writes, 1, "strict encrypted pre-PUT record committed exactly once");
  assert.deepEqual(await journal.listPendingIds(), [first.metadata.object_id]);
  const stored = JSON.stringify([...pending.values.values()]);
  assert.equal(stored.includes(first.fileName), false);
  assert.equal(stored.includes(Buffer.from(first.data).toString()), false);
  assert.equal(stored.includes(secret.toString("base64url")), false);
  assert.equal(stored.includes(first.metadata.object_id), true);
  assert.equal(wire.includes(first.fileName), false);
  assert.equal(wire.includes(secret.toString("base64url")), false);

  // Simulate a cold process/browser restart: fresh journal instance, same
  // durable IndexedDB records. Fail closed while GET still unavailable.
  const restarted = recoverableJournal.openStore(pending);
  const opts = { ...common, journal: restarted,
    objectId: first.metadata.object_id,
    fetchImpl: async (url, options) => {
      assert.ok(url.endsWith("/content/read"), "pending intent MUST NOT issue PUT");
      return down(url, options);
    } };
  await assert.rejects(recoverableWorkspace.resumePendingProtectedFile(opts),
    /ZK_RECOVERABLE_WORKSPACE_DENIED/);
  assert.equal(f.putCount, 1);
  let attacked = 0;
  const blocked = async (overrides) => assert.rejects(
    recoverableWorkspace.resumePendingProtectedFile({ ...opts, ...overrides,
      fetchImpl: (...args) => { attacked++; return first.fetchImpl(...args); } }),
    /ZK_RECOVERABLE_WORKSPACE_DENIED/);
  await blocked({ recoverySecret: crypto.randomBytes(32) });
  await blocked({ independentOwnerSpkiSha256: crypto.randomBytes(32) });
  await blocked({ pinnedCurrentHead: { ...first.pinnedCurrentHead, revision: 0 } });
  assert.equal(attacked, 0, "wrong holder secret/anchor/rollback refused before HTTP");

  const resumed = await recoverableWorkspace.resumePendingProtectedFile({ ...opts,
    fetchImpl: (url, request) => {
      assert.ok(url.endsWith("/content/read"), "no replay of the original PUT");
      networkCalls++;
      wire += String(request.body || "");
      return first.fetchImpl(url, request);
    } });
  assert.equal(resumed.resumedSignedGetOnly, true);
  assert.equal(resumed.encryptedLocalRecoveryJournalCommitted, true);
  assert.equal(resumed.authorizesProductionIo, false);
  assert.deepEqual(resumed.bundle.metadata, first.metadata);
  assert.equal(f.putCount, 1);
  assert.equal(pending.writes, 1, "resume does not mutate/replace the pending journal");
  const reopened = await portable.openWithIndependentRoot({
    recoverySecret: secret, bundle: resumed.bundle,
    expectedMetadata: first.metadata,
    independentlyPinnedCiphertextRoot: Buffer.from(resumed.ciphertextRoot, "base64url"),
  });
  assert.deepEqual(Buffer.from(reopened.data), first.data);
  reopened.data.fill(0);

  // The signed PUT nonce/operation binding is part of the journal's AEAD
  // associated data. Replaying a modified IndexedDB header cannot authorize
  // either a plaintext export or a new network request.
  const journalRow = pending.values.get(first.metadata.object_id);
  const originalOperationId = journalRow.operationId;
  journalRow.operationId = b64(crypto.randomBytes(32));
  await blocked({});
  assert.equal(attacked, 0, "tampered local operation binding rejected before GET");
  journalRow.operationId = originalOperationId;

  const revoked = await fixtures.appendDeviceRevocation(f.state, f.device.device_id);
  f.setHead(revoked);
  await blocked({});
  assert.equal(attacked, 1, "attempted revoked re-entry never receives a valid restored bundle");
  assert.equal(f.putCount, 1);
  secret.fill(0);
});

test("strict encrypted local journal refusal aborts recoverable upload before network PUT", async (t) => {
  const f = await setup(t);
  const first = await f.options();
  const spki = crypto.createHash("sha256").update(Buffer.from(
    await crypto.webcrypto.subtle.exportKey("spki", first.ownerPublicKey))).digest();
  for (const db of [strictIndexedDB({ refuseStrict: true }),
    strictIndexedDB({ failCommit: true })]) {
    let requests = 0;
    await assert.rejects(recoverableWorkspace.createRecoverableProtectedFile({
      ownerPublicKey: first.ownerPublicKey, pinnedOwnerKeyHash: first.pinnedOwnerKeyHash,
      independentOwnerSpkiSha256: spki, pinnedCurrentHead: first.pinnedCurrentHead,
      signedDeviceGrant: first.signedDeviceGrant, ownerHistoryCheckpoint: null,
      devicePublicKey: first.devicePublicKey, devicePrivateKey: first.devicePrivateKey,
      origin: first.origin, nowSeconds: first.nowSeconds,
      recoverySecret: crypto.randomBytes(32), metadata: first.metadata,
      name: first.fileName, mediaType: first.mediaType, data: first.data,
      journal: recoverableJournal.openStore(db),
      fetchImpl: (...args) => { requests++; return first.fetchImpl(...args); },
    }), /ZK_RECOVERABLE_WORKSPACE_DENIED/);
    assert.equal(requests, 0, "not one HTTP request before strict commit/readback");
    assert.equal(f.putCount, 0);
  }
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
  assert.deepEqual(await ownerCapability.json(), { enabled: true,
    securityVersion: 1, signedHistoryRequired: false });
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
    // DevToolsActivePort may exist before /json/list publishes a page target.
    // Reuse the established readiness check within the original 20s budget.
    const debuggerPage = await waitForEdgeDevtoolsPage({
      profileDir: profile, child: edge, timeoutMs: 20000,
    });
    socket = new WebSocket(debuggerPage);
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

test("Edge normal authenticated V2 workspace refuses a real legacy V1 server capability", {
  timeout: 65_000,
}, async (t) => {
  if (process.platform !== "win32" || !fs.existsSync(EDGE)) {
    t.skip("Edge Windows browser unavailable");
    return;
  }
  const f = await setup(t);
  const opts = await f.options();
  const hpke = await z.hpkeSuite().kem.generateKeyPair();
  const hpkeRaw = Buffer.from(await z.hpkeSuite().kem.serializePublicKey(hpke.publicKey));
  const hpkePrivateRaw = Buffer.from(await z.hpkeSuite().kem.serializePrivateKey(hpke.privateKey));
  const popSigner = crypto.generateKeyPairSync("ed25519");
  const popAuthId = crypto.randomBytes(16);
  const popHpkeId = crypto.randomBytes(16);
  const browserRequest = { schema: "rootark-zk1-device-enrollment-request/v1",
    device_id: "fresh-edge-browser-v2", authorization_key_id: b64(popAuthId),
    authorization_public_key: b64(popSigner.publicKey.export({
      format: "der", type: "spki" }).subarray(-32)),
    hpke_key_id: b64(popHpkeId), hpke_public_key: b64(hpkeRaw),
    challenge: b64(crypto.randomBytes(32)),
    approval: "OWNER_MUST_VERIFY_IDENTITY_AND_FINISH_V2_POP_AND_SIGN_CURRENT_GRANT" };
  const popNow = Math.floor(Date.now() / 1000);
  const ownerChallenge = await targetPop.createTargetPopChallenge({
    scope: f.state.scope, operationId: crypto.randomBytes(16),
    targetDeviceId: browserRequest.device_id, hpkeKeyId: popHpkeId,
    hpkePublicKey: hpkeRaw, authorizationKeyId: popAuthId,
    authorizationPublicKey: Buffer.from(browserRequest.authorization_public_key, "base64url"),
    issuedAt: popNow, expiresAt: popNow + 300 });
  const challengeWire = { schema: "rootark-zk1-v2-browser-pop-challenge/v1",
    challenge_context: Object.fromEntries(Object.entries(ownerChallenge.challengeContext)
      .map(([name, value]) => [name, Buffer.isBuffer(value) ? b64(value) : value])),
    enc: b64(ownerChallenge.enc), ciphertext: b64(ownerChallenge.ciphertext) };
  const secret = crypto.randomBytes(32).toString("hex");
  const ownerPrivate = await crypto.webcrypto.subtle.importKey("pkcs8",
    f.ownerPrivate.export({ type: "pkcs8", format: "der" }),
    "Ed25519", false, ["sign"]);
  const ownerHistoryKeyId = crypto.randomBytes(16);
  const historicalScope = Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
    .map((key) => [key, opts.signedDeviceGrant[key]]));
  const genesisCheckpoint = await ownerHistory.signOwnerCheckpoint({
    scope: historicalScope, signerKey: ownerPrivate,
    signerPublicKey: opts.ownerPublicKey, signerKeyId: ownerHistoryKeyId,
    deviceId: "authenticated-workspace-owner", revision: opts.pinnedCurrentHead.revision,
    manifestDigest: opts.pinnedCurrentHead.digest, issuedAt: opts.nowSeconds,
    previous: null,
  });
  const trustedGenesis = await ownerHistory.verifyOwnerCheckpoint({
    checkpoint: genesisCheckpoint, scope: historicalScope,
    signerPublicKey: opts.ownerPublicKey, signerKeyId: ownerHistoryKeyId,
    previous: null,
  });
  const successorCheckpoint = await ownerHistory.signOwnerCheckpoint({
    scope: historicalScope, signerKey: ownerPrivate,
    signerPublicKey: opts.ownerPublicKey, signerKeyId: ownerHistoryKeyId,
    deviceId: "authenticated-workspace-owner", revision: opts.pinnedCurrentHead.revision,
    manifestDigest: opts.pinnedCurrentHead.digest, issuedAt: opts.nowSeconds + 1,
    previous: trustedGenesis,
  });
  const archiveHistory = await ownerHistory.signOwnerCheckpoint({
    scope: historicalScope, signerKey: ownerPrivate,
    signerPublicKey: opts.ownerPublicKey, signerKeyId: ownerHistoryKeyId,
    deviceId: opts.signedDeviceGrant.device_id, revision: opts.pinnedCurrentHead.revision,
    manifestDigest: opts.pinnedCurrentHead.digest, issuedAt: opts.nowSeconds,
    previous: null,
  });
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
    "rootark-zk1-owner-inventory-trust-head", ...scriptNames]);
  const untouchedLegacy = Buffer.from("Synthetic existing legacy file; old server has plaintext.");
  const legacyLastModified = "Thu, 01 Jan 2026 00:00:00 GMT";
  const legacyPin = { storedAs: "legacy.txt", uploadedAt: "2026-01-01T00:00:00Z",
    size: untouchedLegacy.length, lastModified: legacyLastModified,
    sha256: b64(crypto.createHash("sha256").update(untouchedLegacy).digest()),
    mediaType: "text/plain" };
  app.get("/files/legacy.txt", authenticate, (_req, res) => {
    res.set("content-disposition", 'attachment; filename="legacy.txt"');
    res.type("text/plain").status(200).end(untouchedLegacy);
  });
  app.get("/versions/legacy.txt", authenticate, (_req, res) => res.json({
    fileName: "legacy.txt", versions: [1, 2].map((version) => ({
      version, storedAs: legacyPin.storedAs,
      uploadedAt: legacyPin.uploadedAt, size: legacyPin.size,
    })),
  }));
  app.get("/download/legacy.txt/v/:version", authenticate, (req, res) => {
    if (!["1", "2"].includes(req.params.version)) return res.sendStatus(404);
    res.set("content-disposition", 'attachment; filename="legacy.txt"');
    res.set("last-modified", legacyLastModified);
    return res.type("text/plain").status(200).end(untouchedLegacy);
  });
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
      + '<script defer src="/client/rootark-zk1-v2-browser-pop.js"></script>'
      + '<script defer src="/client/rootark-zk1-authenticated-workspace.js"></script>'
      + '<script defer src="/workspace-probe.js"></script></head><body>'
      + '<section class="protected-client-panel"><p id="protectedClientStatus"></p></section>'
      + '</body></html>'));
  const values = { ownerRaw: b64(f.ownerRaw), ownerHash: b64(opts.pinnedOwnerKeyHash),
    browserPoP: { request: browserRequest, challenge: challengeWire,
      hpkePrivateDer: b64(Buffer.concat([
        Buffer.from("302e020100300506032b656e04220420", "hex"),
        Buffer.from(hpkePrivateRaw)])),
      authorizationPrivateDer: b64(popSigner.privateKey.export({
        format: "der", type: "pkcs8" })), nowSeconds: popNow },
    ownerSpkiHash: b64(crypto.createHash("sha256").update(Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"), f.ownerRaw])).digest()),
    deviceRaw: b64(f.device.authorization_public_key), privateDer: b64(f.privateDer),
    grant: opts.signedDeviceGrant,
    migrationCek: b64(crypto.randomBytes(32)),
    batchCeks: [b64(crypto.randomBytes(32)), b64(crypto.randomBytes(32))],
    legacyPin,
    head: { revision: opts.pinnedCurrentHead.revision,
      digest: b64(opts.pinnedCurrentHead.digest), epoch: opts.pinnedCurrentHead.epoch },
    ownerHistoryChain: [genesisCheckpoint, successorCheckpoint],
    archiveHistory, archiveOwnerPrivate: b64(f.ownerPrivate.export({ type: "pkcs8", format: "der" })),
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
        // This disposable server intentionally uses an opt-in V1 store, which
        // must no longer advertise permission to launch the V2 owner-history
        // browser UI. The separate real Edge crypto test above continues to
        // exercise protected PUT/GET and CSP under authenticated HTTP.
        const capability=await fetch("/zk-1/v1/workspace-capability",{
          credentials:"include"}).then(res=>res.json());
        // A V1 server MUST NOT enable the V2 workspace. However, the real
        // browser's standalone HPKE/Ed25519 device PoP remains independently
        // testable without granting any V2 HTTP write or restore privilege.
        window.edgeV2Pop=await window.RootarkZk1V2BrowserPop.respond({
          request: values.browserPoP.request,challenge: values.browserPoP.challenge,
          deviceHpkePrivateDer: decode(values.browserPoP.hpkePrivateDer),
          deviceAuthorizationPrivateDer: decode(values.browserPoP.authorizationPrivateDer),
          nowSeconds: values.browserPoP.nowSeconds });
        if(capability.securityVersion===1 && capability.signedHistoryRequired===false){
          window.dispatchEvent(new Event("rootark:workspace-rendered"));
          await new Promise(resolve=>setTimeout(resolve,250));
          if(document.getElementById("zk1-workspace-open"))throw Error("V1_DOWNGRADE_UI_VISIBLE");
          output.textContent="EDGE_AUTH_WORKSPACE_PASS";
          return;
        }
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
        setFile("history",new TextEncoder().encode(JSON.stringify(values.ownerHistoryChain)));
        document.querySelector('[data-zk1-action="provision"]').click();
        await wait(()=>field("status").textContent.includes("Âncora offline provisionada"));
        setFile("device",decode(values.deviceRaw));
        setFile("private",decode(values.privateDer));
        setFile("file",new TextEncoder().encode("Edge normal authenticated workspace plaintext"));
        document.querySelector('[data-zk1-action="upload"]').click();
        await wait(()=>field("status").textContent.includes("PUT/GET protegidos verificados")
          || field("status").textContent.includes("Operação recusada"));
	        if(!field("status").textContent.includes("PUT/GET protegidos verificados"))
	          throw Error("OP_DENIED:"+field("status").textContent+":REC="
	            +typeof window.RootarkZk1RecoverableWorkspace+":HTTP="
	            +typeof window.RootarkZk1BrowserRecoveryHttp);
        if(field("private").files.length || field("file").files.length)throw Error("KEY_RETAINED");
        field("legacy-name").value="legacy.txt";
        field("migration-opt-in").checked=true;
        setFile("private",decode(values.privateDer));
        setFile("migration-cek",decode(values.migrationCek));
        document.querySelector('[data-zk1-action="migrate"]').click();
        await wait(()=>field("status").textContent.includes("GET conferido")
          || field("status").textContent.includes("Operação recusada"));
        if(!field("status").textContent.includes("GET conferido"))throw Error("LEGACY_MIGRATION_DENIED");
        if(field("migration-object").value.length!==22 || field("migration-version").value.length!==22)
          throw Error("MIGRATION_ID_LOST");
        setFile("private",decode(values.privateDer));
        setFile("migration-cek",decode(values.migrationCek));
        document.querySelector('[data-zk1-action="migrate"]').click();
        await wait(()=>field("status").textContent.includes("GET conferido")
          || field("status").textContent.includes("Operação recusada"));
        if(!field("status").textContent.includes("GET conferido"))throw Error("MIGRATION_RESUME_DENIED");
        if(field("private").files.length || field("migration-cek").files.length)
          throw Error("MIGRATION_KEY_RETAINED");
        // Real Edge integration: local JSON descriptors, two distinct binary
        // CEKs and a separate 32-byte migration secret through authenticated
        // version catalog + legacy GET + signed ciphertext PUT/GET.
        let batchDownloads=[];
        const previousClick=HTMLAnchorElement.prototype.click;
        const previousCreate=URL.createObjectURL;
        const batchBlobs=new Map();
        URL.createObjectURL=function(blob){const url=previousCreate.call(URL,blob);
          batchBlobs.set(url,blob);return url;};
        HTMLAnchorElement.prototype.click=function(){
          if(!this.download||!this.href.startsWith("blob:"))throw Error("UNSAFE_BATCH_DOWNLOAD");
          batchDownloads.push({name:this.download,href:this.href});};
        const batchSecret=crypto.getRandomValues(new Uint8Array(32));
        const batchDescriptors=(partial=false)=>({schema:"rootark-zk1-legacy-version-batch/v1",
          entries:[1,2].map((version,index)=>({legacy:{name:"legacy.txt",folderId:""},
            sourcePin:{...values.legacyPin,version,
              sha256:partial&&index===1?values.ownerHash:values.legacyPin.sha256},
            cekFile:"version-"+version+".bin"}))});
        const selectBatch=(partial=false)=>{
          setFile("history",new TextEncoder().encode(JSON.stringify(values.ownerHistoryChain)));
          setFile("private",decode(values.privateDer));
          setFile("migration-batch-descriptors",new TextEncoder().encode(
            JSON.stringify(batchDescriptors(partial))));
          setFile("migration-batch-secret",batchSecret);
          field("migration-batch-opt-in").checked=true;
          const selection=new DataTransfer();
          for(let index=0;index<2;index++)selection.items.add(new File(
            [decode(values.batchCeks[index])],"version-"+(index+1)+".bin"));
          field("migration-batch-ceks").files=selection.files;
        };
        selectBatch(true);
        document.querySelector('[data-zk1-action="migration-batch"]').click();
        await wait(()=>field("status").textContent.includes("Versões conferidas localmente")
          || field("status").textContent.includes("Operação recusada"));
        if(!field("status").textContent.includes("1/2")||batchDownloads.length!==1)
          throw Error("EDGE_BATCH_PARTIAL_FAIL:"+field("status").textContent);
        const batchPartial=JSON.parse(await batchBlobs.get(batchDownloads[0].href).text());
        if(batchPartial.verified!==1||batchPartial.authorizesCutover!==false
          ||batchPartial.results[1].phase!=="needs-manual-review")
          throw Error("EDGE_BATCH_PARTIAL_REPORT_UNSAFE");
        if(field("migration-batch-ceks").files.length||field("migration-batch-secret").files.length)
          throw Error("EDGE_BATCH_RETAINED_KEYS");
        batchDownloads=[];
        selectBatch(false);
        document.querySelector('[data-zk1-action="migration-batch"]').click();
        await wait(()=>field("status").textContent.includes("Versões conferidas localmente")
          || field("status").textContent.includes("Operação recusada"));
        if(!field("status").textContent.includes("2/2")||batchDownloads.length!==1)
          throw Error("EDGE_BATCH_RESUME_FAIL:"+field("status").textContent);
        batchDownloads=[];
        selectBatch(false);
        field("owner-spki").value=values.ownerHash;
        document.querySelector('[data-zk1-action="migration-batch"]').click();
        await wait(()=>field("status").textContent.includes("Operação recusada"));
        if(batchDownloads.length)throw Error("EDGE_BATCH_FORGED_OWNER_PIN_LEAK");
        field("owner-spki").value=values.ownerSpkiHash;
        URL.createObjectURL=previousCreate;
        HTMLAnchorElement.prototype.click=previousClick;
        batchSecret.fill(0);
        field("digest").value=values.head.digest;
        setFile("history",new TextEncoder().encode(JSON.stringify([
          values.ownerHistoryChain[0],
          {...values.ownerHistoryChain[1],signature:values.ownerHistoryChain[0].signature}
        ])));
        document.querySelector('[data-zk1-action="provision"]').click();
        await wait(()=>field("status").textContent.includes("Operação recusada"));
        setFile("history",new TextEncoder().encode(JSON.stringify(values.ownerHistoryChain)));
	        let locallyExported=0;
	        const originalClick=HTMLAnchorElement.prototype.click;
	        HTMLAnchorElement.prototype.click=function(){
	          if(!this.download || !this.href.startsWith("blob:"))throw Error("UNSAFE_DOWNLOAD");
	          locallyExported++;};
	        const holder=crypto.getRandomValues(new Uint8Array(32));
	        setFile("private",decode(values.privateDer));
	        setFile("file",new TextEncoder().encode("Recoverable authenticated Edge file"));
	        setFile("secret",holder);
	        document.querySelector('[data-zk1-action="upload-recoverable"]').click();
	        await wait(()=>field("status").textContent.includes("Pacote recuperável exportado")
	          || field("status").textContent.includes("Operação recusada"));
	        HTMLAnchorElement.prototype.click=originalClick;
	        if(!field("status").textContent.includes("Pacote recuperável exportado")
	          || locallyExported!==1 || field("secret").files.length
	          || field("private").files.length || field("file").files.length)
	          throw Error("RECOVERABLE_WORKSPACE_FAILED:"+field("status").textContent);
		        // Actual Edge IndexedDB strict transaction survives a later offline
		        // recovery attempt; re-enter using only a signed GET, never PUT.
		        const journal=window.RootarkZk1RecoverablePendingJournal.openStore(indexedDB);
		        const pendingIds=await journal.listPendingIds();
		        if(pendingIds.length!==1)throw Error("EDGE_PENDING_ID_MISSING");
		        field("pending-object").value=pendingIds[0];
		        let offline=true, forbiddenPuts=0;
		        const pendingNativeFetch=window.fetch.bind(window);
		        window.fetch=(url,opts)=>{
		          if(String(url).includes("/content/put")){forbiddenPuts++;throw Error("NO_REPLAY_PUT");}
		          if(offline&&String(url).includes("/content/read"))
		            return Promise.reject(Error("SIMULATED_OFFLINE_GET"));
		          return pendingNativeFetch(url,opts);
		        };
		        setFile("private",decode(values.privateDer));
		        setFile("secret",holder);
		        document.querySelector('[data-zk1-action="pending-resume"]').click();
		        await wait(()=>field("status").textContent.includes("Operação recusada"));
		        if(locallyExported!==1||forbiddenPuts!==0)
		          throw Error("EDGE_OFFLINE_PENDING_RELEASED");
		        offline=false;
		        setFile("private",decode(values.privateDer));
		        setFile("secret",holder);
		        document.querySelector('[data-zk1-action="pending-resume"]').click();
		        await wait(()=>field("status").textContent.includes("GET histórico autenticado")
		          || field("status").textContent.includes("Operação recusada"));
		        window.fetch=pendingNativeFetch;
		        if(!field("status").textContent.includes("GET histórico autenticado")
		          || locallyExported!==2 || forbiddenPuts!==0)
		          throw Error("EDGE_PENDING_REENTRY_FAILED:"+field("status").textContent);
	        holder.fill(0);
        // No owner keys, holder secret, selected file plaintext or recovered
        // plaintext crosses the application HTTP endpoint. Capture DOWNLOADS
        // (blob URLs) without ever permitting a browser file-system write.
        let archiveDownloads=[];
        const originalCreate=URL.createObjectURL;
        const archiveBlobs=new Map();
        URL.createObjectURL=function(blob){const url=originalCreate.call(URL,blob);
          archiveBlobs.set(url,blob);return url;};
        HTMLAnchorElement.prototype.click=function(){
          if(!this.download || !this.href.startsWith("blob:"))throw Error("UNSAFE_KEYRING_DOWNLOAD");
          archiveDownloads.push({name:this.download,href:this.href});};
        const archiveHolder=crypto.getRandomValues(new Uint8Array(32));
        const storageView=async()=>JSON.stringify({
          local:Object.keys(localStorage).sort().map(k=>[k,localStorage.getItem(k)]),
          session:Object.keys(sessionStorage).sort().map(k=>[k,sessionStorage.getItem(k)]),
          databases:(await indexedDB.databases()).map(db=>db.name).sort()});
        const beforeArchiveStorage=await storageView();
        setFile("history",new TextEncoder().encode(JSON.stringify(values.archiveHistory)));
        field("owner-device").value=values.grant.device_id;
        field("owner-signer").value=${JSON.stringify(b64(ownerHistoryKeyId))};
        field("archive-opt-in").checked=true;
        setFile("archive-owner-private",decode(values.archiveOwnerPrivate));
        setFile("secret",archiveHolder);
        const select=new DataTransfer();
        select.items.add(new File(["offline alpha"],"alpha.txt",{type:"text/plain"}));
        select.items.add(new File(["offline beta"],"beta.txt",{type:"text/plain"}));
        field("archive-files").files=select.files;
        document.querySelector('[data-zk1-action="archive-create"]').click();
        await wait(()=>field("status").textContent.includes("cifrado e assinado localmente")
          || field("status").textContent.includes("Operação recusada"));
        if(!field("status").textContent.includes("cifrado e assinado localmente")
          || archiveDownloads.length!==2 || field("archive-owner-private").files.length
          || field("archive-files").files.length || field("secret").files.length)
          throw Error("KEYRING_CREATE_DENIED:"+field("status").textContent);
        const archiveArtifact=archiveDownloads.find(x=>x.name.endsWith(".json"));
        const hashArtifact=archiveDownloads.find(x=>x.name.endsWith(".sha256.txt"));
        if(!archiveArtifact||!hashArtifact)throw Error("KEYRING_EXPORTS_MISSING");
        const exportedArchive=await archiveBlobs.get(archiveArtifact.href).text();
        const externalHash=await archiveBlobs.get(hashArtifact.href).text();
        archiveDownloads=[];
        field("archive-sha").value=externalHash;
        setFile("archive-json",new TextEncoder().encode(exportedArchive));
        setFile("secret",archiveHolder);
        document.querySelector('[data-zk1-action="archive-recover"]').click();
        await wait(()=>field("status").textContent.includes("arquivo(s) baixados localmente")
          || field("status").textContent.includes("Operação recusada"));
        if(!field("status").textContent.includes("2 arquivo(s) baixados localmente")
          || archiveDownloads.length!==2 || field("secret").files.length
          || field("archive-json").files.length)throw Error("KEYRING_RESTORE_DENIED:"+field("status").textContent);
        const contents=await Promise.all(archiveDownloads.map(async x=>({name:x.name,
          data:await archiveBlobs.get(x.href).text()})));
        if(!contents.find(x=>x.name==="alpha.txt"&&x.data==="offline alpha")
          || !contents.find(x=>x.name==="beta.txt"&&x.data==="offline beta"))
          throw Error("KEYRING_LOCAL_CONTENT_MISMATCH");
        // Real Edge: offline account coordinator through authenticated UI and
        // native WebCrypto, with no account archive server endpoint.
        archiveDownloads=[];
        const accountHolder=crypto.getRandomValues(new Uint8Array(32));
        const accountSelection=(files)=>({
          schema:"rootark-zk1-account-workspace-selection/v1",
          accountId:values.grant.account_id,
          keyrings:[{scope:{account_id:values.grant.account_id,
            compartment_id:values.grant.compartment_id,
            keyring_id:values.grant.keyring_id},
            pinnedCurrentHead:{...values.head},signedDeviceGrant:values.grant,
            ownerHistory:[values.archiveHistory],
            signerKeyId:${JSON.stringify(b64(ownerHistoryKeyId))},
            deviceId:values.grant.device_id,holderSecretFile:"holder.bin",files}]});
        const setAccount=(names)=>{
          setFile("account-descriptors",new TextEncoder().encode(JSON.stringify(accountSelection(names))));
          const holderInput=new DataTransfer();
          holderInput.items.add(new File([accountHolder],"holder.bin"));
          field("account-holder-files").files=holderInput.files;
          field("account-opt-in").checked=true;
          setFile("history",new TextEncoder().encode(JSON.stringify(values.archiveHistory)));
        };
        setAccount(["account-selected.txt"]);
        const accountFiles=new DataTransfer();
        accountFiles.items.add(new File(["only selected offline"],"account-selected.txt",
          {type:"text/plain"}));
        field("account-local-files").files=accountFiles.files;
        setFile("account-owner-private",decode(values.archiveOwnerPrivate));
        window.__accountProbeStage="create";
        document.querySelector('[data-zk1-action="account-create"]').click();
        await wait(()=>field("status").textContent.includes("Pacote cifrado e assinado de")
          || field("status").textContent.includes("Operação recusada"));
        if(!field("status").textContent.includes("1 keyring(s) baixado")
          || archiveDownloads.length!==2)throw Error("ACCOUNT_CREATE_DENIED:"+field("status").textContent);
        const accountArchiveArtifact=archiveDownloads.find(x=>x.name==="rootark-account-archive.json");
        const accountHashArtifact=archiveDownloads.find(x=>x.name==="rootark-account-archive.sha256.txt");
        if(!accountArchiveArtifact||!accountHashArtifact)
          throw Error("ACCOUNT_INDEPENDENT_HASH_MISSING");
        const accountArchive=await archiveBlobs.get(accountArchiveArtifact.href).text();
        const accountHash=await archiveBlobs.get(accountHashArtifact.href).text();
        if(!JSON.parse(accountArchive).signature)throw Error("ACCOUNT_UNSIGNED");
        archiveDownloads=[];
        setAccount([]);
        setFile("account-archive",new TextEncoder().encode(accountArchive));
        field("account-sha").value=accountHash;
        window.__accountProbeStage="recover";
        document.querySelector('[data-zk1-action="account-recover"]').click();
        await wait(()=>field("status").textContent.includes("arquivos baixados localmente")
          || field("status").textContent.includes("Operação recusada"));
        if(!field("status").textContent.includes("1 arquivos baixados localmente")
          || archiveDownloads.length!==1)throw Error("ACCOUNT_RECOVER_DENIED:"+field("status").textContent);
        const openedAccount=await archiveBlobs.get(archiveDownloads[0].href).text();
        if(openedAccount!=="only selected offline"
          ||!archiveDownloads[0].name.includes("account-selected.txt"))
          throw Error("ACCOUNT_PLAINTEXT_MISMATCH");
        archiveDownloads=[];
        setAccount([]);
        field("account-sha").value=values.ownerHash;
        setFile("account-archive",new TextEncoder().encode(accountArchive));
        window.__accountProbeStage="wrong-hash";
        document.querySelector('[data-zk1-action="account-recover"]').click();
        await wait(()=>field("status").textContent.includes("Operação recusada"));
        await wait(()=>field("account-holder-files").files.length===0);
        if(archiveDownloads.length)throw Error("ACCOUNT_FORGED_PIN_RELEASE");
        // Intercept post-verification plaintext and simulate logout in the
        // middle of the coordinator's promise: no account output is released.
        setAccount([]);
        field("account-sha").value=accountHash;
        setFile("account-archive",new TextEncoder().encode(accountArchive));
        const accountApi=window.RootarkZk1AccountPortableRecovery;
        let resolvePendingAccount;
        let accountIntercepted=false;
        window.RootarkZk1AccountPortableRecovery={...accountApi,
          recoverArchive:async(...args)=>{
            accountIntercepted=true;
            const value=await accountApi.recoverArchive(...args);
            return new Promise(resolve=>{resolvePendingAccount=()=>resolve(value);});
          }};
        window.__accountProbeStage="late-logout";
        document.querySelector('[data-zk1-action="account-recover"]').click();
        window.__accountProbeStage="late-hold";
        await wait(()=>typeof resolvePendingAccount==="function"
          ||field("status").textContent.includes("Operação recusada"));
        if(typeof resolvePendingAccount!=="function")
          throw Error("ACCOUNT_LATE_NOT_REACHED:"+accountIntercepted);
        window.dispatchEvent(new Event("rootark:logout"));
        resolvePendingAccount();
        window.__accountProbeStage="late-denied";
        await wait(()=>field("status").textContent.includes("Operação recusada"));
        if(archiveDownloads.length||document.querySelector("dialog").open)
          throw Error("ACCOUNT_LOGOUT_LATE_PLAINTEXT_RELEASE");
        window.RootarkZk1AccountPortableRecovery=accountApi;
        accountHolder.fill(0);
        // The rest of this existing Edge acceptance test exercises a fresh
        // authenticated dialog after the deliberate account logout.
        (await wait(()=>document.getElementById("zk1-workspace-open"))).click();
        await wait(()=>document.querySelector("dialog").open);
        setFile("owner",decode(values.ownerRaw));
        field("owner-hash").value=values.ownerHash;
        field("owner-spki").value=values.ownerSpkiHash;
        field("revision").value=values.head.revision;
        field("digest").value=values.head.digest;
        field("epoch").value=values.head.epoch;
        setFile("grant",new TextEncoder().encode(JSON.stringify(values.grant)));
        setFile("history",new TextEncoder().encode(JSON.stringify(values.archiveHistory)));
        field("owner-signer").value=${JSON.stringify(b64(ownerHistoryKeyId))};
        field("owner-device").value=values.grant.device_id;
        archiveDownloads=[];
        field("archive-sha").value=values.ownerHash;
        setFile("archive-json",new TextEncoder().encode(exportedArchive));
        setFile("secret",archiveHolder);
        document.querySelector('[data-zk1-action="archive-recover"]').click();
        await wait(()=>field("status").textContent.includes("Operação recusada"));
        if(archiveDownloads.length)throw Error("KEYRING_WRONG_HASH_LEAK");
        // Pinning the exact hostile archive hash cannot bypass Ed25519 owner
        // signature checks even when that hash is supplied as a valid digest.
        const forged=JSON.parse(exportedArchive);
        forged.signature=btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(64))))
          .replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/g,"");
        const forgedCanonical=new TextEncoder().encode(JSON.stringify(forged));
        const forgedDigest=new Uint8Array(await crypto.subtle.digest("SHA-256",forgedCanonical));
        field("archive-sha").value=btoa(String.fromCharCode(...forgedDigest))
          .replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/g,"");
        setFile("archive-json",forgedCanonical);
        setFile("secret",archiveHolder);
        document.querySelector('[data-zk1-action="archive-recover"]').click();
        await wait(()=>field("status").textContent.includes("Operação recusada"));
        if(archiveDownloads.length)throw Error("KEYRING_UNSIGNED_ARCHIVE_LEAK");
        field("archive-sha").value=externalHash;
        setFile("archive-json",new TextEncoder().encode(exportedArchive));
        setFile("secret",archiveHolder);
        setFile("grant",new TextEncoder().encode(JSON.stringify({
          ...values.grant,revoked_at_epoch:values.head.epoch})));
        document.querySelector('[data-zk1-action="archive-recover"]').click();
        await wait(()=>field("status").textContent.includes("Operação recusada"));
        if(archiveDownloads.length)throw Error("KEYRING_REVOKED_GRANT_LEAK");
        setFile("grant",new TextEncoder().encode(JSON.stringify({
          ...values.grant,keyring_id:values.ownerHash.slice(0,22)})));
        setFile("archive-json",new TextEncoder().encode(exportedArchive));
        setFile("secret",archiveHolder);
        document.querySelector('[data-zk1-action="archive-recover"]').click();
        await wait(()=>field("status").textContent.includes("Operação recusada"));
        if(archiveDownloads.length)throw Error("KEYRING_CROSS_SCOPE_LEAK");
        setFile("grant",new TextEncoder().encode(JSON.stringify(values.grant)));
        archiveDownloads=[];
        field("archive-sha").value=externalHash;
        setFile("archive-json",new TextEncoder().encode(exportedArchive));
        setFile("secret",archiveHolder);
        field("archive-opt-in").checked=false;
        document.querySelector('[data-zk1-action="archive-recover"]').click();
        await wait(()=>field("status").textContent.includes("Operação recusada"));
        if(archiveDownloads.length)throw Error("KEYRING_NO_OPTIN_LEAK");
        field("archive-opt-in").checked=true;
        setFile("archive-owner-private",decode(values.archiveOwnerPrivate));
        setFile("secret",archiveHolder);
        const unsafe=new DataTransfer();
        unsafe.items.add(new File(["bad path"],"../escape.txt"));
        field("archive-files").files=unsafe.files;
        document.querySelector('[data-zk1-action="archive-create"]').click();
        await wait(()=>field("status").textContent.includes("Operação recusada"));
        if(archiveDownloads.length)throw Error("KEYRING_UNSAFE_NAME_LEAK");
        if(await storageView()!==beforeArchiveStorage)
          throw Error("KEYRING_UNINTENDED_BROWSER_PERSISTENCE");
        const postLogoutHolder=archiveHolder.slice();
        archiveHolder.fill(0);
        URL.createObjectURL=originalCreate;
        HTMLAnchorElement.prototype.click=originalClick;
        setFile("history",new TextEncoder().encode(JSON.stringify(values.ownerHistoryChain)));
        field("digest").value=values.ownerHash;
        setFile("private",decode(values.privateDer));
        setFile("file",new TextEncoder().encode("Tampered browser pinned head"));
        document.querySelector('[data-zk1-action="upload"]').click();
        await wait(()=>field("status").textContent.includes("Operação recusada"));
        // Real Edge: a session logout inside the first local archive download
        // must invalidate the remaining plaintext files before release.
        field("digest").value=values.head.digest;
        setFile("grant",new TextEncoder().encode(JSON.stringify(values.grant)));
        setFile("history",new TextEncoder().encode(JSON.stringify(values.archiveHistory)));
        field("archive-opt-in").checked=true;
        field("archive-sha").value=externalHash;
        setFile("archive-json",new TextEncoder().encode(exportedArchive));
        setFile("secret",postLogoutHolder);
        archiveDownloads=[];
        HTMLAnchorElement.prototype.click=function(){
          if(!this.download||!this.href.startsWith("blob:"))throw Error("UNSAFE_LATE_DOWNLOAD");
          archiveDownloads.push(this.download);
          if(archiveDownloads.length===1)
            window.dispatchEvent(new Event("rootark:logout"));
        };
        document.querySelector('[data-zk1-action="archive-recover"]').click();
        await wait(()=>field("status").textContent.includes("Operação recusada")
          && archiveDownloads.length===1);
        if(archiveDownloads.length!==1||document.querySelector("dialog").open)
          throw Error("LATE_LOGOUT_ARCHIVE_RELEASE");
        HTMLAnchorElement.prototype.click=originalClick;
        const historicHolder=postLogoutHolder.slice();
        postLogoutHolder.fill(0);
        // Real Edge logout while the FIRST historical catalog fetch is still
        // unresolved: no version ciphertext PUT and no report release.
        (await wait(()=>document.getElementById("zk1-workspace-open"))).click();
        await wait(()=>document.querySelector("dialog").open);
        setFile("owner",decode(values.ownerRaw));
        field("owner-hash").value=values.ownerHash;
        field("owner-spki").value=values.ownerSpkiHash;
        field("revision").value=values.head.revision;
        field("digest").value=values.head.digest;
        field("epoch").value=values.head.epoch;
        setFile("grant",new TextEncoder().encode(JSON.stringify(values.grant)));
        setFile("device",decode(values.deviceRaw));
        batchSecret.set(crypto.getRandomValues(new Uint8Array(32)));
        selectBatch(false);
        let releaseCatalog=null;
        let interceptedCatalog=false;
        const nativeFetch=window.fetch;
        window.fetch=(...args)=>{
          if(!interceptedCatalog&&String(args[0]).startsWith("/versions/legacy.txt")){
            interceptedCatalog=true;
            return new Promise(resolve=>{releaseCatalog=()=>resolve(nativeFetch(...args));});
          }
          return nativeFetch(...args);
        };
        let lateBatchDownloads=0;
        HTMLAnchorElement.prototype.click=function(){lateBatchDownloads++;};
        document.querySelector('[data-zk1-action="migration-batch"]').click();
        await wait(()=>typeof releaseCatalog==="function");
        window.dispatchEvent(new Event("rootark:logout"));
        releaseCatalog();
        await wait(()=>field("status").textContent.includes("Operação recusada"));
        if(lateBatchDownloads!==0||document.querySelector("dialog").open)
          throw Error("EDGE_LOGOUT_MID_BATCH_EXPORTED");
        window.fetch=nativeFetch;
        HTMLAnchorElement.prototype.click=originalClick;
        batchSecret.fill(0);
        // Real Edge: owner signs a NEW current history head + ACTIVE grant and
        // independently re-endorses EACH encrypted root of an older archive.
        // The browser reconstructs branded genesis->current proof and must
        // reject missing roots, stale grant, and logout after verified decrypt.
        window.__accountProbeStage="historical-real-edge";
        (await wait(()=>document.getElementById("zk1-workspace-open"))).click();
        await wait(()=>document.querySelector("dialog").open);
        const enc=new TextEncoder();
        const raw64=(bytes)=>btoa(String.fromCharCode(...bytes))
          .replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
        const signingKey=await crypto.subtle.importKey("pkcs8",
          decode(values.archiveOwnerPrivate),"Ed25519",false,["sign"]);
        const verifyingKey=await crypto.subtle.importKey("raw",decode(values.ownerRaw),
          "Ed25519",true,["verify"]);
        const scope={account_id:values.grant.account_id,
          compartment_id:values.grant.compartment_id,keyring_id:values.grant.keyring_id};
        const signerId=decode(${JSON.stringify(b64(ownerHistoryKeyId))});
        const genesisBrand=await window.RootarkZk1OwnerSignedCheckpoint.verifyOwnerCheckpoint({
          checkpoint:values.archiveHistory,scope,signerPublicKey:verifyingKey,
          signerKeyId:signerId,previous:null});
        const latestDigest=crypto.getRandomValues(new Uint8Array(32));
        const latestHead={revision:values.head.revision+1,
          digest:raw64(latestDigest),epoch:values.head.epoch+1};
        const newestHistory=await window.RootarkZk1OwnerSignedCheckpoint.signOwnerCheckpoint({
          scope,signerKey:signingKey,signerPublicKey:verifyingKey,signerKeyId:signerId,
          deviceId:values.grant.device_id,revision:latestHead.revision,
          manifestDigest:latestDigest,issuedAt:Math.floor(Date.now()/1000),previous:genesisBrand});
        const grantNames=["schema","account_id","compartment_id","keyring_id","device_id",
          "authorization_key_id","authorization_public_key","manifest_revision",
          "manifest_digest","current_epoch","enrolled_epoch","revoked_at_epoch"];
        const unsignedGrant={...values.grant,manifest_revision:latestHead.revision,
          manifest_digest:latestHead.digest,current_epoch:latestHead.epoch};
        delete unsignedGrant.signature;
        const grantPrefix=enc.encode("Root.ark/zk-1/browser-owner-device-grant/v1\\0");
        const grantBody=enc.encode(JSON.stringify(Object.fromEntries(
          grantNames.map(key=>[key,unsignedGrant[key]]))));
        const grantMessage=new Uint8Array(grantPrefix.length+grantBody.length);
        grantMessage.set(grantPrefix);grantMessage.set(grantBody,grantPrefix.length);
        const currentGrant={...unsignedGrant,signature:raw64(new Uint8Array(
          await crypto.subtle.sign("Ed25519",signingKey,grantMessage)))};
        const oldArchive=JSON.parse(exportedArchive);
        const oldContext={format:oldArchive.format,scope:oldArchive.scope,
          ownerRevision:oldArchive.ownerRevision,ownerDigest:oldArchive.ownerDigest,
          ownerEpoch:oldArchive.ownerEpoch,archiveId:oldArchive.archiveId};
        const holderKey=await crypto.subtle.importKey("raw",historicHolder,"HKDF",false,["deriveKey"]);
        const kdfPrefix=enc.encode("Root.ark/zk-1/keyring-archive-key/v1\\0");
        const kdfContext=enc.encode(JSON.stringify(oldContext));
        const kdfInfo=new Uint8Array(kdfPrefix.length+kdfContext.length);
        kdfInfo.set(kdfPrefix);kdfInfo.set(kdfContext,kdfPrefix.length);
        const oldWrap=await crypto.subtle.deriveKey({name:"HKDF",hash:"SHA-256",
          salt:decode(oldArchive.salt),info:kdfInfo},holderKey,
        {name:"AES-GCM",length:256},false,["decrypt"]);
        const oldContents=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",
          iv:decode(oldArchive.nonce),additionalData:enc.encode(JSON.stringify(oldContext)),
          tagLength:128},oldWrap,decode(oldArchive.ciphertextBase64)));
        const oldEntries=JSON.parse(new TextDecoder().decode(oldContents)).entries;
        oldContents.fill(0);
        const roots=[];
        for(const {bundle} of oldEntries) roots.push(
          await window.RootarkZk1OwnerCiphertextRootCheckpoint.signOwnerCiphertextRootCheckpoint({
            scope,signerKey:signingKey,signerKeyId:signerId,deviceId:values.grant.device_id,
            manifestRevision:latestHead.revision,manifestDigest:latestDigest,
            manifestEpoch:latestHead.epoch,objectId:bundle.metadata.object_id,
            objectRevision:bundle.objectRevision,ciphertextEpoch:bundle.metadata.epoch,
            ciphertextRoot:decode(bundle.ciphertextRoot),issuedAt:Math.floor(Date.now()/1000),
          }));
        const historyWire={signedOwnerHistoryChain:[values.archiveHistory,newestHistory],
          currentSignedDeviceGrant:currentGrant,currentOwnerRootCheckpoints:roots};
        const selectedHistory={schema:"rootark-zk1-keyring-history-endorsement/v1",
          scope,historicalRecovery:historyWire};
        const provisionHistory=()=>{
          setFile("private",decode(values.privateDer));
          setFile("owner",decode(values.ownerRaw));
          field("owner-hash").value=values.ownerHash;
          field("owner-spki").value=values.ownerSpkiHash;
          field("revision").value=latestHead.revision;
          field("digest").value=latestHead.digest;
          field("epoch").value=latestHead.epoch;
          setFile("grant",enc.encode(JSON.stringify(currentGrant)));
          setFile("history",enc.encode(JSON.stringify(historyWire.signedOwnerHistoryChain)));
          field("archive-opt-in").checked=true;
          field("archive-historical-opt-in").checked=true;
          field("owner-signer").value=${JSON.stringify(b64(ownerHistoryKeyId))};
          field("owner-device").value=values.grant.device_id;
          field("archive-sha").value=externalHash;
          setFile("archive-json",enc.encode(exportedArchive));
          setFile("secret",historicHolder);
          setFile("archive-historical-proof",enc.encode(JSON.stringify(selectedHistory)));
        };
        provisionHistory();
        document.querySelector('[data-zk1-action="provision"]').click();
        await wait(()=>field("status").textContent.includes("Piso local verificado/avançado")
          ||field("status").textContent.includes("Operação recusada"));
        if(field("status").textContent.includes("Operação recusada"))
          throw Error("HISTORICAL_CURRENT_FLOOR_NOT_PROVISIONED");
        let historicDownloads=[];
        const currentClick=HTMLAnchorElement.prototype.click;
        HTMLAnchorElement.prototype.click=function(){historicDownloads.push({name:this.download,href:this.href});};
        provisionHistory();
        document.querySelector('[data-zk1-action="archive-recover"]').click();
        await wait(()=>field("status").textContent.includes("Grant atual e reendosso")
          ||field("status").textContent.includes("Operação recusada"));
        if(!field("status").textContent.includes("Grant atual e reendosso")
          ||historicDownloads.length!==2)throw Error("HISTORICAL_VALID_RECOVERY_DENIED");
        historicDownloads=[];
        selectedHistory.historicalRecovery.currentOwnerRootCheckpoints=roots.slice(1);
        provisionHistory();
        document.querySelector('[data-zk1-action="archive-recover"]').click();
        await wait(()=>field("status").textContent.includes("Operação recusada"));
        if(historicDownloads.length)throw Error("HISTORICAL_MISSING_ROOT_LEAK");
        await wait(()=>field("archive-historical-proof").files.length===0);
        selectedHistory.historicalRecovery.currentOwnerRootCheckpoints=roots;
        selectedHistory.historicalRecovery.currentSignedDeviceGrant={...currentGrant,
          revoked_at_epoch:latestHead.epoch};
        provisionHistory();
        document.querySelector('[data-zk1-action="archive-recover"]').click();
        await wait(()=>field("status").textContent.includes("Operação recusada"));
        if(historicDownloads.length)throw Error("HISTORICAL_REVOKED_LEAK");
        await wait(()=>field("archive-historical-proof").files.length===0);
        selectedHistory.historicalRecovery.currentSignedDeviceGrant=currentGrant;
        selectedHistory.historicalRecovery.signedOwnerHistoryChain=[newestHistory];
        window.__accountProbeStage="historical-incomplete-chain";
        provisionHistory();
        document.querySelector('[data-zk1-action="archive-recover"]').click();
        await wait(()=>field("status").textContent.includes("Operação recusada"));
        if(historicDownloads.length)throw Error("HISTORICAL_NO_GENESIS_LEAK");
        await wait(()=>field("archive-historical-proof").files.length===0);
        selectedHistory.historicalRecovery.signedOwnerHistoryChain=[values.archiveHistory,newestHistory];
        selectedHistory.scope={...scope,keyring_id:values.ownerHash.slice(0,22)};
        window.__accountProbeStage="historical-cross-scope";
        provisionHistory();
        document.querySelector('[data-zk1-action="archive-recover"]').click();
        await wait(()=>field("status").textContent.includes("Operação recusada"));
        if(historicDownloads.length)throw Error("HISTORICAL_CROSS_SCOPE_LEAK");
        await wait(()=>field("archive-historical-proof").files.length===0);
        selectedHistory.scope=scope;
        // Decryption completed, but an actual logout before the returned
        // promise settles must not release its plaintext as a late download.
        provisionHistory();
        window.__accountProbeStage="historical-late-restore";
        const historicalModule=window.RootarkZk1KeyringPortableArchive;
        let releaseHistoric=null;
        window.RootarkZk1KeyringPortableArchive={...historicalModule,
          recoverArchive:async(input)=>{
            const opened=await historicalModule.recoverArchive(input);
            return new Promise(resolve=>{releaseHistoric=()=>resolve(opened);});
          }};
        document.querySelector('[data-zk1-action="archive-recover"]').click();
        await wait(()=>typeof releaseHistoric==="function"
          ||field("status").textContent.includes("Operação recusada"));
        if(typeof releaseHistoric!=="function")
          throw Error("HISTORICAL_LATE_NOT_REACHED");
        window.dispatchEvent(new Event("rootark:logout"));
        releaseHistoric();
        await wait(()=>field("status").textContent.includes("Operação recusada"));
        if(historicDownloads.length||document.querySelector("dialog").open)
          throw Error("HISTORICAL_LOGOUT_LATE_RELEASE");
        window.RootarkZk1KeyringPortableArchive=historicalModule;
        historicHolder.fill(0);
        HTMLAnchorElement.prototype.click=currentClick;
        output.textContent="EDGE_AUTH_WORKSPACE_PASS";
      } catch(e){output.textContent="EDGE_AUTH_WORKSPACE_FAIL:"+e.message+
        ":STAGE="+(window.__accountProbeStage||"before-account")+
        ":STATUS="+(document.querySelector('[data-zk1-field="status"]')?.textContent||"");}
    });`));
  const server = await new Promise((resolve) => {
    const value = app.listen(0, "127.0.0.1", () => resolve(value));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = "http://127.0.0.1:" + server.address().port;
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-edge-auth-workspace-"));
  new vm.Script(await (await fetch(origin + "/workspace-probe.js")).text());
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
    }).catch(async (cause) => {
      const debug = await send("Runtime.evaluate", { expression:
        "JSON.stringify({status:document.querySelector('[data-zk1-field=status]')?.textContent,stage:window.__accountProbeStage,busy:document.querySelector('[data-zk1-action=pending-resume]')?.disabled,output:document.getElementById('edge-workspace-result')?.textContent})",
      returnByValue: true });
      throw new Error(cause.message + ": " + debug.result?.value);
    });
    assert.equal(observed, "EDGE_AUTH_WORKSPACE_PASS");
    const edgeProof = await send("Runtime.evaluate", {
      expression: "window.edgeV2Pop || null", returnByValue: true,
    });
    const signedPoP = edgeProof.result?.value;
    assert.equal(signedPoP?.schema, "rootark-zk1-v2-browser-pop-response/v1");
    const verifiedPoP = await targetPop.verifyTargetPopResponse({
      challenge: ownerChallenge,
      challengeContext: ownerChallenge.challengeContext,
      response: { challenge_context: ownerChallenge.challengeContext,
        challenge: Buffer.from(signedPoP.challenge, "base64url"),
        target_signature: Buffer.from(signedPoP.target_signature, "base64url") },
      expectedScope: f.state.scope,
      expectedDeviceKeyDigest: ownerChallenge.challengeContext.target_device_key_digest,
      now: popNow + 30,
    });
    assert.equal(await targetPop.isVerifiedTargetPopResponse(verifiedPoP, popNow + 30), true);
    assert.equal(protectedPuts, 0,
      "V1 backend cannot be tricked into receiving V2 PUTs, even when independent browser PoP succeeds");
    assert.equal(f.store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_object").get().n, 0);
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
