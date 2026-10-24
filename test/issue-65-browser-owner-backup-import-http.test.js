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
const roots = require("../public/client/rootark-zk1-ciphertext-chunk-root");
const http = require("../public/client/rootark-zk1-protected-http-client");
const importer = require("../public/client/rootark-zk1-owner-backup-import");
const history = require("../public/client/rootark-zk1-owner-signed-checkpoint");
const signedRoot = require("../public/client/rootark-zk1-owner-ciphertext-root-checkpoint");
const { Zk1ProtectedObjectStore } = require("../src/services/zk1ProtectedObjectStore");
const { registerZk1ProtectedObjectRoutes } = require("../src/routes/zk1ProtectedObjectRoutes");

const domain = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");
const ownerDomain = Buffer.from("Root.ark/zk-1/client-backup-import-authorization/v1\0");
const id = () => crypto.randomBytes(16).toString("base64url");
const b64 = (bytes) => Buffer.from(bytes).toString("base64url");

async function scenario(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-owner-import-"));
  const state = await fixtures.createInitialState(2);
  const scope = state.scope;
  const scopeWire = Object.fromEntries(Object.entries(scope)
    .map(([key, value]) => [key, b64(value)]));
  const witnessKeys = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  let gateOpen = true;
  let head = state.headManifest;
  let countPut = 0;
  let networkReads = 0;
  let wire = "";
  const manifestDigest = () => v2.recoveryManifestDigestV2(head);
  const witnessProvider = {
    async freshHead({ nonce }) {
      const msg = { type: "rootark-recovery-witness-head/v1",
        witness_key_id: witnessKeyId, ...scope, nonce,
        current_revision: head.revision,
        current_manifest_digest: await manifestDigest(),
        witness_sequence: head.revision, observed_at: 1400,
        status: gateOpen ? "committed" : "pending",
        pending_reservation_id: gateOpen ? null : crypto.randomBytes(16) };
      return z.encodeDeterministic({ ...msg, signature: crypto.sign(null,
        Buffer.concat([domain, Buffer.from(await z.encodeDeterministic(msg))]),
        witnessKeys.privateKey) });
    },
    async beginIoAdmission() {
      if (!gateOpen) throw Error("PENDING_GATE");
      return { admissionId: crypto.randomBytes(16), proceed: true };
    },
    async finishIoAdmission() { return { status: "completed" }; },
  };
  const store = new Zk1ProtectedObjectStore(path.join(dir, "protected.sqlite"), {
    trustedScope: scope, bootstrapNew: true, admissionRequired: true,
    minimumHead: { revision: 1, witnessSequence: 1,
      digest: await v2.recoveryManifestDigestV2(state.baseManifest) },
    witnessProvider, witnessPinned: {
      keyId: witnessKeyId, publicKey: witnessKeys.publicKey },
    manifestProvider: () => z.encodeDeterministic(head),
    nowSeconds: () => 1400,
  });
  const app = express();
  const authenticate = (req, res, next) => {
    if (req.get("x-owner-test") !== "yes") return res.sendStatus(401);
    req.user = { username: "owner" }; next();
  };
  registerZk1ProtectedObjectRoutes({ app, store, authenticate,
    requirePermission: () => (_req, _res, next) => next(),
    resolveTrustedScope: () => scope });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    store.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const fetchImpl = (url, options) => {
    if (url.endsWith("/content/put")) countPut++;
    if (url.endsWith("/content/read")) networkReads++;
    wire = String(options.body);
    return fetch(url, { ...options,
      headers: { ...options.headers, "x-owner-test": "yes" } });
  };
  const owner = crypto.generateKeyPairSync("ed25519");
  const ownerPublicKey = await crypto.webcrypto.subtle.importKey("spki",
    owner.publicKey.export({ format: "der", type: "spki" }),
    "Ed25519", false, ["verify"]);
  const ownerSignerKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    owner.privateKey.export({ format: "der", type: "pkcs8" }),
    "Ed25519", false, ["sign"]);
  const ownerKeySpki = owner.publicKey.export({ format: "der", type: "spki" });
  const ownerKeyId = crypto.randomBytes(16);
  const ownerDeviceId = "independently-enrolled-owner";
  const ownerIdentity = { scope: scopeWire, deviceId: ownerDeviceId,
    signerKeyId: ownerKeyId, publicKeySpki: ownerKeySpki };
  const independentOwnerSpkiSha256 = crypto.createHash("sha256").update(ownerKeySpki).digest();
  const device = head.devices[0];
  const devicePrivate = state.actors.get(Buffer.from(device.authorization_key_id).toString("hex"));
  const signerKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    devicePrivate.export({ format: "der", type: "pkcs8" }),
    "Ed25519", false, ["sign"]);
  const signer = { signerKey, scope: scopeWire, deviceId: device.device_id,
    manifestRevision: head.revision, manifestDigest: await manifestDigest(),
    epoch: head.current_epoch, nowSeconds: 1400 };
  const metadata = { ...scopeWire, object_id: id(), version_id: id(),
    parent_version_id: null, epoch: head.current_epoch, kind: "file" };
  const cek = await file.generateFileCek();
  const plaintext = Buffer.from("owner ZK restore test: hidden filename and payload\0trusted", "utf8");
  const sealed = await file.encryptFile({ cek, metadata,
    name: "hidden-from-server.txt", mediaType: "application/octet-stream",
    data: plaintext });
  const root = await roots.computeCiphertextRoot([sealed]);
  const approvalUnsigned = {
    schema: "rootark-zk1-client-backup-import-authorization/v1",
    ...scopeWire, object_id: metadata.object_id, version_id: metadata.version_id,
    epoch: metadata.epoch, source_revision: 1,
    manifest_revision: signer.manifestRevision,
    manifest_digest: b64(signer.manifestDigest), expires_at: 1445,
    ciphertext_sha256: b64(crypto.createHash("sha256").update(sealed).digest()),
    ciphertext_root: b64(root),
  };
  const signOwner = (unsigned = approvalUnsigned, key = owner.privateKey) => ({ ...unsigned,
    signatureBase64: b64(crypto.sign(null,
      Buffer.concat([ownerDomain, Buffer.from(JSON.stringify(unsigned))]), key)) });
  const ownerHistoryCheckpoint = await history.signOwnerCheckpoint({
    scope: scopeWire, signerKey: ownerSignerKey, signerPublicKey: ownerPublicKey,
    signerKeyId: ownerKeyId, deviceId: ownerDeviceId,
    revision: signer.manifestRevision, manifestDigest: signer.manifestDigest,
    issuedAt: 1390, previous: null,
  });
  const ownerRootCheckpoint = await signedRoot.signOwnerCiphertextRootCheckpoint({
    scope: scopeWire, signerKey: ownerSignerKey, signerKeyId: ownerKeyId,
    deviceId: ownerDeviceId, manifestRevision: signer.manifestRevision,
    manifestDigest: signer.manifestDigest, manifestEpoch: metadata.epoch,
    objectId: metadata.object_id, objectRevision: 1,
    ciphertextEpoch: metadata.epoch, ciphertextRoot: root, issuedAt: 1391,
  });
  const approval = signOwner();
  const prepareTrust = (overrides = {}) => importer.prepareOwnerBackupImportTrust({
    ownerIdentity, independentOwnerSpkiSha256, ownerHistoryCheckpoint,
    previousHistoryProof: null, ownerRootCheckpoint, approval, ...overrides,
  });
  const ownerTrust = await prepareTrust();
  const input = { approval, ownerTrust, ciphertextBase64: b64(sealed),
    signer, origin, fetchImpl };
  return { input, signOwner, approvalUnsigned, scopeWire, metadata, cek,
    plaintext, sealed, root, origin, fetchImpl, store, state, head,
    prepareTrust, ownerIdentity, independentOwnerSpkiSha256,
    ownerHistoryCheckpoint, ownerRootCheckpoint, ownerPublicKey, ownerSignerKey,
    ownerKeyId, ownerDeviceId,
    get countPut() { return countPut; }, get networkReads() { return networkReads; },
    get wire() { return wire; }, setGate: (value) => { gateOpen = value; },
    revoke: async () => { await fixtures.appendDeviceRevocation(state, device.device_id);
      head = state.headManifest; },
    secondSigner: async () => {
      const second = head.devices[1];
      const privateKey = state.actors.get(Buffer.from(second.authorization_key_id).toString("hex"));
      return { ...signer, signerKey: await crypto.webcrypto.subtle.importKey("pkcs8",
        privateKey.export({ format: "der", type: "pkcs8" }),
        "Ed25519", false, ["sign"]), deviceId: second.device_id };
    },
    currentSigner: async () => ({ ...signer, manifestRevision: head.revision,
      manifestDigest: await manifestDigest(), epoch: head.current_epoch }),
  };
}

test("real protected HTTP import verifies owner signature and pinned root before restoring sealed bytes", async (t) => {
  const f = await scenario(t);
  const result = await importer.importOwnerSignedBackupCiphertext(f.input);
  assert.equal(result.ownerSignatureVerified, true);
  assert.equal(result.signedHistoricalRootVerified, true);
  assert.equal(result.externalPinSourceVerifiedByModule, false);
  assert.equal(result.ciphertextReadbackVerified, true);
  assert.equal(result.independentDurabilityProven, false);
  assert.equal(result.authorizesRestore, false);
  assert.equal(result.authorizesRecovery, false);
  assert.equal(result.authorizesRelease, false);
  assert.equal(f.countPut, 1);
  assert.equal(f.networkReads, 1);
  assert.equal(f.wire.includes("hidden-from-server.txt"), false);
  assert.equal(f.wire.includes("owner ZK restore test"), false);
  assert.equal(f.wire.includes("cek"), false);
  const ciphertext = f.store.db.prepare("SELECT ciphertext FROM zk_content_object WHERE id=?")
    .get(f.metadata.object_id).ciphertext;
  assert.deepEqual(Buffer.from(ciphertext), Buffer.from(f.sealed));
  assert.equal(Buffer.from(ciphertext).includes(f.plaintext), false);
  const get = await http.signProtectedContentOperation({
    ...f.input.signer, operation: "get", objectId: f.metadata.object_id,
    expectedObjectRevision: 1,
    expectedCiphertextDigest: crypto.createHash("sha256").update(f.sealed).digest(),
    ciphertext: null,
  });
  const decrypted = await http.postProtectedCiphertextRead({
    origin: f.origin, request: get, fetchImpl: f.fetchImpl,
    expectedObjectRevision: 1, expectedRoot: f.root, cek: f.cek,
    metadata: f.metadata,
  });
  assert.deepEqual(Buffer.from(decrypted.data), f.plaintext,
    "only the owner-held CEK on the client can decrypt the imported ciphertext");
  decrypted.data.fill(0);
  await assert.rejects(importer.importOwnerSignedBackupCiphertext(f.input),
    /ZK_OWNER_BACKUP_IMPORT_DENIED/,
    "replaying an approved backup may not overwrite an existing object");
  assert.equal(f.store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_version").get().n, 1);
});

test("missing/forged owner, tampered ciphertext, scope, epoch, root and malformed envelope deny before network", async (t) => {
  const f = await scenario(t);
  const invalid = [
    { ...f.input, ownerTrust: null },
    { ...f.input, approval: { ...f.input.approval, signatureBase64: b64(crypto.randomBytes(64)) } },
    { ...f.input, trustedOwnerPublicKey: f.ownerPublicKey },
    { ...f.input, trustedRoot: f.root },
    { ...f.input, trustedEpoch: f.metadata.epoch },
    { ...f.input, ciphertextBase64: b64(crypto.randomBytes(128)) },
    { ...f.input, approval: f.signOwner({ ...f.approvalUnsigned,
      account_id: id() }) },
    { ...f.input, approval: f.signOwner({ ...f.approvalUnsigned,
      epoch: f.approvalUnsigned.epoch + 1 }) },
    { ...f.input, approval: f.signOwner({ ...f.approvalUnsigned,
      ciphertext_sha256: b64(crypto.randomBytes(32)) }) },
    { ...f.input, approval: f.signOwner({ ...f.approvalUnsigned,
      source_revision: 2 }) },
    { ...f.input, approval: f.signOwner({ ...f.approvalUnsigned,
      manifest_digest: b64(crypto.randomBytes(32)) }) },
    { ...f.input, approval: f.signOwner({ ...f.approvalUnsigned,
      expires_at: 1399 }) },
    { ...f.input, cek: f.cek },
  ];
  for (const entry of invalid) {
    await assert.rejects(importer.importOwnerSignedBackupCiphertext(entry),
      /ZK_OWNER_BACKUP_IMPORT_DENIED/);
    assert.equal(f.countPut, 0);
    assert.equal(f.networkReads, 0);
  }
  await assert.rejects(f.prepareTrust({ approval: f.signOwner({
    ...f.approvalUnsigned, ciphertext_root: b64(crypto.randomBytes(32)) }) }),
  /ZK_OWNER_BACKUP_IMPORT_DENIED/, "signed root must bind the exact ciphertext root");
  await assert.rejects(f.prepareTrust({ approval: f.signOwner({
    ...f.approvalUnsigned, epoch: f.approvalUnsigned.epoch + 1 }) }),
  /ZK_OWNER_BACKUP_IMPORT_DENIED/, "a higher claimed epoch is not owner root provenance");
  assert.equal(f.store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_object").get().n, 0);
});

test("self-signed archive cannot replace external owner pin, signed root or historic floor", async (t) => {
  const f = await scenario(t);
  const attacker = crypto.generateKeyPairSync("ed25519");
  const attackerSpki = attacker.publicKey.export({ format: "der", type: "spki" });
  // The archive may carry its own complete key, signature and claimed root.
  // Its SPKI is still not authorized by an independently retained fingerprint.
  await assert.rejects(f.prepareTrust({ ownerIdentity: {
    ...f.ownerIdentity, publicKeySpki: attackerSpki },
  }), /ZK_OWNER_BACKUP_IMPORT_DENIED/);
  await assert.rejects(f.prepareTrust({ independentOwnerSpkiSha256: crypto.randomBytes(32) }),
    /ZK_OWNER_BACKUP_IMPORT_DENIED/);
  await assert.rejects(f.prepareTrust({ ownerRootCheckpoint: {
    ...f.ownerRootCheckpoint, ciphertext_root: b64(crypto.randomBytes(32)) },
  }), /ZK_OWNER_BACKUP_IMPORT_DENIED/);
  const substitutedSignedRoot = await signedRoot.signOwnerCiphertextRootCheckpoint({
    scope: f.scopeWire, signerKey: f.ownerSignerKey,
    signerKeyId: f.ownerKeyId, deviceId: f.ownerDeviceId,
    manifestRevision: f.input.signer.manifestRevision,
    manifestDigest: f.input.signer.manifestDigest,
    manifestEpoch: f.metadata.epoch, objectId: id(), objectRevision: 1,
    ciphertextEpoch: f.metadata.epoch, ciphertextRoot: f.root, issuedAt: 1391,
  });
  await assert.rejects(f.prepareTrust({ ownerRootCheckpoint: substitutedSignedRoot }),
    /ZK_OWNER_BACKUP_IMPORT_DENIED/,
    "even an authentic root for another object is not interchangeable");
  await assert.rejects(f.prepareTrust({ ownerHistoryCheckpoint: {
    ...f.ownerHistoryCheckpoint, manifest_digest: b64(crypto.randomBytes(32)) },
  }), /ZK_OWNER_BACKUP_IMPORT_DENIED/);
  // The local verified checkpoint is the minimum head: accepting the same
  // archived earlier checkpoint as its own successor would roll history back.
  const verifiedHead = await history.verifyOwnerCheckpoint({
    checkpoint: f.ownerHistoryCheckpoint, scope: f.scopeWire,
    signerPublicKey: f.ownerPublicKey, signerKeyId: f.ownerKeyId,
    previous: null,
  });
  await assert.rejects(f.prepareTrust({ previousHistoryProof: verifiedHead }),
    /ZK_OWNER_BACKUP_IMPORT_DENIED/);
  await assert.rejects(importer.importOwnerSignedBackupCiphertext({
    ...f.input, signer: { ...f.input.signer, epoch: f.metadata.epoch + 1 },
  }), /ZK_OWNER_BACKUP_IMPORT_DENIED/,
  "a valid old owner archive cannot override the signer's newer epoch");
  await assert.rejects(importer.importOwnerSignedBackupCiphertext({
    ...f.input, ownerTrust: { ...f.input.ownerTrust },
  }), /ZK_OWNER_BACKUP_IMPORT_DENIED/, "a JSON clone cannot forge the trusted capability");
  assert.equal(f.countPut, 0);
  assert.equal(f.networkReads, 0);
});

test("signed historical read rejects a replayed ciphertext response and makes no restore claim", async (t) => {
  const f = await scenario(t);
  const replayFetch = async (url, options) => {
    if (url.endsWith("/content/read")) return new Response(JSON.stringify({
      id: f.metadata.object_id, revision: 1, epoch: f.metadata.epoch,
      ciphertextBase64: b64(crypto.randomBytes(f.sealed.length)),
    }), { status: 200, headers: { "content-type": "application/json" } });
    return f.fetchImpl(url, options);
  };
  await assert.rejects(importer.importOwnerSignedBackupCiphertext({
    ...f.input, fetchImpl: replayFetch,
  }), /ZK_OWNER_BACKUP_IMPORT_DENIED/);
  assert.equal(f.countPut, 1);
  assert.equal(f.networkReads, 0, "replayed GET is intercepted before actual server read");
  assert.deepEqual(Buffer.from(f.store.db.prepare(
    "SELECT ciphertext FROM zk_content_object WHERE id=?").get(f.metadata.object_id).ciphertext),
  Buffer.from(f.sealed), "ciphertext remains for a manual uncertain-write reconciliation");
  await assert.rejects(importer.importOwnerSignedBackupCiphertext(f.input),
    /ZK_OWNER_BACKUP_IMPORT_DENIED/, "same signed archive cannot replace the first write");
});

test("witness pending and revoked device refuse backup import without storing ciphertext", async (t) => {
  const f = await scenario(t);
  f.setGate(false);
  await assert.rejects(importer.importOwnerSignedBackupCiphertext(f.input),
    /ZK_OWNER_BACKUP_IMPORT_DENIED/);
  f.setGate(true);
  await f.revoke();
  await assert.rejects(importer.importOwnerSignedBackupCiphertext({ ...f.input,
    signer: await f.currentSigner(),
  }), /ZK_OWNER_BACKUP_IMPORT_DENIED/);
  assert.equal(f.store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_object").get().n, 0);
});

test("lost PUT acknowledgement stays uncertain and never retries or deletes the sealed copy", async (t) => {
  const f = await scenario(t);
  let putCalls = 0;
  const unreliableFetch = async (url, options) => {
    const response = await f.fetchImpl(url, options);
    if (url.endsWith("/content/put")) {
      putCalls++;
      throw new Error("synthetic lost PUT ACK after durable response");
    }
    return response;
  };
  await assert.rejects(importer.importOwnerSignedBackupCiphertext({ ...f.input,
    fetchImpl: unreliableFetch,
  }), /ZK_OWNER_BACKUP_IMPORT_DENIED/);
  assert.equal(putCalls, 1, "unknown outcome cannot cause automatic PUT replay");
  assert.equal(f.countPut, 1);
  assert.equal(f.networkReads, 0, "without a witnessed ACK, this operation makes no success claim");
  assert.deepEqual(Buffer.from(f.store.db.prepare(
    "SELECT ciphertext FROM zk_content_object WHERE id=?").get(f.metadata.object_id).ciphertext),
  Buffer.from(f.sealed), "already stored ciphertext must remain intact for later manual reconciliation");
});

test("second enrolled device reconciles lost ACK through signed HTTP GET, without another PUT or restore authority", async (t) => {
  const f = await scenario(t);
  const lostAck = async (url, options) => {
    const response = await f.fetchImpl(url, options);
    if (url.endsWith("/content/put")) throw Error("lost ACK after durable commit");
    return response;
  };
  await assert.rejects(importer.importOwnerSignedBackupCiphertext({
    ...f.input, fetchImpl: lostAck,
  }), /ZK_OWNER_BACKUP_IMPORT_DENIED/);
  assert.equal(f.countPut, 1);
  assert.equal(f.networkReads, 0);

  const remoteDevice = await f.secondSigner();
  const readback = await importer.reconcileOwnerSignedBackupCiphertext({
    ...f.input, signer: remoteDevice,
  });
  assert.equal(readback.objectId, f.metadata.object_id);
  assert.equal(readback.revision, 1);
  assert.equal(readback.ownerSignatureVerified, true);
  assert.equal(readback.signedHistoricalRootVerified, true);
  assert.equal(readback.ciphertextReadbackVerified, true);
  assert.equal(readback.reconciledWithoutWrite, true);
  assert.equal(readback.authorizesRestore, false);
  assert.equal(readback.authorizesRecovery, false);
  assert.equal(readback.independentDurabilityProven, false);
  assert.equal(f.countPut, 1, "second device must NEVER resend uncertain PUT");
  assert.equal(f.networkReads, 1, "second device authenticates exact remote ciphertext");
  // The second device can now use an independently held owner CEK to open the
  // exact sealed object locally. The server never sees that key or plaintext.
  const get = await http.signProtectedContentOperation({
    ...remoteDevice, operation: "get", objectId: f.metadata.object_id,
    expectedObjectRevision: 1,
    expectedCiphertextDigest: crypto.createHash("sha256").update(f.sealed).digest(),
    ciphertext: null,
  });
  const reopened = await http.postProtectedCiphertextRead({
    origin: f.origin, request: get, fetchImpl: f.fetchImpl,
    expectedObjectRevision: 1, expectedRoot: f.root,
    cek: f.cek, metadata: f.metadata,
  });
  assert.deepEqual(Buffer.from(reopened.data), f.plaintext);
  reopened.data.fill(0);
  assert.equal(f.countPut, 1);
  assert.equal(f.networkReads, 2);
  assert.equal(f.store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_version").get().n, 1);
});

test("owner backup reconcile refuses missing write, forged preflight, tampered GET and pending/revoked admission", async (t) => {
  const f = await scenario(t);
  const second = await f.secondSigner();
  const recovered = { ...f.input, signer: second };
  await assert.rejects(importer.reconcileOwnerSignedBackupCiphertext(recovered),
    /ZK_OWNER_BACKUP_IMPORT_DENIED/, "an intent without committed remote bytes never succeeds");
  assert.equal(f.countPut, 0);
  assert.equal(f.networkReads, 1);

  const readsBefore = f.networkReads;
  for (const invalid of [
    { ...recovered, ownerTrust: null },
    { ...recovered, approval: { ...recovered.approval, signatureBase64: b64(crypto.randomBytes(64)) } },
    { ...recovered, ciphertextBase64: b64(crypto.randomBytes(64)) },
    { ...recovered, signer: { ...second, epoch: second.epoch + 1 } },
    { ...recovered, signer: { ...second, nowSeconds: 1500 } },
  ]) await assert.rejects(importer.reconcileOwnerSignedBackupCiphertext(invalid),
    /ZK_OWNER_BACKUP_IMPORT_DENIED/);
  assert.equal(f.countPut, 0, "invalid owner proof must not write");
  assert.equal(f.networkReads, readsBefore, "invalid owner proof must fail before network");

  await importer.importOwnerSignedBackupCiphertext(f.input);
  const tamperedFetch = (url, options) => {
    if (url.endsWith("/content/read")) return Promise.resolve(new Response(JSON.stringify({
      id: f.metadata.object_id, revision: 1, epoch: f.metadata.epoch,
      ciphertextBase64: b64(crypto.randomBytes(f.sealed.length)),
    }), { status: 200, headers: { "content-type": "application/json" } }));
    return f.fetchImpl(url, options);
  };
  await assert.rejects(importer.reconcileOwnerSignedBackupCiphertext({
    ...recovered, fetchImpl: tamperedFetch,
  }), /ZK_OWNER_BACKUP_IMPORT_DENIED/);
  f.setGate(false);
  await assert.rejects(importer.reconcileOwnerSignedBackupCiphertext(recovered),
    /ZK_OWNER_BACKUP_IMPORT_DENIED/, "pending witness gate blocks historical readback");
  f.setGate(true);
  await f.revoke();
  await assert.rejects(importer.reconcileOwnerSignedBackupCiphertext(f.input),
    /ZK_OWNER_BACKUP_IMPORT_DENIED/, "revoked device cannot reconcile");
  assert.equal(f.countPut, 1, "all reconciliation paths remain GET-only");
});

test("browser standalone UMD loads signed backup importer without Node capabilities", () => {
  const context = vm.createContext({ crypto: crypto.webcrypto,
    TextEncoder, TextDecoder, URL, btoa, atob, Uint8Array, ArrayBuffer,
    RootarkZk1CiphertextRoot: roots,
    RootarkZk1ProtectedHttpClient: http,
    RootarkZk1OwnerCiphertextRootCheckpoint: signedRoot });
  vm.runInContext(fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-owner-backup-import.js"), "utf8"), context);
  assert.equal(typeof context.RootarkZk1OwnerBackupImport.importOwnerSignedBackupCiphertext,
    "function");
  assert.equal(typeof context.RootarkZk1OwnerBackupImport.prepareOwnerBackupImportTrust,
    "function");
  assert.equal(typeof context.RootarkZk1OwnerBackupImport.reconcileOwnerSignedBackupCiphertext,
    "function");
});
