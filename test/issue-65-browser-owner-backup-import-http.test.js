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
  const input = { approval: signOwner(), trustedOwnerPublicKey: ownerPublicKey,
    trustedRoot: root, trustedEpoch: metadata.epoch,
    ciphertextBase64: b64(sealed), signer, origin, fetchImpl };
  return { input, signOwner, approvalUnsigned, scopeWire, metadata, cek,
    plaintext, sealed, root, origin, fetchImpl, store, state, head,
    get countPut() { return countPut; }, get networkReads() { return networkReads; },
    get wire() { return wire; }, setGate: (value) => { gateOpen = value; },
    revoke: async () => { await fixtures.appendDeviceRevocation(state, device.device_id);
      head = state.headManifest; },
    currentSigner: async () => ({ ...signer, manifestRevision: head.revision,
      manifestDigest: await manifestDigest(), epoch: head.current_epoch }),
  };
}

test("real protected HTTP import verifies owner signature and pinned root before restoring sealed bytes", async (t) => {
  const f = await scenario(t);
  const result = await importer.importOwnerSignedBackupCiphertext(f.input);
  assert.equal(result.ownerSignatureVerified, true);
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
    { ...f.input, trustedOwnerPublicKey: null },
    { ...f.input, approval: { ...f.input.approval, signatureBase64: b64(crypto.randomBytes(64)) } },
    { ...f.input, trustedRoot: crypto.randomBytes(32) },
    { ...f.input, trustedEpoch: f.input.trustedEpoch + 1 },
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
  assert.equal(f.store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_object").get().n, 0);
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

test("browser standalone UMD loads signed backup importer without Node capabilities", () => {
  const context = vm.createContext({ crypto: crypto.webcrypto,
    TextEncoder, TextDecoder, URL, btoa, atob, Uint8Array, ArrayBuffer,
    RootarkZk1CiphertextRoot: roots,
    RootarkZk1ProtectedHttpClient: http });
  vm.runInContext(fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-owner-backup-import.js"), "utf8"), context);
  assert.equal(typeof context.RootarkZk1OwnerBackupImport.importOwnerSignedBackupCiphertext,
    "function");
});
