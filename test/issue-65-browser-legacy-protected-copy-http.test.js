"use strict";

const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const express = require("express");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const file = require("../public/client/rootark-zk1-file-content");
const migrate = require("../public/client/rootark-zk1-legacy-protected-copy");
const { Zk1ProtectedObjectStore } = require("../src/services/zk1ProtectedObjectStore");
const { registerZk1ProtectedObjectRoutes } =
  require("../src/routes/zk1ProtectedObjectRoutes");

const ID = () => crypto.randomBytes(16).toString("base64url");
const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const headDomain = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");

test("legacy ciphertext copy rejects oversized manifest digest before reading source", async () => {
  const scope = { account_id: ID(), compartment_id: b64(Buffer.from("lab")),
    keyring_id: ID() };
  const oversized = new Uint8Array(33);
  let sliceCalls = 0;
  oversized.buffer.slice = () => { sliceCalls++; throw Error("oversized clone attempted"); };
  let reads = 0;
  await assert.rejects(migrate.copyLegacyIntoProtectedCiphertext({
    legacy: { name: "legacy.txt", folderId: "" },
    metadata: { ...scope, object_id: ID(), version_id: ID(),
      parent_version_id: null, epoch: 1, kind: "file" },
    signer: { signerKey: null, scope, deviceId: "trusted", manifestRevision: 1,
      manifestDigest: oversized, epoch: 1, nowSeconds: 1400 },
    cek: null, origin: "http://127.0.0.1:1234/",
    fetchImpl: () => { reads++; throw Error("should not read source"); },
  }), /ZK_CLIENT_MIGRATION_UNVERIFIED/);
  assert.equal(sliceCalls, 0, "oversized digest must be rejected before copying backing buffer");
  assert.equal(reads, 0, "oversized digest must be rejected before a legacy plaintext read");
});

async function fixture(t) {
  const dir = createPrivateAuthorityFixture("rootark-zk1-legacy-copy-");
  const state = await fixtures.createInitialState(2);
  const witnessKey = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const scope = state.scope;
  const scopeWire = Object.fromEntries(Object.entries(scope)
    .map(([field, value]) => [field, b64(value)]));
  const manifest = state.headManifest;
  const digest = await v2.recoveryManifestDigestV2(manifest);
  let sourceBytes = Buffer.from("Legacy owner plaintext only in old route. Secret filename.");
  let sourceReads = 0;
  const app = express();
  app.get("/files/:name", (req, res) => {
    if (req.get("x-lab-session") !== "owner") return res.sendStatus(401);
    if (req.params.name !== "report.txt") return res.sendStatus(404);
    sourceReads++;
    res.setHeader("content-type", "text/plain");
    res.setHeader("content-disposition", 'attachment; filename="report.txt"');
    res.setHeader("content-length", sourceBytes.length);
    res.status(200).end(sourceBytes);
  });
  const witnessProvider = {
    async freshHead({ nonce }) {
      const message = {
        type: "rootark-recovery-witness-head/v1",
        witness_key_id: witnessKeyId, ...scope, nonce,
        current_revision: manifest.revision,
        current_manifest_digest: digest, witness_sequence: manifest.revision,
        observed_at: 1400, status: "committed", pending_reservation_id: null,
      };
      const signature = crypto.sign(null, Buffer.concat([
        headDomain, Buffer.from(await z.encodeDeterministic(message)),
      ]), witnessKey.privateKey);
      return z.encodeDeterministic({ ...message, signature });
    },
    async beginIoAdmission() {
      return { admissionId: crypto.randomBytes(16), proceed: true };
    },
    async finishIoAdmission() { return { status: "FINISHED" }; },
  };
  const store = new Zk1ProtectedObjectStore(path.join(dir, "protected.sqlite"), {
    trustedScope: scope, bootstrapNew: true, admissionRequired: true,
    minimumHead: { revision: 1, witnessSequence: 1,
      digest: await v2.recoveryManifestDigestV2(state.baseManifest) },
    witnessProvider, witnessPinned: {
      keyId: witnessKeyId, publicKey: witnessKey.publicKey,
    }, manifestProvider: () => z.encodeDeterministic(manifest),
    nowSeconds: () => 1400,
  });
  const authenticate = (req, res, next) => {
    if (req.get("x-lab-session") !== "owner") return res.sendStatus(401);
    req.user = { username: "owner" }; next();
  };
  registerZk1ProtectedObjectRoutes({ app, store, authenticate,
    requirePermission: () => (_req, _res, next) => next(),
    resolveTrustedScope: () => scope });
  const server = await new Promise((resolve) => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    store.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const origin = "http://127.0.0.1:" + server.address().port;
  const realFetch = (url, options) => fetch(url.startsWith("/") ? origin + url : url, {
    ...options, headers: { ...options.headers, "x-lab-session": "owner" },
  });
  const device = manifest.devices[0];
  const devicePrivate = state.actors.get(Buffer.from(device.authorization_key_id).toString("hex"));
  const signerKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    devicePrivate.export({ type: "pkcs8", format: "der" }),
    "Ed25519", false, ["sign"]);
  const metadata = { ...scopeWire, object_id: ID(), version_id: ID(),
    parent_version_id: null, epoch: manifest.current_epoch, kind: "file" };
  const context = { signerKey, scope: scopeWire, deviceId: device.device_id,
    manifestRevision: manifest.revision, manifestDigest: digest,
    epoch: manifest.current_epoch, nowSeconds: 1400 };
  const cek = await file.generateFileCek();
  return { origin, store, metadata, context, cek, realFetch, dir,
    get sourceReads() { return sourceReads; },
    setSource: (value) => { sourceBytes = Buffer.from(value); },
    legacyBytes: Buffer.from(sourceBytes) };
}

test("legacy plaintext is copied by client AEAD into actual protected HTTP store, verified and never deleted", async (t) => {
  const f = await fixture(t);
  const result = await migrate.copyLegacyIntoProtectedCiphertext({
    legacy: { name: "report.txt", folderId: "" },
    metadata: f.metadata, signer: f.context, cek: f.cek,
    origin: f.origin, fetchImpl: f.realFetch,
  });
  assert.equal(result.authorizesCutover, false);
  assert.equal(result.canDeleteLegacy, false);
  assert.equal(result.protectedCiphertextLocallyVerified, true);
  assert.equal(result.sourceRechecked, true);
  assert.equal(result.revision, 1);
  assert.equal(result.objectId, f.metadata.object_id);
  assert.equal(result.ciphertextRoot.length, 32);
  assert.equal(f.sourceReads, 2, "source is reread before any possible cutover statement");
  const row = f.store.db.prepare("SELECT ciphertext FROM zk_content_object WHERE id=?")
    .get(f.metadata.object_id);
  assert.ok(row);
  assert.equal(row.ciphertext.includes(f.legacyBytes), false,
    "server holds only authenticated ciphertext, not original plaintext");
  assert.equal(row.ciphertext.toString().includes("report.txt"), false);
  const source = await f.realFetch("/files/report.txt", { method: "GET" });
  assert.equal(source.status, 200);
  assert.deepEqual(Buffer.from(await source.arrayBuffer()), f.legacyBytes,
    "original legacy source bytes remain byte-for-byte intact");
});

test("plain browser UMD modules compose legacy encrypted copy without Node require or server plaintext decrypt", async (t) => {
  const f = await fixture(t);
  const context = vm.createContext({
    crypto: crypto.webcrypto, TextEncoder, TextDecoder, URL, btoa, atob,
    Uint8Array, ArrayBuffer, AbortController, setTimeout, clearTimeout,
    location: { origin: f.origin },
  });
  for (const moduleName of [
    "rootark-dev-vault-migration.js",
    "rootark-zk1-file-content.js",
    "rootark-zk1-ciphertext-chunk-root.js",
    "rootark-zk1-ciphertext-download-integrity.js",
    "rootark-zk1-protected-http-client.js",
    "rootark-zk1-legacy-protected-copy.js",
  ]) {
    const script = fs.readFileSync(path.join(__dirname, "../public/client", moduleName), "utf8");
    vm.runInContext(script, context);
  }
  context.cek = f.cek;
  context.signerKey = f.context.signerKey;
  context.scope = f.context.scope;
  context.digest = f.context.manifestDigest;
  context.metadata = f.metadata;
  context.origin = f.origin;
  context.testFetch = f.realFetch;
  const result = await vm.runInContext(`RootarkZk1LegacyProtectedCopy.copyLegacyIntoProtectedCiphertext({
    legacy: { name: "report.txt", folderId: "" },
    metadata: { ...metadata },
    signer: { signerKey, scope: { ...scope }, deviceId: "trusted-0",
      manifestRevision: 2, manifestDigest: digest, epoch: metadata.epoch,
      nowSeconds: 1400 },
    cek, origin, fetchImpl: testFetch,
  })`, context);
  assert.equal(result.revision, 1);
  assert.equal(result.protectedCiphertextLocallyVerified, true);
  assert.equal(result.canDeleteLegacy, false);
});

test("changed legacy source, lost PUT ACK and corrupted read-back fail closed without deleting original data", async (t) => {
  for (const scenario of ["source-changed", "ack-lost", "readback-corrupted"]) {
    const f = await fixture(t);
    let sourceSeen = 0;
    let putSeen = 0;
    const guardedFetch = async (url, options) => {
      if (url.includes("/files/")) {
        sourceSeen++;
        if (scenario === "source-changed" && sourceSeen === 2) {
          f.setSource(Buffer.from("Legacy source changed during migration."));
        }
      }
      const response = await f.realFetch(url, options);
      if (url.endsWith("/content/put")) {
        putSeen++;
        if (scenario === "ack-lost") throw new Error("simulated lost response after PUT");
      }
      if (url.endsWith("/content/read") && scenario === "readback-corrupted") {
        const body = await response.json();
        body.ciphertextBase64 = b64(crypto.randomBytes(96));
        return new Response(JSON.stringify(body), { status: 200,
          headers: { "content-type": "application/json" } });
      }
      return response;
    };
    await assert.rejects(migrate.copyLegacyIntoProtectedCiphertext({
      legacy: { name: "report.txt", folderId: "" },
      metadata: f.metadata, signer: f.context, cek: f.cek,
      origin: f.origin, fetchImpl: guardedFetch,
    }), /ZK_CLIENT_MIGRATION_UNVERIFIED/, scenario);
    assert.equal(putSeen, 1, "uncertain PUT acknowledgement must never cause a second write");
    const source = await f.realFetch("/files/report.txt", { method: "GET" });
    assert.equal(source.status, 200);
    assert.ok((await source.arrayBuffer()).byteLength > 0,
      "legacy source remains despite incomplete protected migration");
    assert.equal(f.store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_object").get().n, 1,
      "partial migration never destroys newly written ciphertext; can be inspected later");
  }
});
