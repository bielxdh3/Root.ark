"use strict";

// Regression for the REAL browser catalog verifier (UMD's Node/WebCrypto path).
// Only IndexedDB and the remote HTTP transport are fixture boundaries. The
// owner history, signed grants/checkpoints, and catalog/CAS proofs are genuine.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const recovery = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const history = require("../src/crypto/rootark-zk-recovery-history-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const checkpoint = require("../public/client/rootark-zk1-owner-signed-checkpoint");
const floor = require("../public/client/rootark-zk1-normal-browser-trust-floor");
const catalog = require("../public/client/rootark-zk1-browser-catalog");
const { catalogHeaderMessage, catalogHeadDigest, catalogPageDigest } =
  require("../src/services/zk1OpaqueCatalog");

const { subtle } = crypto.webcrypto;
const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const rawKey = (key) => key.export({ format: "der", type: "spki" }).subarray(-32);
const GRANT = ["schema", "account_id", "compartment_id", "keyring_id",
  "device_id", "authorization_key_id", "authorization_public_key",
  "manifest_revision", "manifest_digest", "current_epoch", "enrolled_epoch", "revoked_at_epoch"];
const DOMAIN_GRANT = Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0");
const DOMAIN_CAS = Buffer.from("Root.ark/zk-1/opaque-catalog-cas/v1\0");
const DOMAIN_OP = Buffer.from("Root.ark/zk-1/protected-object-operation/v1\0");

// Small asynchronous IDB transaction fixture; it does not emulate owner trust.
// The real production owner floor and catalog both exercise this same store.
function memoryIndexedDB() {
  const databases = new Map();
  return { open(name) {
    const request = {};
    queueMicrotask(() => {
      const fresh = !databases.has(name);
      if (fresh) databases.set(name, new Map());
      const tables = databases.get(name);
      const database = {
        objectStoreNames: { contains: (table) => tables.has(table) },
        createObjectStore(table) { if (tables.has(table)) throw Error("duplicate table"); tables.set(table, new Map()); },
        transaction(table) {
          if (!tables.has(table)) throw Error("missing table");
          let aborted = false;
          const tx = {
            objectStore() { return {
              get(key) {
                const result = {};
                queueMicrotask(() => {
                  if (aborted) return;
                  result.result = tables.get(table).get(key);
                  result.onsuccess?.();
                  queueMicrotask(() => { if (!aborted) tx.oncomplete?.(); });
                });
                return result;
              },
              put(value, key) { tables.get(table).set(key, value); },
            }; },
            abort() { aborted = true; queueMicrotask(() => tx.onabort?.()); },
          };
          return tx;
        },
        close() {},
      };
      request.result = database;
      if (fresh) request.onupgradeneeded?.();
      queueMicrotask(() => request.onsuccess?.());
    });
    return request;
  } };
}

async function browserKeys(keyPair) {
  return {
    publicKey: await subtle.importKey("raw", rawKey(keyPair.publicKey), "Ed25519", true, ["verify"]),
    privateKey: await subtle.importKey("pkcs8", keyPair.privateKey.export({
      format: "der", type: "pkcs8" }), "Ed25519", false, ["sign"]),
  };
}

test("current B reads A's pre-revocation signed catalog, but revoked A and forged history never authorize access", async (t) => {
  const previousIndexedDB = globalThis.indexedDB;
  const indexedDBImpl = memoryIndexedDB();
  globalThis.indexedDB = indexedDBImpl;
  t.after(() => { if (previousIndexedDB === undefined) delete globalThis.indexedDB;
    else globalThis.indexedDB = previousIndexedDB; });

  // Real V2 owner-device history, not an arbitrary test-supplied roster.
  const state = await fixtures.createInitialState(2);
  const atEpochOne = state.headManifest;
  const A = atEpochOne.devices.find((device) => device.device_id === "trusted-0");
  const B = atEpochOne.devices.find((device) => device.device_id === "trusted-1");
  const aSigner = state.actors.get(Buffer.from(A.authorization_key_id).toString("hex"));
  const bSigner = state.actors.get(Buffer.from(B.authorization_key_id).toString("hex"));
  const oldDigest = await recovery.recoveryManifestDigestV2(atEpochOne);
  await fixtures.appendDeviceRevocation(state, A.device_id, undefined, B.device_id);
  assert.equal(await history.isVerifiedTrustedDeviceRecoveryHistoryV2(state.verifiedHistory), true);
  const atEpochTwo = state.headManifest;
  const currentDigest = await recovery.recoveryManifestDigestV2(atEpochTwo);
  assert.equal(atEpochTwo.current_epoch, 2);
  assert.equal(atEpochTwo.devices.find((d) => d.device_id === A.device_id).revoked_at_epoch, 2);
  assert.equal(atEpochTwo.devices.find((d) => d.device_id === B.device_id).revoked_at_epoch, null);

  const owner = crypto.generateKeyPairSync("ed25519");
  const ownerKeys = await browserKeys(owner);
  const bKeys = await browserKeys({ publicKey: crypto.createPublicKey(bSigner), privateKey: bSigner });
  const aKeys = await browserKeys({ publicKey: crypto.createPublicKey(aSigner), privateKey: aSigner });
  const scope = Object.fromEntries(Object.entries(state.scope).map(([key, value]) => [key, b64(value)]));
  const currentHead = { revision: atEpochTwo.revision, digest: currentDigest, epoch: 2 };
  const ownerSpki = owner.publicKey.export({ format: "der", type: "spki" });
  const now = 2000;
  async function signedGrant(device, revision, digest, epoch, revokedAt) {
    const fields = { schema: "rootark-zk1-browser-owner-device-grant/v1", ...scope,
      device_id: device.device_id, authorization_key_id: b64(device.authorization_key_id),
      authorization_public_key: b64(device.authorization_public_key),
      manifest_revision: revision, manifest_digest: b64(digest), current_epoch: epoch,
      enrolled_epoch: device.enrolled_epoch, revoked_at_epoch: revokedAt };
    const body = Object.fromEntries(GRANT.map((key) => [key, fields[key]]));
    const signature = crypto.sign(null, Buffer.concat([DOMAIN_GRANT,
      Buffer.from(JSON.stringify(body))]), owner.privateKey);
    return { ...body, signature: b64(signature) };
  }
  const priorA = await signedGrant(A, atEpochOne.revision, oldDigest, 1, null);
  const activeB = await signedGrant(B, atEpochTwo.revision, currentDigest, 2, null);
  const revokedA = await signedGrant(A, atEpochTwo.revision, currentDigest, 2, 2);

  // Real owner-signed checkpoint chain connects the historical manifest digest
  // to the independently pinned current owner head; no patched trust floor.
  const ownerSignerKeyId = crypto.randomBytes(16);
  const initialCheckpoint = await checkpoint.signOwnerCheckpoint({ scope,
    signerKey: ownerKeys.privateKey, signerPublicKey: ownerKeys.publicKey,
    signerKeyId: ownerSignerKeyId, deviceId: "offline-owner", revision: atEpochOne.revision,
    manifestDigest: oldDigest, issuedAt: now - 10, previous: null });
  const previousOwnerHistoryProof = await checkpoint.verifyOwnerCheckpoint({
    checkpoint: initialCheckpoint, scope, signerPublicKey: ownerKeys.publicKey,
    signerKeyId: ownerSignerKeyId, previous: null });
  const ownerHistoryCheckpoint = await checkpoint.signOwnerCheckpoint({ scope,
    signerKey: ownerKeys.privateKey, signerPublicKey: ownerKeys.publicKey,
    signerKeyId: ownerSignerKeyId, deviceId: "offline-owner", revision: atEpochTwo.revision,
    manifestDigest: currentDigest, issuedAt: now, previous: previousOwnerHistoryProof });
  const trust = { ownerPublicKey: ownerKeys.publicKey,
    independentOwnerSpkiSha256: crypto.createHash("sha256").update(ownerSpki).digest(),
    pinnedCurrentHead: currentHead, signedDeviceGrant: activeB,
    ownerHistoryCheckpoint, previousOwnerHistoryProof };
  await floor.provisionOffline({ ...trust });

  const cas = crypto.generateKeyPairSync("ed25519");
  const authorityKeys = await browserKeys(cas);
  const entry = { object_id: b64(crypto.randomBytes(16)), revision: 1, epoch: 1,
    ciphertext_digest: crypto.randomBytes(32), metadata_ciphertext: crypto.randomBytes(284) };
  const header = { type: "rootark-zk1-opaque-catalog/v1", ...state.scope,
    sequence: 1, previous_digest: Buffer.alloc(32), manifest_revision: atEpochOne.revision,
    manifest_digest: oldDigest, epoch: 1, signer_device_id: A.device_id,
    total_count: 1, page_digests: [await catalogPageDigest([entry])], issued_at: now - 10 };
  const headerBytes = Buffer.from(await z.encodeDeterministic(header));
  const genuineSignature = crypto.sign(null, await catalogHeaderMessage(header), aSigner);
  // Positive control: a CURRENT B-signed head must be readable through the
  // exact same production browser route and trust floor. Without this, a
  // malformed fixture could masquerade as a historical-revocation RED.
  const currentHeader = { ...header, manifest_revision: atEpochTwo.revision,
    manifest_digest: currentDigest, epoch: 2, signer_device_id: B.device_id,
    issued_at: now };
  const currentSignature = crypto.sign(null, await catalogHeaderMessage(currentHeader), bSigner);

  async function attempt({ signerGrant, deviceKeys, catalogHeader = header,
    signature = genuineSignature, catalogIndexedDBImpl = indexedDBImpl,
    trustPatch = {}, onFetch = () => {} }) {
    const signedBytes = catalogHeader === header ? headerBytes
      : Buffer.from(await z.encodeDeterministic(catalogHeader));
    const digest = catalogHeadDigest(signedBytes, signature);
    let fetched = 0;
    let receiptSigner = cas.privateKey;
    const fetchImpl = async (url, request) => {
      fetched++;
      onFetch({ args, useReceiptSigner: (key) => { receiptSigner = key; } });
      assert.equal(new URL(url).pathname, "/zk-1/v1/catalog/read");
      const body = JSON.parse(request.body);
      assert.equal(body.authorization.device_id, signerGrant === revokedA ? A.device_id : B.device_id);
      const unsignedOperation = { ...body.authorization };
      for (const key of ["account_id", "compartment_id", "keyring_id", "manifest_digest",
        "nonce", "ciphertext_digest"]) unsignedOperation[key] = Buffer.from(unsignedOperation[key], "base64url");
      const operationSignature = Buffer.from(body.signatureBase64, "base64url");
      assert.equal(crypto.verify(null, Buffer.concat([DOMAIN_OP,
        Buffer.from(await z.encodeDeterministic(unsignedOperation))]),
      signerGrant === revokedA ? aSigner : bSigner, operationSignature), true,
      "actual browser must sign fresh IO with the current authorized device");
      const fields = { type: "rootark-zk1-opaque-catalog-cas/v1", ...state.scope,
        sequence: 1, digest, nonce: Buffer.from(body.authorization.nonce, "base64url"),
        observed_at: now };
      const receipt = { ...fields, signature: crypto.sign(null,
        Buffer.concat([DOMAIN_CAS, Buffer.from(await z.encodeDeterministic(fields))]),
        receiptSigner) };
      const response = { sequence: 1, totalCount: 1, pageIndex: 0, pageCount: 1,
        catalogDigest: b64(digest), headerBase64: b64(signedBytes),
        headerSignatureBase64: b64(signature), entries: [{ objectId: entry.object_id,
          revision: 1, epoch: 1, ciphertextDigestBase64: b64(entry.ciphertext_digest),
          metadataCiphertextBase64: b64(entry.metadata_ciphertext) }],
        authorityProofBase64: b64(await z.encodeDeterministic(receipt)) };
      return new Response(JSON.stringify(response), { status: 200,
        headers: { "Content-Type": "application/json" } });
    };
    const args = { trust: { ...trust,
      signedDeviceGrant: signerGrant === revokedA ? revokedA : activeB,
      ...trustPatch },
    signerGrant, devicePrivateKey: deviceKeys.privateKey,
    catalogAuthorityKey: authorityKeys.publicKey,
    independentAuthoritySpkiHash: crypto.createHash("sha256").update(
      cas.publicKey.export({ format: "der", type: "spki" })).digest(),
    pinnedCatalogHead: { sequence: 1, digest: b64(digest) },
    origin: "http://127.0.0.1:8765/", fetchImpl, assertLive: () => {},
    indexedDBImpl: catalogIndexedDBImpl, nowSeconds: now };
    return { read: () => catalog.openCatalog(args), fetched: () => fetched };
  }

  await t.test("a revoked at epoch 2 cannot authorize fresh read IO", async () => {
    const denied = await attempt({ signerGrant: revokedA, deviceKeys: aKeys });
    await assert.rejects(denied.read(), /ZK_BROWSER_CATALOG_UNVERIFIED/);
    assert.equal(denied.fetched(), 0, "revoked device must fail before any HTTP egress");
  });
  await t.test("forged historical A signature fails despite a genuine nonce-bound CAS proof", async () => {
    const outsider = crypto.generateKeyPairSync("ed25519");
    const forged = await attempt({ signerGrant: priorA, deviceKeys: bKeys,
      signature: crypto.sign(null, await catalogHeaderMessage(header), outsider.privateKey) });
    await assert.rejects(forged.read(), /ZK_BROWSER_CATALOG_UNVERIFIED/);
    assert.equal(forged.fetched(), 1,
      "negative assurance must reach signature verification, not fail on the old grant");
  });
  await t.test("owner-signed historical grant with unpinned manifest digest never reaches HTTP", async () => {
    const unpinned = await signedGrant(A, atEpochOne.revision, crypto.randomBytes(32), 1, null);
    const denied = await attempt({ signerGrant: unpinned, deviceKeys: bKeys });
    await assert.rejects(denied.read(), /ZK_BROWSER_CATALOG_UNVERIFIED/);
    assert.equal(denied.fetched(), 0,
      "an owner signature alone cannot replace independently checked historical manifest commitment");
  });
  await t.test("historical signer revoked by its claimed signing epoch is never accepted", async () => {
    const invalid = await signedGrant(A, atEpochOne.revision, oldDigest, 1, 1);
    const denied = await attempt({ signerGrant: invalid, deviceKeys: bKeys });
    await assert.rejects(denied.read(), /ZK_BROWSER_CATALOG_UNVERIFIED/);
    assert.equal(denied.fetched(), 0, "revocation at epoch1 invalidates epoch1 head authority");
  });
  await t.test("a historical digest cannot self-assert the current epoch", async () => {
    // The predecessor owner checkpoint binds revision/digest, not its epoch.
    // Even an owner-signed grant must not turn that incomplete evidence into
    // current-epoch signing power for a device that is now revoked.
    const inconsistent = await signedGrant(A, atEpochOne.revision, oldDigest, 2, null);
    const denied = await attempt({ signerGrant: inconsistent, deviceKeys: bKeys });
    await assert.rejects(denied.read(), /ZK_BROWSER_CATALOG_UNVERIFIED/);
    assert.equal(denied.fetched(), 0, "a prior checkpoint does not pin current-epoch authority");
  });
  await t.test("historical helper cannot authenticate a detached old checkpoint", async () => {
    await assert.rejects(floor.verifyHistoricalSignerGrant({ ...trust,
      ownerHistoryCheckpoint: null, historicalSignerGrant: priorA }),
    /ZK_NORMAL_BROWSER_LOCAL_FLOOR_UNVERIFIED/);
  });
  await t.test("an owner-signed foreign-scope history grant cannot authorize catalog read", async () => {
    const fields = { ...priorA, compartment_id: b64(Buffer.from("other-compartment")) };
    const grantBody = Object.fromEntries(GRANT.map((key) => [key, fields[key]]));
    const foreign = { ...grantBody, signature: b64(crypto.sign(null, Buffer.concat([
      DOMAIN_GRANT, Buffer.from(JSON.stringify(grantBody))]), owner.privateKey)) };
    const denied = await attempt({ signerGrant: foreign, deviceKeys: bKeys });
    await assert.rejects(denied.read(), /ZK_BROWSER_CATALOG_UNVERIFIED/);
    assert.equal(denied.fetched(), 0);
  });
  await t.test("a false independent owner pin cannot upgrade old signatures", async () => {
    const denied = await attempt({ signerGrant: priorA, deviceKeys: bKeys,
      trustPatch: { independentOwnerSpkiSha256: crypto.randomBytes(32) } });
    await assert.rejects(denied.read(), /ZK_BROWSER_CATALOG_UNVERIFIED/);
    assert.equal(denied.fetched(), 0);
  });
  await t.test("a mutable signer-grant caller cannot swap the verified historical key after fetch", async () => {
    const supplied = { ...priorA };
    const good = await attempt({ signerGrant: supplied, deviceKeys: bKeys,
      catalogIndexedDBImpl: memoryIndexedDB(),
      onFetch() { supplied.authorization_public_key = b64(crypto.randomBytes(32)); } });
    const opened = await good.read();
    assert.equal(good.fetched(), 1);
    assert.equal(opened.entries.length, 1);
  });
  await t.test("a mutable CAS key cannot replace the independently pinned signer mid-fetch", async () => {
    const attacker = crypto.generateKeyPairSync("ed25519");
    const attackerKeys = await browserKeys(attacker);
    const forged = await attempt({ signerGrant: priorA, deviceKeys: bKeys,
      catalogIndexedDBImpl: memoryIndexedDB(),
      onFetch({ args, useReceiptSigner }) {
        // Model an untrusted caller changing the input after the legitimate
        // authority key passed the initial independent SPKI hash check.
        args.catalogAuthorityKey = attackerKeys.publicKey;
        useReceiptSigner(attacker.privateKey);
      } });
    await assert.rejects(forged.read(), /ZK_BROWSER_CATALOG_UNVERIFIED/);
    assert.equal(forged.fetched(), 1,
      "the response must reach CAS signature verification, not fail on owner grants");
  });
  await t.test("B verifies A's authentic epoch-1 head with pinned owner history", async () => {
    const good = await attempt({ signerGrant: priorA, deviceKeys: bKeys });
    const opened = await good.read();
    assert.equal(good.fetched(), 1, "a valid historical head must reach the browser verifier");
    assert.equal(opened.sequence, 1);
    assert.equal(opened.entries.length, 1);
    assert.equal(opened.entries[0].objectId, entry.object_id);
  });
  await t.test("positive control: current B-signed head reads with the same browser trust floor", async () => {
    // Keep the test's *catalog* rollback floor independent of the historical
    // scenario. The owner checkpoint floor remains real and shared.
    const current = await attempt({ signerGrant: activeB, deviceKeys: bKeys,
      catalogHeader: currentHeader, signature: currentSignature,
      catalogIndexedDBImpl: memoryIndexedDB() });
    const opened = await current.read();
    assert.equal(current.fetched(), 1, "a valid current head must reach real HTTP verification");
    assert.equal(opened.sequence, 1);
    assert.equal(opened.entries.length, 1);
  });
});
