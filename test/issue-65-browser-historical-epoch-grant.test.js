"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { webcrypto } = crypto;
const z = require("../src/crypto/rootark-zk-1");
const browser = require("../public/client/rootark-zk1-browser-opaque-catalog-commit");

const b64 = (v) => Buffer.from(v).toString("base64url");
const hash = (v) => crypto.createHash("sha256").update(v).digest();
const raw = (key) => key.export({ type: "spki", format: "der" }).subarray(-32);
const GRANT_DOMAIN = Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0");
const EPOCH_DOMAIN = Buffer.from("Root.ark/zk-1/browser-owner-epoch-head/v1\0");
const EPOCH_HASH_DOMAIN = Buffer.from("Root.ark/zk-1/browser-owner-epoch-head-hash/v1\0");
const WITNESS_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0");
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const GRANT = ["schema", ...SCOPE, "device_id", "authorization_key_id",
  "authorization_public_key", "manifest_revision", "manifest_digest",
  "current_epoch", "enrolled_epoch", "revoked_at_epoch"];
const EPOCH = ["schema", ...SCOPE, "revision", "manifestDigest", "epoch", "previousDigest"];
const asKey = (nodeKey, purpose) => webcrypto.subtle.importKey(
  purpose === "sign" ? "pkcs8" : "raw",
  purpose === "sign" ? nodeKey.export({ type: "pkcs8", format: "der" }) : raw(nodeKey),
  "Ed25519", purpose !== "sign", [purpose]);

async function scenario() {
  const owner = crypto.generateKeyPairSync("ed25519");
  const witness = crypto.generateKeyPairSync("ed25519");
  const current = crypto.generateKeyPairSync("ed25519");
  const legacy = crypto.generateKeyPairSync("ed25519");
  const cas = crypto.generateKeyPairSync("ed25519");
  const scopeBytes = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("rootark-fixture"), keyring_id: crypto.randomBytes(16) };
  const scope = Object.fromEntries(SCOPE.map((key) => [key, b64(scopeBytes[key])]));
  const genesisDigest = crypto.randomBytes(32), currentDigest = crypto.randomBytes(32);
  const ownerSignedGrant = (key, deviceId, revision, epoch, digest, revoked = null) => {
    const data = { schema: "rootark-zk1-browser-owner-device-grant/v1", ...scope,
      device_id: deviceId, authorization_key_id: b64(crypto.randomBytes(16)),
      authorization_public_key: b64(raw(key.publicKey)),
      manifest_revision: revision, manifest_digest: b64(digest),
      current_epoch: epoch, enrolled_epoch: 1, revoked_at_epoch: revoked };
    return { ...data, signature: b64(crypto.sign(null, Buffer.concat([
      GRANT_DOMAIN, Buffer.from(JSON.stringify(Object.fromEntries(
        GRANT.map((name) => [name, data[name]]))))]), owner.privateKey)) };
  };
  let predecessor = null;
  const ownerEpochs = [];
  for (const [index, digest] of [genesisDigest, currentDigest].entries()) {
    const body = { schema: "rootark-zk1-browser-owner-epoch-head/v1", ...scope,
      revision: index + 1, manifestDigest: b64(digest),
      epoch: index + 1, previousDigest: predecessor };
    const payload = Buffer.from(JSON.stringify(Object.fromEntries(EPOCH.map(
      (field) => [field, body[field]]))));
    const signature = crypto.sign(null, Buffer.concat([EPOCH_DOMAIN, payload]),
      owner.privateKey);
    predecessor = b64(hash(Buffer.concat([EPOCH_HASH_DOMAIN, payload, signature])));
    ownerEpochs.push({ ...body, signature: b64(signature) });
  }
  const oldGrant = ownerSignedGrant(legacy, "revoked-after-epoch-1", 1, 1, genesisDigest);
  const newGrant = ownerSignedGrant(current, "current-device", 2, 2, currentDigest);
  const witnessId = crypto.randomBytes(16);
  const witnessProbe = async ({ nonce }) => {
    const stmt = { type: "rootark-recovery-witness-head/v1", witness_key_id: witnessId,
      ...scopeBytes, current_revision: 2, current_manifest_digest: currentDigest,
      witness_sequence: 2, nonce: Buffer.from(nonce), observed_at: 1100,
      status: "committed", pending_reservation_id: null };
    return z.encodeDeterministic({ ...stmt, signature: crypto.sign(null,
      Buffer.concat([WITNESS_DOMAIN, Buffer.from(await z.encodeDeterministic(stmt))]),
      witness.privateKey) });
  };
  const opts = { origin: "http://127.0.0.1:8801/",
    fetchImpl: async () => { throw Error("NO NETWORK WRITES"); },
    ownerPublicKey: await asKey(owner.publicKey, "verify"),
    pinnedOwnerKeyHash: hash(raw(owner.publicKey)),
    pinnedOwnerHead: { revision: 2, digest: currentDigest, epoch: 2 },
    signedDeviceGrant: newGrant, devicePublicKey: await asKey(current.publicKey, "verify"),
    devicePrivateKey: await asKey(current.privateKey, "sign"),
    signerGrants: [newGrant], ownerWitnessPublicKey: await asKey(witness.publicKey, "verify"),
    ownerWitnessKeyId: witnessId, ownerWitnessProbe: witnessProbe,
    catalogAuthorityPublicKey: await asKey(cas.publicKey, "verify"),
    catalogProbe: async () => { throw Error("NO CAS TEST"); },
    minimumCatalogHead: { sequence: 0, digest: Buffer.alloc(32) },
    csrfToken: () => "test-csrf", isSessionCurrent: () => true,
    assertCurrent: async () => {}, nowSeconds: () => 1100,
    journalStore: { async write() {}, async read() {}, async remove() {} },
    historicalOwnerEpochHistory: { heads: ownerEpochs, grants: [oldGrant] } };
  return { opts, oldGrant, ownerEpochs, oldPrivateKey: legacy.privateKey,
    ownerPrivateKey: owner.privateKey, genesisDigest, currentDigest };
}

test("historical epoch grant: old signer authenticates only its owner-signed historical epoch", async () => {
  const state = await scenario();
  const writer = browser.createClient(state.opts);
  const key = await writer.verifyHistoricalSigner("revoked-after-epoch-1", 1, 1,
    state.genesisDigest);
  assert.equal(await webcrypto.subtle.verify("Ed25519", key,
    crypto.sign(null, Buffer.from("historical"), state.oldPrivateKey),
    Buffer.from("historical")), true, "historical signer key must be exact owner-authorized key");
  assert.equal(await webcrypto.subtle.verify("Ed25519", key,
    crypto.randomBytes(64), Buffer.from("historical")), false);
  await assert.rejects(writer.verifyAuthorizedSigner("revoked-after-epoch-1", 1),
    /ZK_BROWSER_CATALOG_UNVERIFIED/,
  "historic credential never becomes a current signer/PUT capability");
  await assert.rejects(writer.verifyHistoricalSigner("revoked-after-epoch-1", 2, 2,
    state.currentDigest), /ZK_BROWSER_CATALOG_UNVERIFIED/,
  "old device has no owner authorization to attest new epoch");
});

test("historical epoch chain rejects forged owner grant, disconnected chain, wrong head and 129-entry rollover", async () => {
  const state = await scenario();
  const forged = { ...state.oldGrant, signature: b64(crypto.randomBytes(64)) };
  await assert.rejects(browser.createClient({ ...state.opts,
    historicalOwnerEpochHistory: { heads: state.ownerEpochs, grants: [forged] } })
    .verifyHistoricalSigner("revoked-after-epoch-1", 1, 1, state.genesisDigest),
  /ZK_BROWSER_CATALOG_UNVERIFIED/);
  const missing = { ...state.opts, historicalOwnerEpochHistory: {
    heads: state.ownerEpochs.slice(1), grants: [state.oldGrant] } };
  await assert.rejects(browser.createClient(missing)
    .verifyHistoricalSigner("revoked-after-epoch-1", 1, 1, state.genesisDigest),
  /ZK_BROWSER_CATALOG_UNVERIFIED/);
  await assert.rejects(browser.createClient({ ...state.opts,
    historicalOwnerEpochHistory: { heads: state.ownerEpochs, grants: [] } })
    .verifyHistoricalSigner("revoked-after-epoch-1", 1, 1, state.genesisDigest),
  /ZK_BROWSER_CATALOG_UNVERIFIED/, "missing signed historical device grant is UNKNOWN");
  const altered = { ...state.opts, historicalOwnerEpochHistory: {
    heads: [...state.ownerEpochs.slice(0, 1), {
      ...state.ownerEpochs[1], manifestDigest: b64(crypto.randomBytes(32)) }],
    grants: [state.oldGrant] } };
  await assert.rejects(browser.createClient(altered)
    .verifyHistoricalSigner("revoked-after-epoch-1", 1, 1, state.genesisDigest),
  /ZK_BROWSER_CATALOG_UNVERIFIED/);
  assert.throws(() => browser.createClient({ ...state.opts,
    historicalOwnerEpochHistory: { heads: Array(129).fill(state.ownerEpochs[0]),
      grants: [state.oldGrant] } }), /ZK_BROWSER_CATALOG_UNVERIFIED/,
  "unproved >128 rollover must be UNKNOWN/deny, not silently restart the chain");
});
