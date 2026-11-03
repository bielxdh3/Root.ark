"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const nodeCrypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const browser = require("../public/client/rootark-zk1-browser-opaque-catalog-commit");

const crypto = nodeCrypto.webcrypto;
const b64 = (value) => Buffer.from(value).toString("base64url");
const rawPublic = (key) => Buffer.from(key.export({ type: "spki", format: "der" })).subarray(-32);
const digest = (value) => nodeCrypto.createHash("sha256").update(value).digest();
const WITNESS = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0");
const CAS = Buffer.from("Root.ark/zk-1/opaque-catalog-cas/v1\0");
const GRANT = Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0");
const GRANT_FIELDS = ["schema", "account_id", "compartment_id", "keyring_id", "device_id",
  "authorization_key_id", "authorization_public_key", "manifest_revision", "manifest_digest",
  "current_epoch", "enrolled_epoch", "revoked_at_epoch"];

async function importEd25519(key, type) {
  return crypto.subtle.importKey(type === "private" ? "pkcs8" : "raw",
    type === "private" ? key.export({ type: "pkcs8", format: "der" }) : rawPublic(key),
    "Ed25519", type !== "private", [type === "private" ? "sign" : "verify"]);
}

async function fixture(nowSeconds) {
  const owner = nodeCrypto.generateKeyPairSync("ed25519");
  const device = nodeCrypto.generateKeyPairSync("ed25519");
  const witness = nodeCrypto.generateKeyPairSync("ed25519");
  const authority = nodeCrypto.generateKeyPairSync("ed25519");
  const witnessId = nodeCrypto.randomBytes(16);
  const pinnedDigest = nodeCrypto.randomBytes(32);
  const deviceId = "signed-present-day-device";
  const scope = { account_id: nodeCrypto.randomBytes(16),
    compartment_id: Buffer.from("vault"), keyring_id: nodeCrypto.randomBytes(16) };
  const grantBody = { schema: "rootark-zk1-browser-owner-device-grant/v1",
    account_id: b64(scope.account_id), compartment_id: b64(scope.compartment_id),
    keyring_id: b64(scope.keyring_id), device_id: deviceId,
    authorization_key_id: b64(nodeCrypto.randomBytes(16)),
    authorization_public_key: b64(rawPublic(device.publicKey)),
    manifest_revision: 1, manifest_digest: b64(pinnedDigest), current_epoch: 1,
    enrolled_epoch: 1, revoked_at_epoch: null };
  const signedGrant = { ...grantBody, signature: b64(nodeCrypto.sign(null,
    Buffer.concat([GRANT, Buffer.from(JSON.stringify(Object.fromEntries(
      GRANT_FIELDS.map((name) => [name, grantBody[name]]))))]), owner.privateKey)) };

  async function signedWitness(nonce, observedAt = nowSeconds) {
    const stmt = { type: "rootark-recovery-witness-head/v1", witness_key_id: witnessId,
      ...scope, current_revision: 1, current_manifest_digest: pinnedDigest,
      witness_sequence: 1, nonce: Buffer.from(nonce), observed_at: observedAt,
      status: "committed", pending_reservation_id: null };
    const signature = nodeCrypto.sign(null, Buffer.concat([
      WITNESS, Buffer.from(await z.encodeDeterministic(stmt)),
    ]), witness.privateKey);
    return z.encodeDeterministic({ ...stmt, signature });
  }
  async function signedCas(nonce, observedAt = nowSeconds) {
    const stmt = { type: "rootark-zk1-opaque-catalog-cas/v1", ...scope,
      sequence: 0, digest: Buffer.alloc(32), nonce: Buffer.from(nonce),
      observed_at: observedAt };
    const signature = nodeCrypto.sign(null, Buffer.concat([
      CAS, Buffer.from(await z.encodeDeterministic(stmt)),
    ]), authority.privateKey);
    return z.encodeDeterministic({ ...stmt, signature });
  }
  const options = {
    origin: "http://127.0.0.1/",
    fetchImpl: async () => { throw Error("unexpected HTTP request"); },
    ownerPublicKey: await importEd25519(owner.publicKey, "public"),
    pinnedOwnerKeyHash: digest(rawPublic(owner.publicKey)),
    pinnedOwnerHead: { revision: 1, digest: pinnedDigest, epoch: 1 },
    signedDeviceGrant: signedGrant,
    devicePublicKey: await importEd25519(device.publicKey, "public"),
    devicePrivateKey: await importEd25519(device.privateKey, "private"),
    signerGrants: [signedGrant],
    ownerWitnessPublicKey: await importEd25519(witness.publicKey, "public"),
    ownerWitnessKeyId: witnessId,
    ownerWitnessProbe: ({ nonce }) => signedWitness(nonce),
    catalogAuthorityPublicKey: await importEd25519(authority.publicKey, "public"),
    catalogProbe: ({ nonce }) => signedCas(nonce),
    minimumCatalogHead: { sequence: 0, digest: Buffer.alloc(32) },
    csrfToken: () => "unused", isSessionCurrent: () => true,
    assertCurrent: async () => {}, nowSeconds: () => nowSeconds,
    journalStore: { write: async () => {}, read: async () => null, remove: async () => {} },
  };
  return { deviceId, pinnedDigest, options, signedWitness, signedCas };
}

test("real Ed25519 witness and CAS observed_at at today's Unix seconds allow owner and historical signer", async () => {
  const now = Math.floor(Date.now() / 1000);
  assert.ok(now > 8192 && Number.isSafeInteger(now));
  const f = await fixture(now);
  const client = browser.createClient(f.options);
  const signer = await client.verifyHistoricalSigner(f.deviceId, 1, 1, f.pinnedDigest);
  assert.equal(signer.type, "public");
  const catalog = await client.readAll();
  assert.equal(catalog.head.sequence, 0);
  assert.deepEqual(catalog.rows, []);
});

test("CBOR uint accepts the largest safe integer independently of probe byte budget", async () => {
  const f = await fixture(Number.MAX_SAFE_INTEGER);
  const signer = await browser.createClient(f.options)
    .verifyHistoricalSigner(f.deviceId, 1, 1, f.pinnedDigest);
  assert.equal(signer.type, "public");
});

test("negative, unsafe, malformed and oversized CBOR still fail closed before authorization", async () => {
  const f = await fixture(Math.floor(Date.now() / 1000));
  const tryWitness = (ownerWitnessProbe) => browser.createClient({
    ...f.options, ownerWitnessProbe,
  }).verifyHistoricalSigner(f.deviceId, 1, 1, f.pinnedDigest);
  await assert.rejects(tryWitness(({ nonce }) => f.signedWitness(nonce, f.options.nowSeconds() - 31)),
    /ZK_BROWSER_CATALOG_UNVERIFIED/, "expired but authentically signed witness must fail");
  await assert.rejects(tryWitness(async () => Uint8Array.of(0x20)),
    /ZK_BROWSER_CATALOG_UNVERIFIED/, "negative CBOR integer must fail");
  await assert.rejects(tryWitness(async () => Uint8Array.of(0x1b, 0x00, 0x20, 0, 0, 0, 0, 0, 0)),
    /ZK_BROWSER_CATALOG_UNVERIFIED/, "integer outside JS safe range must fail");
  await assert.rejects(tryWitness(async () => Uint8Array.of(0x99, 0x40, 0x01)),
    /ZK_BROWSER_CATALOG_UNVERIFIED/, "array declaring 16385 elements must fail without allocation");
  await assert.rejects(tryWitness(async () => new Uint8Array(8193)),
    /ZK_BROWSER_CATALOG_UNVERIFIED/, "witness bytes beyond 8192 must fail before decode");
  await assert.rejects(tryWitness(async () => Uint8Array.of(0x5a, 0, 0, 0x20, 0x01)),
    /ZK_BROWSER_CATALOG_UNVERIFIED/, "CBOR byte-string claiming 8193 bytes cannot overread");
  await assert.rejects(tryWitness(async () => Uint8Array.of(0x9f)),
    /ZK_BROWSER_CATALOG_UNVERIFIED/, "indefinite CBOR must remain forbidden");
});
