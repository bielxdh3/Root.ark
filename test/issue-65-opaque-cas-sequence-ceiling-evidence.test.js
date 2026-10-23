"use strict";

// Executable v1 boundary evidence. A future checkpoint protocol must replace
// these guards as one coherent migration, retaining the absolute sequence and
// authenticated history. Do not increase individual ceilings in isolation.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const z = require("../src/crypto/rootark-zk-1");
const { catalogHeadDigest } = require("../src/services/zk1OpaqueCatalog");
const { Zk1OpaqueCatalogIndependentFloorLedger } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");
const { createZk1OpaqueCatalogCasHttpsClient } =
  require("../src/services/zk1OpaqueCatalogCasHttpsClient");

const HEAD_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0");

test("signed opaque catalog v1 ceiling: 129 refused, immutable floor retains absolute sequence across restart", async (t) => {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-opaque-sequence-ceiling-"));
  if (process.platform !== "win32") fs.chmodSync(folder, 0o700);
  let floor;
  t.after(() => {
    if (floor?.db?.open) floor.db.close();
    fs.rmSync(folder, { recursive: true, force: true, maxRetries: 5 });
  });

  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("ceiling"), keyring_id: crypto.randomBytes(16) };
  const floorSigner = crypto.generateKeyPairSync("ed25519");
  const casSigner = crypto.generateKeyPairSync("ed25519");
  const deviceSigner = crypto.generateKeyPairSync("ed25519");
  const dbFile = path.join(folder, "floor.sqlite");
  const options = { trustedScope: scope,
    signingPrivateKey: floorSigner.privateKey,
    casSignerPublicKey: casSigner.publicKey,
    catalogSignerPublicKey: deviceSigner.publicKey };
  floor = new Zk1OpaqueCatalogIndependentFloorLedger(dbFile,
    { ...options, bootstrapNew: true });

  const build = async (sequence, previousDigest) => {
    const header = { type: "rootark-zk1-opaque-catalog/v1", ...scope,
      sequence, previous_digest: previousDigest, manifest_revision: 1,
      manifest_digest: crypto.randomBytes(32), epoch: 1,
      signer_device_id: "device", total_count: 0, page_digests: [],
      issued_at: Math.floor(Date.now() / 1000) };
    const headBytes = Buffer.from(await z.encodeDeterministic(header));
    const headSignature = crypto.sign(null,
      Buffer.concat([HEAD_DOMAIN, headBytes]), deviceSigner.privateKey);
    assert.equal(crypto.verify(null, Buffer.concat([HEAD_DOMAIN, headBytes]),
      deviceSigner.publicKey, headSignature), true);
    const nextDigest = catalogHeadDigest(headBytes, headSignature);
    return { scope, expectedSequence: sequence - 1, expectedDigest: previousDigest,
      nextSequence: sequence, nextDigest, headBytes, headSignature,
      nonce: crypto.randomBytes(32) };
  };

  // A correctly signed and hashed 129th header is rejected by the floor's
  // sequence contract, before any attempt to change durable state.
  await assert.rejects(floor.compareAndSwap(await build(129, crypto.randomBytes(32))),
    { code: "ZK_OPAQUE_FLOOR_UNAVAILABLE" });
  assert.deepEqual(floor.inspect(), { sequence: 0, digest: Buffer.alloc(32) });

  const initial = await build(1, Buffer.alloc(32));
  const firstReceipt = await floor.compareAndSwap(initial);
  const signedReceipt = await z.decodeDeterministic(firstReceipt);
  assert.equal(signedReceipt.sequence, 1);
  assert.deepEqual(Buffer.from(signedReceipt.digest), initial.nextDigest);
  await assert.rejects(floor.compareAndSwap(await build(1, Buffer.alloc(32))),
    { code: "ZK_OPAQUE_FLOOR_CONFLICT" }, "genesis must not restart at sequence 1");

  floor.db.close();
  floor = new Zk1OpaqueCatalogIndependentFloorLedger(dbFile,
    { ...options, bootstrapNew: false });
  assert.deepEqual(floor.inspect(), { sequence: 1, digest: initial.nextDigest });
  await assert.rejects(floor.compareAndSwap(await build(129, initial.nextDigest)),
    { code: "ZK_OPAQUE_FLOOR_UNAVAILABLE" });
  assert.deepEqual(floor.inspect(), { sequence: 1, digest: initial.nextDigest });

  // The HTTPS client refuses both requests before network I/O. An isolated
  // change in server SQLite would therefore strand upgraded remote heads.
  const client = createZk1OpaqueCatalogCasHttpsClient({
    endpoint: "https://127.0.0.1:65534/", ca: "fixture", clientKey: "fixture",
    clientCert: "fixture", serverFingerprint256: "00:".repeat(31) + "00",
    authorityPublicKey: casSigner.publicKey,
  });
  await assert.rejects(client.fetchSnapshot({ scope, sequence: 129,
    nonce: crypto.randomBytes(32) }),
  { code: "ZK_OPAQUE_CAS_TRANSPORT_UNAVAILABLE" });
  await assert.rejects(client.compareAndSwap({
    scope, expectedSequence: 128, expectedDigest: initial.nextDigest,
    nextSequence: 129, nextDigest: crypto.randomBytes(32),
    nonce: crypto.randomBytes(32), headBytes: Buffer.from([1]),
    headSignature: Buffer.alloc(64), pageBodies: [],
  }), { code: "ZK_OPAQUE_CAS_TRANSPORT_UNAVAILABLE" });
});
