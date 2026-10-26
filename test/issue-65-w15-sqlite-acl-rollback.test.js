"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const z = require("../src/crypto/rootark-zk-1");
const { catalogHeadDigest } = require("../src/services/zk1OpaqueCatalog");
const { Zk1OpaqueCatalogIndependentFloorLedger } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");
const { OpaqueCheckpointV2Authority } =
  require("../src/services/zk1OpaqueCheckpointV2Remote");
const { ensureWindowsChunkUploadRoot } =
  require("../services/chunkUploadWindowsAcl");

function windowsPrivateFixture(t) {
  const dir = path.join(process.env.LOCALAPPDATA,
    `rootark-w15-private-${crypto.randomBytes(9).toString("hex")}`);
  assert.equal(fs.existsSync(dir), false);
  ensureWindowsChunkUploadRoot(dir);
  t.after(() => fs.rmSync(dir, { force: true, recursive: true, maxRetries: 6, retryDelay: 100 }));
  return dir;
}

function exposeToLocalUsers(dir) {
  execFileSync("icacls.exe", [dir, "/grant", "*S-1-5-32-545:(OI)(CI)(M)"], { windowsHide: true });
}

test("Windows independent floor rejects a local Users Modify directory before creating SQLite", (t) => {
  if (process.platform !== "win32") return t.skip("Native Windows ACL threat model");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-w15-floor-rollback-"));
  t.after(() => fs.rmSync(dir, { force: true, recursive: true, maxRetries: 6, retryDelay: 100 }));
  exposeToLocalUsers(dir);
  const dbPath = path.join(dir, "floor.sqlite");
  const signed = Array.from({ length: 3 }, () => crypto.generateKeyPairSync("ed25519"));
  assert.throws(() => new Zk1OpaqueCatalogIndependentFloorLedger(dbPath, {
    bootstrapNew: true, trustedScope: { account_id: crypto.randomBytes(16),
      compartment_id: Buffer.from("w15-floor-rollback"), keyring_id: crypto.randomBytes(16) },
    signingPrivateKey: signed[0].privateKey, casSignerPublicKey: signed[1].publicKey,
    catalogSignerPublicKey: signed[2].publicKey,
  }), /ZK_OPAQUE_FLOOR_UNAVAILABLE/);
  assert.equal(fs.existsSync(dbPath), false, "unsafe permissions must be denied before SQLite exists");
});

test("independent floor denies a valid signed rollback after local filesystem permissions become unsafe", async (t) => {
  const dir = process.platform === "win32" ? windowsPrivateFixture(t)
    : fs.mkdtempSync(path.join(os.tmpdir(), "zk65-w15-floor-posix-rollback-"));
  if (process.platform !== "win32") {
    fs.chmodSync(dir, 0o700);
    t.after(() => fs.rmSync(dir, { force: true, recursive: true, maxRetries: 6 }));
  }
  const dbPath = path.join(dir, "floor.sqlite");
  const backupPath = path.join(dir, "rollback.sqlite");
  const signed = Array.from({ length: 3 }, () => crypto.generateKeyPairSync("ed25519"));
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("w15-floor-rollback"), keyring_id: crypto.randomBytes(16) };
  const args = { trustedScope: scope, signingPrivateKey: signed[0].privateKey,
    casSignerPublicKey: signed[1].publicKey, catalogSignerPublicKey: signed[2].publicKey };
  let floor = new Zk1OpaqueCatalogIndependentFloorLedger(dbPath, { ...args, bootstrapNew: true });
  floor.close();
  fs.copyFileSync(dbPath, backupPath);
  floor = new Zk1OpaqueCatalogIndependentFloorLedger(dbPath, { ...args, bootstrapNew: false });
  const header = Buffer.from(await z.encodeDeterministic({ type: "rootark-zk1-opaque-catalog/v1",
    ...scope, sequence: 1, previous_digest: Buffer.alloc(32), manifest_revision: 1,
    manifest_digest: crypto.randomBytes(32), epoch: 1, signer_device_id: "device-1",
    total_count: 0, page_digests: [], issued_at: Math.floor(Date.now() / 1000) }));
  const signature = crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0"), header]), signed[2].privateKey);
  const digest = catalogHeadDigest(header, signature);
  await floor.compareAndSwap({ scope, expectedSequence: 0, expectedDigest: Buffer.alloc(32),
    nextSequence: 1, nextDigest: digest, headBytes: header, headSignature: signature,
    nonce: crypto.randomBytes(32) });
  assert.equal(floor.inspect().sequence, 1);
  floor.close();
  if (process.platform === "win32") exposeToLocalUsers(dir);
  else fs.chmodSync(dir, 0o777);
  // Another local user can now rename/replace the pathname, even if the
  // SQLite file itself remains owner-only.
  fs.renameSync(dbPath, path.join(dir, "advanced.sqlite"));
  fs.renameSync(backupPath, dbPath);
  assert.throws(() => new Zk1OpaqueCatalogIndependentFloorLedger(dbPath,
    { ...args, bootstrapNew: false }), /ZK_OPAQUE_FLOOR_UNAVAILABLE/,
  "an otherwise valid rollback must be rejected when the storage ACL permits hostile replacement");
});

test("Windows remote checkpoint authority refuses ACL-unsafe bootstrap and accepts owner-only directory", (t) => {
  if (process.platform !== "win32") return t.skip("Native Windows ACL threat model");
  const dir = windowsPrivateFixture(t);
  const [cas, floor, checkpoint, owner, witness] = Array.from({ length: 5 },
    () => crypto.generateKeyPairSync("ed25519"));
  const options = { role: "CAS", bootstrapNew: true,
    scope: { account_id: crypto.randomBytes(16), compartment_id: Buffer.from("w15-v2"),
      keyring_id: crypto.randomBytes(16) }, signingPrivateKey: cas.privateKey,
    casSignerPublicKey: cas.publicKey, floorSignerPublicKey: floor.publicKey,
    checkpointPublicKey: checkpoint.publicKey, ownerPublicKey: owner.publicKey,
    ownerTrust: { genesisDigest: crypto.randomBytes(32),
      pinnedWitness: { keyId: crypto.randomBytes(16), publicKey: witness.publicKey },
      minimumHead: { revision: 1, witnessSequence: 1, digest: crypto.randomBytes(32) },
      freshWitnessHead: async () => Buffer.alloc(0) },
    baseDigest: crypto.randomBytes(32), baseCheckpoint: crypto.randomBytes(32) };
  const filename = path.join(dir, "checkpoint.sqlite");
  const authority = new OpaqueCheckpointV2Authority(filename, options);
  authority.close();
  exposeToLocalUsers(dir);
  assert.throws(() => new OpaqueCheckpointV2Authority(filename, {
    ...options, bootstrapNew: false }), /ZK_CHECKPOINT_V2_UNAVAILABLE/);
});
