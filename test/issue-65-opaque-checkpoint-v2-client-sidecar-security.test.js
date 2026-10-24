"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Database = require("better-sqlite3");
const { Zk1OpaqueCheckpointV2Client } = require("../src/services/zk1OpaqueCheckpointV2Client");
const { createOpaqueCheckpointV2HttpsClient } = require("../src/services/zk1OpaqueCheckpointV2Remote");
const { createZk1OpaqueCatalogIndependentFloorHttpsClient } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");

const identity = () => crypto.generateKeyPairSync("ed25519");
const sha = (p) => crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
function options(journalPath, bootstrapNew) {
  const pairs = Array.from({ length: 7 }, identity);
  const [v1Cas, v1Floor, cas, floor, checkpoint, owner, catalog] = pairs;
  const trustedScope = { account_id: crypto.randomBytes(16), compartment_id: Buffer.from("v2-sqlite-local"),
    keyring_id: crypto.randomBytes(16) };
  const credentials = { ca: Buffer.from("fixture"), clientKey: Buffer.from("fixture"),
    clientCert: Buffer.from("fixture"), serverFingerprint256: Array(32).fill("AA").join(":"),
    scope: trustedScope };
  const v1FloorClient = createZk1OpaqueCatalogIndependentFloorHttpsClient({
    endpoint: "https://127.0.0.1:9443/", ca: credentials.ca, clientKey: credentials.clientKey,
    clientCert: credentials.clientCert, serverFingerprint256: credentials.serverFingerprint256,
    floorPublicKey: v1Floor.publicKey, casSignerPublicKey: v1Cas.publicKey, trustedScope,
  });
  const remote = (pub) => createOpaqueCheckpointV2HttpsClient({ ...credentials,
    endpoint: "https://127.0.0.1:9443/", authorityPublicKey: pub,
    casPublicKey: cas.publicKey, floorPublicKey: floor.publicKey });
  return { journalPath, bootstrapNew, trustedScope, v1FloorClient,
    v1CasClient: { publicKey: v1Cas.publicKey, readHead: async () => Buffer.alloc(0) },
    casClient: remote(cas.publicKey), floorClient: remote(floor.publicKey),
    expectedV1Digest: crypto.randomBytes(32), expectedV1Checkpoint: crypto.randomBytes(32),
    checkpointPublicKey: checkpoint.publicKey, ownerPublicKey: owner.publicKey,
    catalogPublicKey: catalog.publicKey,
    ownerTrust: { pinnedWitness: { publicKey: identity().publicKey, keyId: crypto.randomBytes(16) },
      minimumHead: { revision: 1, witnessSequence: 1, digest: crypto.randomBytes(32) },
      freshWitnessHead: async () => Buffer.alloc(0) } };
}

test("existing V2 client journal refuses alien hardlinked WAL/SHM and redirected directory before writable open", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-v2-local-sidecar-"));
  if (process.platform !== "win32") fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));
  const journalPath = path.join(dir, "owner-v2.sqlite");
  const opts = options(journalPath, true);
  const first = new Zk1OpaqueCheckpointV2Client(opts);
  first.close();
  const opening = () => new Zk1OpaqueCheckpointV2Client({ ...opts, bootstrapNew: false });
  const ordinary = opening(); ordinary.close();
  const sentinel = path.join(dir, "unrelated-confidential-file.bin");
  fs.writeFileSync(sentinel, crypto.randomBytes(4096));
  const sentinelHash = sha(sentinel);
  for (const suffix of ["-shm", "-wal", "-journal"]) {
    const alias = journalPath + suffix;
    fs.linkSync(sentinel, alias);
    let opened;
    try {
      assert.throws(() => { opened = opening(); }, /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE|UNTRUSTED_SQLITE_PATH/,
        `a foreign hardlinked ${suffix} sidecar must be rejected before SQLite opens`);
    } finally {
      opened?.close();
      if (fs.existsSync(alias)) fs.unlinkSync(alias);
    }
    assert.equal(sha(sentinel), sentinelHash, `foreign ${suffix} sentinel bytes unchanged`);
  }
  const redirectedParent = path.join(dir, "redirected");
  try {
    fs.symlinkSync(dir, redirectedParent, process.platform === "win32" ? "junction" : "dir");
    assert.throws(() => new Zk1OpaqueCheckpointV2Client({ ...opts,
      journalPath: path.join(redirectedParent, "owner-v2.sqlite"), bootstrapNew: false }),
    /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE|UNTRUSTED_SQLITE_PATH/);
  } catch (err) { if (!["EPERM", "EACCES", "ENOTSUP"].includes(err.code)) throw err; }
});

test("a same-name fake immutable intent trigger attached to another table fails closed without rewriting journal", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-v2-local-fake-trigger-"));
  if (process.platform !== "win32") fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));
  const journalPath = path.join(dir, "client.sqlite");
  const opts = options(journalPath, true);
  const first = new Zk1OpaqueCheckpointV2Client(opts);
  first.close();
  const forged = new Database(journalPath);
  forged.exec(`CREATE TABLE irrelevant(x INTEGER);
    DROP TRIGGER intent_immutable_update;
    CREATE TRIGGER intent_immutable_update BEFORE UPDATE ON irrelevant
      BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;`);
  forged.close();
  const original = sha(journalPath);
  assert.throws(() => new Zk1OpaqueCheckpointV2Client({ ...opts, bootstrapNew: false }),
    /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/);
  assert.equal(sha(journalPath), original, "preflight never repairs or changes a malformed client journal");
  assert.equal(fs.existsSync(journalPath + "-shm"), false);
});

test("V2 client bootstrap rejects a foreign SQLite substituted after O_EXCL without modifying it", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-v2-client-bootstrap-race-"));
  if (process.platform !== "win32") fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));
  const journalPath = path.join(dir, "new-client.sqlite");
  const foreign = path.join(dir, "foreign.sqlite");
  const unrelated = new Database(foreign);
  unrelated.exec("CREATE TABLE foreign_identity (id INTEGER PRIMARY KEY, marker TEXT);");
  unrelated.prepare("INSERT INTO foreign_identity VALUES (1, 'untouched')").run();
  unrelated.close();
  if (process.platform !== "win32") fs.chmodSync(foreign, 0o600);
  const priorHash = sha(foreign);

  const originalOpen = fs.openSync;
  const originalClose = fs.closeSync;
  let createdFd;
  let swapped = false;
  fs.openSync = function (name, flags, ...rest) {
    const fd = originalOpen.call(fs, name, flags, ...rest);
    if (name === journalPath && (flags & fs.constants.O_EXCL)) createdFd = fd;
    return fd;
  };
  fs.closeSync = function (fd, ...rest) {
    const closed = originalClose.call(fs, fd, ...rest);
    if (fd === createdFd && !swapped) {
      swapped = true;
      fs.renameSync(journalPath, path.join(dir, "original-client.sqlite"));
      // A distinct private, single-link inode bypasses ordinary no-hardlink
      // checks while retaining a recognizable foreign SQLite schema.
      fs.copyFileSync(foreign, journalPath);
    }
    return closed;
  };
  let opened;
  let rejected;
  try {
    opened = new Zk1OpaqueCheckpointV2Client(options(journalPath, true));
  } catch (error) {
    rejected = error;
  } finally {
    fs.openSync = originalOpen;
    fs.closeSync = originalClose;
    opened?.close();
  }
  assert.equal(swapped, true, "the adversary must swap the exact O_EXCL-created journal");
  assert.equal(sha(foreign), priorHash, "foreign database bytes must remain unchanged");
  assert.equal(sha(journalPath), priorHash, "substituted single-link journal must not be mutated");
  const readonly = new Database(foreign, { readonly: true, fileMustExist: true });
  try {
    assert.deepEqual(readonly.prepare("SELECT name FROM sqlite_master WHERE type='table'").all(),
      [{ name: "foreign_identity" }]);
  } finally { readonly.close(); }
  assert.match(rejected?.message || "", /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE|UNTRUSTED_SQLITE_PATH/,
    "the constructor must reject before opening the substituted journal writable");
});

test("a forged historical signer append trigger fails preflight before writable SQLite open", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-v2-signer-trigger-"));
  if (process.platform !== "win32") fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));
  const journalPath = path.join(dir, "client.sqlite");
  const opts = options(journalPath, true);
  const original = new Zk1OpaqueCheckpointV2Client(opts);
  original.close();
  const tampered = new Database(journalPath);
  tampered.exec(`DROP TRIGGER signer_grants_no_gap;
    CREATE TRIGGER signer_grants_no_gap BEFORE INSERT ON signer_grants
    BEGIN SELECT 1; END;`);
  tampered.close();
  const originalHash = sha(journalPath);
  assert.throws(() => new Zk1OpaqueCheckpointV2Client({ ...opts, bootstrapNew: false }),
    /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/);
  assert.equal(sha(journalPath), originalHash,
    "preflight rejects forged signer schema without repairing or mutating journal");
  assert.equal(fs.existsSync(journalPath + "-shm"), false);
});

test("historical grant authority cannot alias device, owner approval, CAS, floor or checkpoint signers", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-v2-grant-root-alias-"));
  if (process.platform !== "win32") fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));
  const journalPath = path.join(dir, "client.sqlite");
  const opts = options(journalPath, true);
  for (const alias of [opts.catalogPublicKey, opts.ownerPublicKey,
    opts.checkpointPublicKey, opts.casClient.publicKey, opts.floorClient.publicKey]) {
    assert.throws(() => new Zk1OpaqueCheckpointV2Client({ ...opts,
      signerGrantRootPublicKey: alias }), /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/);
    assert.equal(fs.existsSync(journalPath), false,
      "a self-certifying trust root is rejected before an authority journal is created");
  }
});
