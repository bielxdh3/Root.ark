"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const protocol = require("../sync-client/rootark-sync-protocol");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { preflightAndPinSignedList } =
  require("../experiments/issue-66-w22-batched-admission/preflight");

async function fixture(t) {
  const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-w22-proof-"));
  t.after(() => fsp.rm(rootDir, { recursive: true, force: true }));
  const journal = await new SyncJournal(path.join(rootDir, ".rootark-sync-journal.json")).open();
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const fileKey = crypto.randomBytes(32);
  const trackedFiles = Object.create(null);
  const expected = {
    rootDir, journal, keyEpoch: "epoch-1", username: "alice",
    trustedDevicePublicKeys: { "signing-device": publicKey }, revokedDeviceIds: [],
    fileKeyResolver: () => fileKey, trackedFiles,
  };
  const signed = async (index, operation = "create", expiresAt = Date.now() + 60000,
    name = `file-${index}.txt`, epoch = "epoch-1") => {
    const plaintext = Buffer.from(`signed contents ${index}`, "utf8");
    const record = protocol.createOperation({
      operation, operationId: `signed-operation-${index}`,
      objectId: `signed-object-${index}`, fileId: `signed-file-${index}`,
      versionId: `signed-version-${index}`, deviceId: "signing-device",
      revision: { counter: 1, deviceId: "signing-device" }, baseRevision: null,
      keyEpoch: epoch, compartmentId: "private", plaintext, fileKey,
      metadata: operation === "delete" ? { path: name }
        : { path: name, name, size: plaintext.length },
    });
    record.authorization = await createAuthorizationProof(record, {
      username: "alice", publicKey, privateKey: pair.privateKey, expiresAt,
    });
    return record;
  };
  return { rootDir, journal, expected, signed, trackedFiles };
}

test("W22: invalid final Ed25519 envelope aborts the entire LIST before any durable pin or DELETE", async (t) => {
  const f = await fixture(t);
  const safe = await f.signed(1, "delete");
  const canary = path.join(f.rootDir, safe.metadata.path);
  await fsp.writeFile(canary, "private local user bytes");
  f.trackedFiles[safe.metadata.path] = { objectId: safe.objectId, fileId: safe.fileId,
    directory: false, deleted: false };
  const forged = await f.signed(2);
  forged.authorization.signature = crypto.randomBytes(64).toString("base64url");
  const oldJournal = await fsp.readFile(f.journal.filePath, "utf8");
  await assert.rejects(preflightAndPinSignedList({ ...f.expected, records: [safe, forged] }),
    (error) => error.code === "authorization_signature");
  assert.equal(await fsp.readFile(f.journal.filePath, "utf8"), oldJournal);
  assert.equal(await fsp.readFile(canary, "utf8"), "private local user bytes");
  assert.equal(f.journal.hasLocalAdmission(safe.operationId,
    crypto.createHash("sha256").update(protocol.canonicalJson(safe)).digest("hex")), false);
});

test("W22: signed DELETE is preflighted, physically bound and pinned before any stage", async (t) => {
  const f = await fixture(t);
  const removal = await f.signed(3, "delete");
  const local = path.join(f.rootDir, removal.metadata.path);
  await fsp.writeFile(local, "local cache bytes");
  f.trackedFiles[removal.metadata.path] = { objectId: removal.objectId,
    fileId: removal.fileId, directory: false, deleted: false };
  const prepared = await preflightAndPinSignedList({ ...f.expected, records: [removal] });
  assert.equal(prepared.observed, 1);
  assert.equal(prepared.operations[0].operation, "delete");
  assert.equal(await fsp.readFile(local, "utf8"), "local cache bytes",
    "the proof primitive itself cannot stage or delete anything");
  const cold = await new SyncJournal(f.journal.filePath).open();
  assert.equal(cold.hasLocalAdmission(removal.operationId,
    crypto.createHash("sha256").update(protocol.canonicalJson(removal)).digest("hex")), true);
});

test("W22: key epoch and revocation reject a whole LIST even after earlier valid envelopes", async (t) => {
  const f = await fixture(t);
  const valid = await f.signed(1);
  const oldEpoch = await f.signed(2, "create", Date.now() + 60000, "older.txt", "epoch-old");
  const before = await fsp.readFile(f.journal.filePath, "utf8");
  await assert.rejects(preflightAndPinSignedList({ ...f.expected,
    records: [valid, oldEpoch] }), { code: "remote_authorization_rejected" });
  await assert.rejects(preflightAndPinSignedList({ ...f.expected,
    records: [valid], revokedDeviceIds: ["signing-device"] }),
  { code: "authorization_device_revoked" });
  assert.equal(await fsp.readFile(f.journal.filePath, "utf8"), before);
});

test("W22: expired fresh record fails; previously pinned exact historical digest keeps current revocation checks", async (t) => {
  const f = await fixture(t);
  const expiry = Date.now() + 200;
  const valid = await f.signed(4, "create", expiry);
  const digest = crypto.createHash("sha256").update(protocol.canonicalJson(valid)).digest("hex");
  const fresh = await preflightAndPinSignedList({ ...f.expected, records: [valid] });
  assert.equal(fresh.observed, 1);
  await new Promise((resolve) => setTimeout(resolve, 240));
  const prior = await preflightAndPinSignedList({ ...f.expected, records: [valid] });
  assert.equal(prior.observed, 0);
  assert.equal(f.journal.hasLocalAdmission(valid.operationId, digest), true);
  await assert.rejects(preflightAndPinSignedList({ ...f.expected,
    records: [valid], revokedDeviceIds: ["signing-device"] }),
  { code: "authorization_device_revoked" });
  const f2 = await fixture(t);
  await assert.rejects(preflightAndPinSignedList({ ...f2.expected, records: [valid],
    trustedDevicePublicKeys: f.expected.trustedDevicePublicKeys }),
  { code: "authorization_expired" });
});

test("W22: a fresh signed batch expires during pre-commit policy wait before any durable pin", async (t) => {
  const f = await fixture(t);
  const fresh = await f.signed(41, "create", Date.now() + 650);
  const before = await fsp.readFile(f.journal.filePath, "utf8");
  await assert.rejects(preflightAndPinSignedList({ ...f.expected, records: [fresh],
    beforeCommit: async () => new Promise((resolve) => setTimeout(resolve, 900)),
  }), { code: "authorization_expired" });
  assert.equal(await fsp.readFile(f.journal.filePath, "utf8"), before);
  assert.equal(Object.keys(f.journal.state.observed).length, 0);
});

test("W22: journal queue delay cannot pin a newly expired signed LIST", async (t) => {
  const f = await fixture(t);
  const fresh = await f.signed(42, "create", Date.now() + 650);
  const busy = f.journal.commit(async () => {
    await new Promise((resolve) => setTimeout(resolve, 900));
  });
  await assert.rejects(preflightAndPinSignedList({ ...f.expected, records: [fresh] }),
    { code: "authorization_expired" });
  await busy;
  assert.equal(Object.keys(f.journal.state.observed).length, 0);
  assert.equal(f.journal.hasLocalAdmission(fresh.operationId,
    crypto.createHash("sha256").update(protocol.canonicalJson(fresh)).digest("hex")), false);
});

test("W22: duplicate operationIds and portable case aliases cannot mutate an earlier admission", async (t) => {
  const f = await fixture(t);
  const first = await f.signed(5);
  const sameCaseFold = await f.signed(6, "create", Date.now() + 60000, "FILE-5.txt");
  const before = await fsp.readFile(f.journal.filePath, "utf8");
  await assert.rejects(preflightAndPinSignedList({ ...f.expected, records: [first, first] }),
    { code: "remote_authorization_rejected" });
  await assert.rejects(preflightAndPinSignedList({ ...f.expected, records: [first, sameCaseFold] }),
    { code: "remote_path_collision" });
  await fsp.writeFile(path.join(f.rootDir, "FILE-5.txt"), "untracked canary");
  await assert.rejects(preflightAndPinSignedList({ ...f.expected, records: [first] }),
    { code: "remote_path_collision" });
  assert.equal(await fsp.readFile(f.journal.filePath, "utf8"), before);
});

test("W22: bounded LIST refuses 641 members before any persistent observation", async (t) => {
  const f = await fixture(t);
  const first = await f.signed(1);
  const previous = await fsp.readFile(f.journal.filePath, "utf8");
  await assert.rejects(preflightAndPinSignedList({ ...f.expected,
    records: Array.from({ length: 641 }, () => first) }),
  { code: "remote_authorization_rejected" });
  assert.equal(await fsp.readFile(f.journal.filePath, "utf8"), previous);
});

test("W22: journal rename EIO after complete signed LIST preflight leaves zero pins and no stage", async (t) => {
  const f = await fixture(t);
  const first = await f.signed(9, "delete");
  const target = path.join(f.rootDir, first.metadata.path);
  await fsp.writeFile(target, "keep this cache copy");
  f.trackedFiles[first.metadata.path] = { objectId: first.objectId,
    fileId: first.fileId, directory: false, deleted: false };
  const previous = await fsp.readFile(f.journal.filePath, "utf8");
  const originalRename = fsp.rename;
  fsp.rename = async (...args) => {
    if (args[1] === f.journal.filePath) {
      throw Object.assign(new Error("simulated EIO after preflight"), { code: "EIO" });
    }
    return originalRename(...args);
  };
  try {
    await assert.rejects(preflightAndPinSignedList({ ...f.expected,
      records: [first] }), { code: "EIO" });
  } finally { fsp.rename = originalRename; }
  assert.equal(await fsp.readFile(f.journal.filePath, "utf8"), previous);
  assert.equal(await fsp.readFile(target, "utf8"), "keep this cache copy");
  const cold = await new SyncJournal(f.journal.filePath).open();
  assert.equal(Object.keys(cold.state.observed).length, 0);
});

test("W22: all 160/640 real Ed25519 records preflight before one journal rename", async (t) => {
  for (const count of [160, 640]) {
    const f = await fixture(t);
    const records = [];
    for (let i = 0; i < count; i += 1) records.push(await f.signed(i));
    const originalRename = fsp.rename;
    let writes = 0;
    fsp.rename = async (...args) => {
      if (args[1] === f.journal.filePath) writes += 1;
      return originalRename(...args);
    };
    let result;
    const start = process.hrtime.bigint();
    try { result = await preflightAndPinSignedList({ ...f.expected, records }); }
    finally { fsp.rename = originalRename; }
    const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
    assert.equal(result.observed, count);
    assert.equal(writes, 1);
    assert.equal(Object.keys((await new SyncJournal(f.journal.filePath).open()).state.observed).length, count);
    assert.ok(elapsedMs > 0);
    t.diagnostic(`Ed25519/AEAD LIST ${count}: ${elapsedMs.toFixed(1)} ms; 1 journal rename`);
  }
});
