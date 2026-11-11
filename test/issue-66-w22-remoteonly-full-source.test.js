"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof,
  verifyHistoricalAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { probeStrictRemoteOnlyBatch } =
  require("../experiments/issue-66-w22-batched-admission/remote-only-full-source");

async function fixture(t, count = 2, expiry = Date.now() + 60000) {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-w22-inert-source-"));
  t.after(() => fsp.rm(temp, { recursive: true, force: true }));
  const rootDir = path.join(temp, "cache");
  const fileKey = crypto.randomBytes(32);
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const records = [];
  const state = { epoch: 7, revoked: [], pushes: 0 };
  async function sign(i, operation = "create", prior = null) {
    const relative = `private/file-${String(i).padStart(4, "0")}.txt`;
    const bytes = Buffer.from(`encrypted fixture ${i}`);
    const result = protocol.createOperation({
      operation, objectId: `inert-object-${i}`, fileId: `inert-file-${i}`,
      versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
      keyEpoch: "epoch-1", compartmentId: "private", deviceId: "device-signer",
      revision: { counter: prior ? 2 : 1, deviceId: "device-signer" },
      baseRevision: prior?.revision || null,
      metadata: { path: relative, name: path.posix.basename(relative), size: bytes.length },
      plaintext: bytes, fileKey,
    });
    result.authorization = await createAuthorizationProof(result, {
      username: "alice", publicKey, privateKey: pair.privateKey, expiresAt: expiry,
    });
    return result;
  }
  for (let i = 0; i < count; i++) records.push(await sign(i));
  const trusted = {
    minEpoch: 7, keyEpoch: "epoch-1", username: "alice",
    trustedDevicePublicKeys: { "device-signer": publicKey },
    currentPolicyProvider: () => ({ epoch: state.epoch, username: "alice",
      keyEpoch: "epoch-1", trustedDevicePublicKeys: { "device-signer": publicKey },
      revokedDeviceIds: [...state.revoked] }),
  };
  const adapter = { async list() { return records; },
    async push() { state.pushes += 1; throw new Error("inert remote-only probe attempted remote mutation"); } };
  const makeEngine = async () => new SyncEngine({
    rootDir, adapter, deviceId: "device-reader", keyEpoch: "epoch-1",
    compartmentId: "private", excludedPaths: ["private"],
    requireAuthorization: true, fileKeyResolver: () => fileKey,
    verifyIncoming: async (operation, { locallyAdmitted = false } = {}) => {
      const policy = { username: "alice", trustedDevicePublicKeys: { "device-signer": publicKey },
        revokedDeviceIds: [...state.revoked] };
      return locallyAdmitted
        ? verifyHistoricalAuthorizationProof(operation.authorization, operation, policy)
        : verifyAuthorizationProof(operation.authorization, operation, policy);
    },
  }).open();
  const engine = await makeEngine();
  return { temp, rootDir, fileKey, publicKey, records, state, trusted, engine, makeEngine, sign };
}

async function persisted(f) {
  return {
    journal: await fsp.readFile(path.join(f.rootDir, ".rootark-sync-journal.json"), "utf8"),
    snapshot: await fsp.readFile(path.join(f.rootDir, ".rootark-sync-index.json"), "utf8"),
  };
}

// Bind negative-only crash evidence to the SAME opened inode; an lstat(path)
// followed by readFile(path) could observe unrelated equal-byte replacements.
// These disposable receipts never grant cold authority or clean up a name.
async function holdColdFile(t, directory, name) {
  const filename = path.join(directory, name);
  const handle = await fsp.open(filename,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  t.after(() => handle.close());
  const before = await handle.stat({ bigint: true });
  assert.equal(before.isFile(), true);
  assert.notEqual(before.ino, 0n);
  assert.equal(before.nlink, 1n);
  assert.ok(before.size > 0n && before.size < 1024n * 1024n,
    "the disposable cold receipt must be bounded");
  const data = Buffer.alloc(Number(before.size) + 1);
  const { bytesRead } = await handle.read(data, 0, data.length, 0);
  assert.equal(BigInt(bytesRead), before.size);
  const after = await handle.stat({ bigint: true });
  for (const key of ["dev", "ino", "size", "mtimeNs", "ctimeNs"]) {
    assert.equal(after[key], before[key], `opened ${name} changed during read`);
  }
  return { filename, name, handle, before, data: data.subarray(0, bytesRead) };
}

async function assertColdFileUntouched(receipt) {
  const current = await receipt.handle.stat({ bigint: true });
  for (const key of ["dev", "ino", "size", "mtimeNs", "ctimeNs"]) {
    assert.equal(current[key], receipt.before[key], `${receipt.name} original inode changed`);
  }
  const bytes = Buffer.alloc(receipt.data.length + 1);
  const { bytesRead } = await receipt.handle.read(bytes, 0, bytes.length, 0);
  assert.equal(bytesRead, receipt.data.length);
  assert.deepEqual(bytes.subarray(0, bytesRead), receipt.data);
  const reopened = await fsp.open(receipt.filename,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const named = await reopened.stat({ bigint: true });
    assert.equal(named.dev, receipt.before.dev);
    assert.equal(named.ino, receipt.before.ino,
      `${receipt.name} name was rebound to a different inode`);
  } finally { await reopened.close(); }
}

async function holdOneUncommittedTemp(t, directory, prefix) {
  const names = (await fsp.readdir(directory)).filter((name) => name.startsWith(prefix));
  assert.equal(names.length, 1, "failed publication must retain one uncommitted temporary");
  const receipt = await holdColdFile(t, directory, names[0]);
  return { names: await fsp.readdir(directory), receipt };
}

test("W22 inert source: exact 160/640 signed remoteOnly CREATE stays metadata-only and persists 2 journal + 1 snapshot transactions", async (t) => {
  for (const count of [160, 640]) {
    const f = await fixture(t, count);
    const originalRename = fsp.rename;
    let journalWrites = 0;
    let indexWrites = 0;
    const journalFile = f.engine.journal.filePath;
    const indexFile = f.engine.snapshotPath;
    fsp.rename = async (...args) => {
      if (args[1] === journalFile) journalWrites++;
      if (args[1] === indexFile) indexWrites++;
      return originalRename(...args);
    };
    let result;
    const started = process.hrtime.bigint();
    try { result = await probeStrictRemoteOnlyBatch(f.engine, f.trusted); }
    finally { fsp.rename = originalRename; }
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    assert.deepEqual(result, { observed: count, acknowledged: count });
    assert.equal(journalWrites, 2);
    assert.equal(indexWrites, 1);
    assert.equal(f.state.pushes, 0);
    const restarted = await f.makeEngine();
    assert.equal(Object.keys(restarted.snapshot.files).length, 0);
    assert.equal(Object.keys(restarted.snapshot.remoteOnly).length, count);
    assert.equal(restarted.journal.state.seen.length, count);
    assert.equal(Object.keys(restarted.journal.state.observed).length, 0);
    assert.deepEqual((await fsp.readdir(f.rootDir)).sort(),
      [".rootark-sync-index.json", ".rootark-sync-journal.json"].sort());
    t.diagnostic(`W22 inert full source ${count} Ed25519+AEAD: ${ms.toFixed(1)} ms, 3 durable renames`);
  }
});

test("W22 inert source: late invalid Ed25519 signature refuses whole LIST before observation and snapshot", async (t) => {
  const f = await fixture(t, 160);
  const before = await persisted(f);
  f.records[159].authorization.signature = crypto.randomBytes(64).toString("base64url");
  await assert.rejects(probeStrictRemoteOnlyBatch(f.engine, f.trusted),
    { code: "authorization_signature" });
  assert.deepEqual(await persisted(f), before);
  assert.equal(f.state.pushes, 0);
});

test("W22 inert source: physical negative canaries, directory aliases and staged trash refuse all writes", async (t) => {
  for (const kind of ["file", "directory", "case-alias", "trash"]) {
    const f = await fixture(t, 2);
    const relative = kind === "file" ? "private-file-canary"
      : kind === "directory" ? "private" : kind === "case-alias" ? "PRIVATE" : ".rootark-trash";
    const target = path.join(f.rootDir, relative);
    if (kind === "file") await fsp.writeFile(target, "canary");
    else await fsp.mkdir(target);
    const before = await persisted(f);
    await assert.rejects(probeStrictRemoteOnlyBatch(f.engine, f.trusted),
      { code: "unsafe_path" });
    assert.deepEqual(await persisted(f), before);
    assert.equal((await fsp.lstat(target)).isFile(), kind === "file");
  }
});

test("W22 inert source: a nested physical canary inside the root lock is not empty cache", async (t) => {
  const f = await fixture(t);
  const lock = path.join(f.rootDir, ".rootark-sync.lock");
  await fsp.mkdir(lock);
  const nested = path.join(lock, "untracked-physical-data");
  await fsp.mkdir(nested);
  const canary = path.join(nested, "user-canary.txt");
  await fsp.writeFile(canary, "untouched physical user bytes");
  const { assertRootHasNoPhysicalCache } =
    require("../experiments/issue-66-w22-batched-admission/remote-only-full-source");
  await assert.rejects(assertRootHasNoPhysicalCache(f.rootDir), { code: "unsafe_path" });
  assert.equal(await fsp.readFile(canary, "utf8"), "untouched physical user bytes");
});

test("W22 inert source: physical symlink/junction to an outside canary is refused with no external byte changes", async (t) => {
  const f = await fixture(t);
  const outside = path.join(f.temp, "external-canary");
  await fsp.mkdir(outside);
  await fsp.writeFile(path.join(outside, "keep.txt"), "untouched external bytes");
  const symlink = path.join(f.rootDir, "private");
  try { await fsp.symlink(outside, symlink, process.platform === "win32" ? "junction" : "dir"); }
  catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP", "ENOSYS"].includes(error?.code)) {
      t.skip(`Native junction/symlink privilege unavailable: ${error.code}`);
      return;
    }
    throw error;
  }
  const before = await persisted(f);
  await assert.rejects(probeStrictRemoteOnlyBatch(f.engine, f.trusted),
    { code: "unsafe_path" });
  assert.deepEqual(await persisted(f), before);
  assert.equal(await fsp.readFile(path.join(outside, "keep.txt"), "utf8"),
    "untouched external bytes");
  assert.equal((await fsp.lstat(symlink)).isSymbolicLink(), true);
});

test("W22 inert source: active eviction or local tracked/pinned state cannot enter batch", async (t) => {
  const f = await fixture(t);
  const before = await persisted(f);
  for (const inject of [
    () => { f.engine.snapshot.evictionLedgerRequired = true; },
    () => { f.engine.snapshot.pendingEvictions = { foo: { path: "private/x", code: "EIO", attempts: 1 } }; },
    () => { f.engine.snapshot.files["public/canary.txt"] = { objectId: "x" }; },
    () => { f.engine.snapshot.pinnedFiles = { foo: { path: "x" } }; },
  ]) {
    const original = JSON.parse(JSON.stringify(f.engine.snapshot));
    inject();
    // The real exclusive-root open reloads durable state, so a test-only
    // in-memory injection must call the pure predicate instead.
    const { assertEmptyLocalCache } =
      require("../experiments/issue-66-w22-batched-admission/remote-only-full-source");
    assert.throws(() => assertEmptyLocalCache(f.engine),
      { code: "remote_only_batch_ineligible" });
    f.engine.snapshot = original;
  }
  assert.deepEqual(await persisted(f), before);
});

test("W22 inert source: snapshot rename EIO preserves pins and quarantines an untrusted cold orphan", async (t) => {
  const f = await fixture(t, 4);
  const old = await persisted(f);
  const originalRename = fsp.rename;
  fsp.rename = async (...args) => args[1] === f.engine.snapshotPath
    ? Promise.reject(Object.assign(new Error("snapshot EIO"), { code: "EIO" }))
    : originalRename(...args);
  try { await assert.rejects(probeStrictRemoteOnlyBatch(f.engine, f.trusted), { code: "EIO" }); }
  finally { fsp.rename = originalRename; }
  const intermediate = await persisted(f);
  assert.equal(intermediate.snapshot, old.snapshot);
  assert.equal(Object.keys(JSON.parse(intermediate.journal).observed).length, 4);
  assert.equal(JSON.parse(intermediate.journal).seen.length, 0);
  const { names, receipt: orphan } = await holdOneUncommittedTemp(t, f.rootDir,
    ".rootark-sync-index.json.tmp-");
  const snapshot = await holdColdFile(t, f.rootDir, ".rootark-sync-index.json");
  const journal = await holdColdFile(t, f.rootDir, ".rootark-sync-journal.json");
  const restarted = await f.makeEngine();
  assert.equal(Object.keys(restarted.snapshot.remoteOnly).length, 0);
  await assert.rejects(probeStrictRemoteOnlyBatch(restarted, f.trusted),
    { code: "unsafe_path" }, "a preserved untrusted orphan cannot authorize a cold ACK");
  assert.equal(f.state.pushes, 0);
  assert.equal((await restarted.journal.recover()).length, 0);
  assert.equal(restarted.journal.state.seen.length, 0);
  assert.equal(Object.keys(restarted.journal.state.observed).length, 4);
  assert.deepEqual(await persisted(f), intermediate);
  assert.deepEqual(await fsp.readdir(f.rootDir), names);
  for (const witness of [orphan, snapshot, journal]) await assertColdFileUntouched(witness);
});

test("W22 inert source: externally trusted policy epoch rollback/revocation across preflight refuses snapshot", async (t) => {
  for (const change of ["rollback", "revoke"]) {
    const f = await fixture(t, 2);
    const before = await persisted(f);
    let calls = 0;
    const originalPolicy = f.trusted.currentPolicyProvider;
    f.trusted.currentPolicyProvider = () => {
      calls++;
      if (calls === 2) {
        if (change === "rollback") f.state.epoch = 6;
        else f.state.revoked = ["device-signer"];
      }
      return originalPolicy();
    };
    await assert.rejects(probeStrictRemoteOnlyBatch(f.engine, f.trusted),
      { code: change === "rollback" ? "remote_authorization_rejected"
        : "authorization_device_revoked" });
    assert.deepEqual(await persisted(f), before);
  }
});

test("W22 inert source: revocation while final ACK is queued cannot mark signed records seen", async (t) => {
  const f = await fixture(t, 1);
  let blockingCommit;
  await assert.rejects(probeStrictRemoteOnlyBatch(f.engine, f.trusted, {
    afterSnapshot: async () => {
      blockingCommit = f.engine.journal.commit(async () => {
        await new Promise((resolve) => setTimeout(resolve, 550));
        f.state.epoch = 8;
        f.state.revoked = ["device-signer"];
      });
    },
  }), { code: "authorization_device_revoked" });
  await blockingCommit;
  const cold = await f.makeEngine();
  assert.equal(cold.journal.state.seen.length, 0);
  assert.equal(Object.keys(cold.journal.state.observed).length, 1);
  assert.equal(Object.keys(cold.snapshot.remoteOnly).length, 1);
  assert.deepEqual(f.state.revoked, ["device-signer"]);
});

test("W22 inert source: physical canary introduced after preflight pins is detected before snapshot", async (t) => {
  const f = await fixture(t, 2);
  const canary = path.join(f.rootDir, "private");
  await assert.rejects(probeStrictRemoteOnlyBatch(f.engine, f.trusted, {
    afterObserve: async () => fsp.mkdir(canary),
  }), { code: "unsafe_path" });
  const intermediate = await persisted(f);
  assert.equal(Object.keys(JSON.parse(intermediate.journal).observed).length, 2);
  assert.equal(Object.keys(JSON.parse(intermediate.snapshot).remoteOnly).length, 0);
  assert.equal((await fsp.lstat(canary)).isDirectory(), true);
  await fsp.rmdir(canary);
  assert.deepEqual(await probeStrictRemoteOnlyBatch(await f.makeEngine(), f.trusted),
    { observed: 0, acknowledged: 2 });
});

test("W22 inert source: incomplete LIST, missing prior marker and repeated operationId failclosed", async (t) => {
  const f = await fixture(t, 2);
  const first = f.records[0];
  const second = f.records[1];
  const before = await persisted(f);
  f.records.splice(1, 1, first);
  await assert.rejects(probeStrictRemoteOnlyBatch(f.engine, f.trusted),
    { code: "remote_only_batch_ineligible" });
  assert.deepEqual(await persisted(f), before);
  f.records.splice(1, 1, second);
  await probeStrictRemoteOnlyBatch(f.engine, f.trusted);
  f.records.splice(1, 1);
  await assert.rejects(probeStrictRemoteOnlyBatch(await f.makeEngine(), f.trusted),
    { code: "remote_only_batch_ineligible" });
});

test("W22 inert source: markSeen EIO preserves exact pins but cold orphan blocks unsafe replay", async (t) => {
  const f = await fixture(t, 3);
  let journalWrites = 0;
  const originalRename = fsp.rename;
  fsp.rename = async (...args) => {
    if (args[1] === f.engine.journal.filePath && ++journalWrites === 2) {
      throw Object.assign(new Error("ACK EIO"), { code: "EIO" });
    }
    return originalRename(...args);
  };
  try { await assert.rejects(probeStrictRemoteOnlyBatch(f.engine, f.trusted), { code: "EIO" }); }
  finally { fsp.rename = originalRename; }
  const intermediate = await persisted(f);
  assert.equal(Object.keys(JSON.parse(intermediate.snapshot).remoteOnly).length, 3);
  assert.equal(Object.keys(JSON.parse(intermediate.journal).observed).length, 3);
  assert.equal(JSON.parse(intermediate.journal).seen.length, 0);
  const { names, receipt: orphan } = await holdOneUncommittedTemp(t, f.rootDir,
    ".rootark-sync-journal.json.tmp-");
  const snapshot = await holdColdFile(t, f.rootDir, ".rootark-sync-index.json");
  const journal = await holdColdFile(t, f.rootDir, ".rootark-sync-journal.json");
  const restarted = await f.makeEngine();
  assert.equal(Object.keys(restarted.snapshot.remoteOnly).length, 3);
  assert.equal(Object.keys(restarted.journal.state.observed).length, 3);
  assert.equal(restarted.journal.state.seen.length, 0);
  await assert.rejects(probeStrictRemoteOnlyBatch(restarted, f.trusted),
    { code: "unsafe_path" }, "a failed ACK's temporary is not a signed admission receipt");
  assert.equal(f.state.pushes, 0);
  assert.equal(restarted.journal.state.seen.length, 0);
  assert.deepEqual(await persisted(f), intermediate);
  assert.deepEqual(await fsp.readdir(f.rootDir), names);
  for (const witness of [orphan, snapshot, journal]) await assertColdFileUntouched(witness);
});

test("W22 inert source: expiry after observation permits same digest restart, but revocation rejects", async (t) => {
  const f = await fixture(t, 2, Date.now() + 550);
  await assert.rejects(probeStrictRemoteOnlyBatch(f.engine, f.trusted, {
    afterObserve: async () => { throw Object.assign(new Error("simulated crash window"), { code: "CRASH" }); },
  }), { code: "CRASH" });
  await new Promise((resolve) => setTimeout(resolve, 650));
  const restarted = await f.makeEngine();
  assert.deepEqual(await probeStrictRemoteOnlyBatch(restarted, f.trusted),
    { observed: 0, acknowledged: 2 });
  f.state.revoked = ["device-signer"];
  const cold = await f.makeEngine();
  await assert.rejects(probeStrictRemoteOnlyBatch(cold, f.trusted),
    { code: "authorization_device_revoked" });
});

test("W22 inert source: UPDATE with previous excluded remoteOnly identity accepted; MOVE/DELETE refused", async (t) => {
  const f = await fixture(t, 1);
  assert.deepEqual(await probeStrictRemoteOnlyBatch(f.engine, f.trusted),
    { observed: 1, acknowledged: 1 });
  const original = f.records[0];
  f.records[0] = await f.sign(0, "update", original);
  const updated = await f.makeEngine();
  assert.deepEqual(await probeStrictRemoteOnlyBatch(updated, f.trusted),
    { observed: 1, acknowledged: 1 });
  for (const mutation of ["delete", "move"]) {
    f.records[0] = { ...f.records[0], operation: mutation, tombstone: mutation === "delete" };
    await assert.rejects(probeStrictRemoteOnlyBatch(await f.makeEngine(), f.trusted),
      { code: "remote_only_batch_ineligible" });
  }
  assert.equal(f.state.pushes, 0);
});

test("W22 inert source: real process exit after observation / snapshot reopens and completes without cache mutation", async (t) => {
  for (const phase of ["afterObserve", "afterSnapshot"]) {
    const f = await fixture(t, 2);
    const file = path.join(f.temp, "fixture.json");
    await fsp.writeFile(file, JSON.stringify({ rootDir: f.rootDir, records: f.records,
      key: f.fileKey.toString("base64url"), publicKey: f.publicKey }), { mode: 0o600 });
    const childFile = path.join(__dirname,
      "../experiments/issue-66-w22-batched-admission/remote-only-hard-exit-child.cjs");
    const child = spawnSync(process.execPath, [childFile, file, phase], {
      timeout: 20000, encoding: "utf8", windowsHide: true,
    });
    assert.equal(child.status, 73, child.stderr);
    // A hard-killed child intentionally leaves the exclusive root lock:
    // recovery requires a separate operator action. This is only a fresh,
    // disposable test root; never auto-clear locks in the production engine.
    const staleLock = path.join(f.rootDir, ".rootark-sync.lock");
    assert.deepEqual(await fsp.readdir(staleLock), []);
    await fsp.rmdir(staleLock);
    const cold = await f.makeEngine();
    assert.equal(Object.keys(cold.journal.state.observed).length, 2);
    assert.equal(Object.keys(cold.snapshot.remoteOnly).length,
      phase === "afterSnapshot" ? 2 : 0);
    assert.deepEqual(await probeStrictRemoteOnlyBatch(cold, f.trusted),
      { observed: 0, acknowledged: 2 });
    assert.equal((await f.makeEngine()).journal.state.seen.length, 2);
  }
});
