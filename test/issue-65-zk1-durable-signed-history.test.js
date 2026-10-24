"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const z = require("../src/crypto/rootark-zk-1");
const m = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const verifiedHistory = require("../src/crypto/rootark-zk-recovery-history-v2");
const { Zk1LocalSignedHistoryStore } = require("../src/services/zk1LocalSignedHistoryStore");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");

function scope(state) { return { owner: "alice", ...state.scope }; }
async function encoded(manifest) { return Buffer.from(await z.encodeDeterministic(manifest)); }
function scratch() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-durable-history-"));
  return path.join(directory, "signed.sqlite");
}
function open(file) { return new Zk1LocalSignedHistoryStore(file, { nowSeconds: () => 1100 }); }

test("signed keyring v2 initialize persists exact canonical bytes, digest and identifier inventory", async (t) => {
  const file = scratch();
  const state = await fixtures.createInitialState(1);
  const store = open(file);
  let reopened;
  t.after(() => { reopened?.close(); store.close(); fs.rmSync(path.dirname(file), {
    recursive: true, force: true, maxRetries: 10, retryDelay: 100,
  }); });
  const manifestBytes = await encoded(state.headManifest);
  const result = await store.append({
    owner: "alice", manifestBytes, expectedRevision: 0, expectedDigest: null,
  });
  assert.equal(result.revision, 1);
  assert.deepEqual(result.digest, await m.recoveryManifestDigestV2(state.headManifest));
  assert.equal(result.capacity.usedTransitions, 1);
  const snapshot = store.snapshot(scope(state));
  assert.equal(snapshot.revision, 1);
  assert.deepEqual(snapshot.entries, [manifestBytes]);
  assert.deepEqual(snapshot.digest, result.digest);
  store.close();
  reopened = open(file);
  assert.deepEqual(reopened.snapshot(scope(state)), snapshot);
  assert.equal(reopened.snapshot({ owner: "bob", ...state.scope }), null,
    "separate account must never read another account's signed metadata");
});

test("rejects stale expected head, duplicate operation, altered signatures, changed owner, invalid canonical input", async (t) => {
  const file = scratch();
  const state = await fixtures.createInitialState(1);
  const store = open(file);
  t.after(() => { store.close(); fs.rmSync(path.dirname(file), {
    recursive: true, force: true, maxRetries: 10, retryDelay: 100,
  }); });
  const original = await encoded(state.headManifest);
  await store.append({ owner: "alice", manifestBytes: original, expectedRevision: 0, expectedDigest: null });
  await assert.rejects(store.append({
    owner: "alice", manifestBytes: original, expectedRevision: 0, expectedDigest: null,
  }), /ZK1_HISTORY_CONFLICT/);
  const broken = { ...state.headManifest, actor_signature: crypto.randomBytes(64) };
  await assert.rejects(store.append({
    owner: "bob", manifestBytes: await encoded(broken), expectedRevision: 0, expectedDigest: null,
  }));
  await assert.rejects(store.append({
    owner: "alice", manifestBytes: Buffer.from("not canonical CBOR"),
    expectedRevision: 1, expectedDigest: Buffer.alloc(32),
  }));
  const outside = Buffer.concat([original, Buffer.from([0])]);
  await assert.rejects(store.append({
    owner: "bob", manifestBytes: outside, expectedRevision: 0, expectedDigest: null,
  }));
});

test("a concurrent append is accepted once and preserves a contiguous durable chain", async (t) => {
  const file = scratch();
  const state = await fixtures.createInitialState(2);
  const base = state.baseManifest;
  const manifestBytes = await encoded(base);
  const store = open(file);
  t.after(() => { store.close(); fs.rmSync(path.dirname(file), {
    recursive: true, force: true, maxRetries: 10, retryDelay: 100,
  }); });
  const created = await store.append({
    owner: "alice", manifestBytes, expectedRevision: 0, expectedDigest: null,
  });
  const nextManifest = state.headManifest;
  const nextBytes = await encoded(nextManifest);
  const request = {
    owner: "alice", manifestBytes: nextBytes,
    expectedRevision: 1, expectedDigest: created.digest,
  };
  const outcomes = await Promise.allSettled([store.append(request), store.append(request)]);
  assert.equal(outcomes.filter((o) => o.status === "fulfilled").length, 1);
  assert.equal(outcomes.filter((o) => o.status === "rejected").length, 1);
  const history = store.snapshot(scope(state));
  assert.equal(history.revision, 2);
  assert.deepEqual(history.entries, [manifestBytes, nextBytes]);
  assert.deepEqual(history.digest, await m.recoveryManifestDigestV2(nextManifest));
});

test("two independently opened SQLite handles cannot both commit the same revision", async (t) => {
  const file = scratch();
  const first = open(file);
  const second = open(file);
  t.after(() => {
    first.close(); second.close();
    fs.rmSync(path.dirname(file), { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const state = await fixtures.createInitialState(2);
  const initialized = await first.append({
    owner: "a user with spaces", manifestBytes: await encoded(state.baseManifest),
    expectedRevision: 0, expectedDigest: null,
  });
  const proposal = { owner: "a user with spaces",
    manifestBytes: await encoded(state.headManifest),
    expectedRevision: 1, expectedDigest: initialized.digest };
  const completed = await Promise.allSettled([
    first.append(proposal), second.append(proposal),
  ]);
  assert.equal(completed.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal(completed.filter((r) => r.status === "rejected").length, 1);
  assert.equal(first.snapshot({ owner: proposal.owner, ...state.scope }).revision, 2);
  assert.equal(second.snapshot({ owner: proposal.owner, ...state.scope }).revision, 2);
});

test("tampered persisted signed history fails closed instead of silently returning a false head", async (t) => {
  const file = scratch();
  const state = await fixtures.createInitialState(1);
  const store = open(file);
  await store.append({ owner: "alice", manifestBytes: await encoded(state.headManifest),
    expectedRevision: 0, expectedDigest: null });
  store.close();
  const Database = require("better-sqlite3");
  const db = new Database(file);
  db.prepare("UPDATE zk1_local_history SET manifest_bytes = ? WHERE revision = 1")
    .run(Buffer.from("invalid"));
  db.close();
  const reopened = open(file);
  t.after(() => { reopened.close(); fs.rmSync(path.dirname(file), {
    recursive: true, force: true, maxRetries: 10, retryDelay: 100,
  }); });
  assert.throws(() => reopened.snapshot(scope(state)), /ZK1_HISTORY_CORRUPT/);
});

test("persisted signed chain is publicly reverified against an independently supplied pinned witness base", async (t) => {
  const file = scratch();
  const store = open(file);
  t.after(() => {
    store.close();
    fs.rmSync(path.dirname(file), { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const state = await fixtures.createInitialState(2);
  const first = await store.append({ owner: "alice", manifestBytes: await encoded(state.baseManifest),
    expectedRevision: 0, expectedDigest: null });
  await store.append({ owner: "alice", manifestBytes: await encoded(state.headManifest),
    expectedRevision: 1, expectedDigest: first.digest });
  const result = await store.verifyPublicHistory({
    owner: "alice", ...state.scope,
    baseReceipt: state.baseReceipt, pinnedWitness: state.pinnedWitness, now: 100_000,
  });
  assert.equal(result.signedStateVerified, true);
  assert.equal(await verifiedHistory.isVerifiedPublicRecoveryHistoryV2(result), true);
  assert.equal(result.authorizationVerified, false,
    "the local archive must never be confused with active-device authorization");
  assert.equal(result.freshnessProven, false,
    "a pinned BASE receipt is not a fresh nonce-bound independent witness");
  await assert.rejects(store.verifyPublicHistory({
    owner: "alice", ...state.scope, baseReceipt: null,
    pinnedWitness: state.pinnedWitness, now: 100_000,
  }), /ZK1_HISTORY_UNVERIFIED/);
});

test("public archive verification requires exact externally supplied opaque package envelopes when registered", async (t) => {
  const file = scratch();
  const store = open(file);
  t.after(() => {
    store.close();
    fs.rmSync(path.dirname(file), { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const state = await fixtures.createInitialState(1);
  const packageToRegister = await fixtures.createPackageEnvelope(state, {
    previousManifest: state.headManifest,
  });
  const registered = await fixtures.appendPackageActivation(state, packageToRegister.envelopeBytes);
  const base = await store.append({
    owner: "alice", manifestBytes: await encoded(state.baseManifest),
    expectedRevision: 0, expectedDigest: null,
  });
  await store.append({
    owner: "alice", manifestBytes: await encoded(registered.manifest),
    expectedRevision: 1, expectedDigest: base.digest,
  });
  const args = { owner: "alice", ...state.scope, baseReceipt: state.baseReceipt,
    pinnedWitness: state.pinnedWitness, now: 100_000 };
  await assert.rejects(store.verifyPublicHistory(args), /ZK1_HISTORY_UNVERIFIED/,
    "signed package activation must not be accepted without the matching opaque envelope");
  const withPackage = await store.verifyPublicHistory({
    ...args,
    packageEnvelopes: [{ activationRevision: registered.manifest.revision,
      envelopeBytes: packageToRegister.envelopeBytes }],
  });
  assert.equal(withPackage.signedStateVerified, true);
  assert.equal(withPackage.authorizationVerified, false);
});

test("public archive verifies a legitimately delayed package activation after signed device enrollment", async (t) => {
  const file = scratch();
  const store = open(file);
  t.after(() => { store.close(); fs.rmSync(path.dirname(file),
    { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); });
  const state = await fixtures.createInitialState(2);
  const packageData = await fixtures.createPackageEnvelope(state, { previousManifest: state.headManifest });
  const packageActivation = await fixtures.appendPackageActivation(state, packageData.envelopeBytes);
  const entries = [
    state.baseManifest,
    await z.decodeDeterministic(state.transitions[0]),
    packageActivation.manifest,
  ];
  let expectedRevision = 0;
  let expectedDigest = null;
  for (const entry of entries) {
    const committed = await store.append({
      owner: "alice", manifestBytes: await encoded(entry), expectedRevision, expectedDigest,
    });
    expectedRevision = committed.revision;
    expectedDigest = committed.digest;
  }
  const verifiedInput = {
    owner: "alice", ...state.scope, baseReceipt: state.baseReceipt,
    pinnedWitness: state.pinnedWitness, now: 100_000,
    packageEnvelopes: [{ activationRevision: packageActivation.manifest.revision,
      envelopeBytes: packageData.envelopeBytes }],
  };
  const checked = await store.verifyPublicHistory(verifiedInput);
  assert.equal(checked.signedStateVerified, true);
  assert.equal(checked.packageEnvelopeBound, true);
  assert.equal(checked.revision, 3);
  assert.equal(checked.freshnessProven, false);
  await assert.rejects(store.verifyPublicHistory({ ...verifiedInput, packageEnvelopes: [] }),
    /ZK1_HISTORY_UNVERIFIED/, "omitting the package envelope must fail closed");
  await assert.rejects(store.verifyPublicHistory({
    ...verifiedInput, packageEnvelopes: [{ activationRevision: 3,
      envelopeBytes: Buffer.from(packageData.envelopeBytes).fill(0xa5) }],
  }), /ZK1_HISTORY_UNVERIFIED/, "wrong envelope must fail closed even with valid history signatures");
});

test("public archive cryptographically binds replacement and compromise package activation envelopes", async (t) => {
  const file = scratch();
  const store = open(file);
  t.after(() => { store.close(); fs.rmSync(path.dirname(file),
    { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); });
  const state = await fixtures.createInitialState(1);
  const original = await fixtures.createPackageEnvelope(state, { previousManifest: state.headManifest });
  await fixtures.appendPackageActivation(state, original.envelopeBytes);
  const replacement = await fixtures.createPackageEnvelope(state, { previousManifest: state.headManifest });
  await fixtures.appendPackageActivation(state, replacement.envelopeBytes, "replace-package");
  const compromiseReplacement = await fixtures.createPackageEnvelope(state, { previousManifest: state.headManifest });
  await fixtures.appendPackageCompromise(state, compromiseReplacement.envelopeBytes);
  let expectedRevision = 0;
  let expectedDigest = null;
  const allEntries = [state.baseManifest, ...state.transitions.map((raw) => raw)];
  for (const item of allEntries) {
    const raw = Buffer.isBuffer(item) || item instanceof Uint8Array ? Buffer.from(item) : await encoded(item);
    const outcome = await store.append({ owner: "alice", manifestBytes: raw,
      expectedRevision, expectedDigest });
    expectedRevision = outcome.revision;
    expectedDigest = outcome.digest;
  }
  const args = {
    owner: "alice", ...state.scope, baseReceipt: state.baseReceipt,
    pinnedWitness: state.pinnedWitness, now: 100_000,
    packageEnvelopes: [
      { activationRevision: 2, envelopeBytes: original.envelopeBytes },
      { activationRevision: 3, envelopeBytes: replacement.envelopeBytes },
      { activationRevision: 4, envelopeBytes: compromiseReplacement.envelopeBytes },
    ],
  };
  const history = await store.verifyPublicHistory(args);
  assert.equal(history.revision, 4);
  assert.equal(history.packageEnvelopeBound, true);
  await assert.rejects(store.verifyPublicHistory({
    ...args, packageEnvelopes: args.packageEnvelopes.slice(0, 2),
  }), /ZK1_HISTORY_UNVERIFIED/);
});

test("a deleted retained identifier ledger entry is caught before any next signed append", async (t) => {
  const file = scratch();
  const store = open(file);
  t.after(() => {
    store.close();
    fs.rmSync(path.dirname(file), { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const state = await fixtures.createInitialState(2);
  const first = await store.append({
    owner: "alice", manifestBytes: await encoded(state.baseManifest),
    expectedRevision: 0, expectedDigest: null,
  });
  store.db.prepare("DELETE FROM zk1_local_identifier WHERE identifier LIKE 'operation:%'").run();
  await assert.rejects(store.append({
    owner: "alice", manifestBytes: await encoded(state.headManifest),
    expectedRevision: 1, expectedDigest: first.digest,
  }), /ZK1_HISTORY_CORRUPT/);
});

test("read snapshot stays on one coherent revision when another SQLite handle commits between SELECTs", async (t) => {
  const file = scratch();
  const first = open(file);
  const second = open(file);
  t.after(() => {
    first.close(); second.close();
    fs.rmSync(path.dirname(file), { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const state = await fixtures.createInitialState(2);
  const initBytes = await encoded(state.baseManifest);
  await first.append({
    owner: "alice", manifestBytes: initBytes, expectedRevision: 0, expectedDigest: null,
  });
  const nextBytes = await encoded(state.headManifest);
  const nextDigest = Buffer.from(await m.recoveryManifestDigestV2(state.headManifest));
  const row = second.db.prepare(
    "SELECT scope_id FROM zk1_local_scope WHERE owner='alice'").get();
  assert.ok(row?.scope_id);
  const statement = first.allEntries;
  let injected = false;
  first.allEntries = { all(owner, id) {
    if (!injected) {
      injected = true;
      second.db.transaction(() => {
        second.db.prepare(
          "UPDATE zk1_local_scope SET revision=2,digest=?,entry_count=2,history_bytes=history_bytes+? WHERE owner=? AND scope_id=?",
        ).run(nextDigest, nextBytes.length, owner, id);
        second.db.prepare(
          "INSERT INTO zk1_local_history(owner,scope_id,revision,digest,operation_id,manifest_bytes) VALUES(?,?,?,?,?,?)",
        ).run(owner, id, 2, nextDigest,
          Buffer.from(state.headManifest.operation.operation_id), nextBytes);
      }).immediate();
    }
    return statement.all(owner, id);
  } };
  const during = first.snapshot(scope(state));
  assert.equal(during.revision, 1,
    "reader must see the old coherent state, not the newer entries with the old head");
  first.allEntries = statement;
  const afterward = first.snapshot(scope(state));
  assert.equal(afterward.revision, 2);
});

test("signed-history storage rejects unbounded global scope growth and per-owner retained bytes", async (t) => {
  const file = scratch();
  const state = await fixtures.createInitialState(2);
  const initialRaw = await encoded(state.baseManifest);
  const store = new Zk1LocalSignedHistoryStore(file, {
    nowSeconds: () => 1100,
    maxScopesPerOwner: 1, maxGlobalScopes: 1,
    maxOwnerBytes: initialRaw.length + 8,
    maxTotalBytes: initialRaw.length + 8,
  });
  t.after(() => {
    store.close();
    fs.rmSync(path.dirname(file), { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const initial = await store.append({
    owner: "alice", manifestBytes: initialRaw,
    expectedRevision: 0, expectedDigest: null,
  });
  await assert.rejects(store.append({
    owner: "bob", manifestBytes: initialRaw,
    expectedRevision: 0, expectedDigest: null,
  }), /ZK1_HISTORY_LIMIT/, "another owner must not open unlimited signed-history scopes");
  await assert.rejects(store.append({
    owner: "alice", manifestBytes: await encoded(state.headManifest),
    expectedRevision: 1, expectedDigest: initial.digest,
  }), /ZK1_HISTORY_LIMIT/, "owner bytes must include all retained immutable history");
  assert.equal(store.snapshot(scope(state)).revision, 1,
    "quota rejection must not partially change the previous signed history");
});
