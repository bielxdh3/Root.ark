"use strict";

// All signers and SQLite files are disposable. This does not prove off-host custody.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const Database = require("better-sqlite3");
const { fork } = require("node:child_process");
const { Worker } = require("node:worker_threads");
const { signatureBytes } = require("../src/crypto/rootark-zk10-account-cutover-v1");
const {
  createDevOffZk10MonotonicFloorCustodian,
} = require("../src/services/zk10DevOffMonotonicFloorCustodian");

const DOMAIN_GENESIS = Buffer.from("Root.ark/zk10/custodian-owner-genesis/v1\0");
const DOMAIN_LEASE = Buffer.from("Root.ark/zk10/custodian-owner-lease/v1\0");
const DOMAIN_FLOOR = Buffer.from("Root.ark/zk10/external-floor-current/v1\0");
const b64 = (buffer) => buffer.toString("base64url");
const id = (number) => b64(Buffer.alloc(16, number));
const sha = (number) => Buffer.alloc(32, number).toString("hex");
const keyHash = (key) => crypto.createHash("sha256")
  .update(key.export({ type: "spki", format: "der" })).digest("hex");
function sign(payload, signer, domain) {
  return { ...payload, signature: b64(crypto.sign(null, signatureBytes(domain, payload), signer)) };
}
function setup(t, suffix = "single") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk10-custodian-w4-"));
  const opened = [];
  t.after(() => {
    for (const custodian of opened) custodian.close();
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 4, retryDelay: 50 });
  });
  const owner = crypto.generateKeyPairSync("ed25519");
  const custodian = crypto.generateKeyPairSync("ed25519");
  const paths = { databasePath: path.join(root, suffix + ".sqlite"),
    anchorDatabasePath: path.join(root, suffix + "-external-minimum.sqlite") };
  const genesis = sign({ type: "rootark-zk10-custodian-owner-genesis/v1",
    sequence: 1, head_digest: sha(1), enrollment_root: sha(2),
    immutable_account_id: id(3), identity_digest: sha(4), lease_serial: 0 },
  owner.privateKey, DOMAIN_GENESIS);
  const config = { devOff: true, ...paths,
    ownerPublicKey: owner.publicKey,
    custodianPrivateKey: custodian.privateKey,
    custodianSpkiSha256: keyHash(custodian.publicKey), bootstrap: genesis };
  let serial = 0;
  function offer(overrides = {}) {
    const at = Date.now();
    const lease = { type: "rootark-zk10-custodian-owner-lease/v1",
      sequence: 1, head_digest: sha(1), enrollment_root: sha(2),
      immutable_account_id: id(3), identity_digest: sha(4),
      operation: "legacy:read", nonce: b64(crypto.randomBytes(32)),
      lease_id: b64(crypto.randomBytes(16)), lease_serial: ++serial,
      issued_at_ms: at, lease_expires_at_ms: at + 4000, ...overrides };
    const request = Object.fromEntries([
      "immutable_account_id", "identity_digest", "operation", "nonce",
      "lease_id", "lease_expires_at_ms"].map(k => [k, lease[k]]));
    return { request, ownerLease: sign(lease, owner.privateKey, DOMAIN_LEASE) };
  }
  return { root, owner, custodian, genesis, config, offer, paths,
    track: instance => { opened.push(instance); return instance; } };
}

test("opt-in, separately pinned Ed25519 signer and owner-signed genesis required before state creation", (t) => {
  const x = setup(t);
  for (const changes of [
    { devOff: false }, { custodianPrivateKey: undefined },
    { custodianSpkiSha256: sha(8) }, { ownerPublicKey: x.custodian.publicKey },
    { bootstrap: { ...x.genesis, signature: b64(Buffer.alloc(64)) } },
  ]) {
    assert.throws(() => createDevOffZk10MonotonicFloorCustodian({ ...x.config, ...changes }),
      /ZK10_CUSTODIAN_UNAVAILABLE/);
  }
  const previous = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = "production";
    assert.throws(() => createDevOffZk10MonotonicFloorCustodian(x.config),
      /ZK10_CUSTODIAN_UNAVAILABLE/);
  } finally {
    if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous;
  }
  assert.equal(fs.existsSync(x.paths.databasePath), false);
  assert.equal(fs.existsSync(x.paths.anchorDatabasePath), false);
});

test("two independent disposable custodians sign W170 exact floor bytes with distinct keys", (t) => {
  const a = setup(t, "first");
  const b = setup(t, "second");
  const ca = a.track(createDevOffZk10MonotonicFloorCustodian(a.config));
  const cb = b.track(createDevOffZk10MonotonicFloorCustodian(b.config));
  const { request, ownerLease } = a.offer();
  const result = ca.attest(request, ownerLease);
  assert.deepEqual(Object.keys(result), ["floor"]);
  const { signature, ...payload } = result.floor;
  assert.deepEqual(Object.keys(payload), [
    "type", "sequence", "head_digest", "enrollment_root", "immutable_account_id",
    "identity_digest", "operation", "nonce", "lease_id", "lease_expires_at_ms",
    "issued_at_ms", "expires_at_ms"]);
  assert.ok(crypto.verify(null, signatureBytes(DOMAIN_FLOOR, payload),
    a.custodian.publicKey, Buffer.from(signature, "base64url")));
  assert.equal(crypto.verify(null, signatureBytes(DOMAIN_FLOOR, payload),
    b.custodian.publicKey, Buffer.from(signature, "base64url")), false);
  const different = b.offer();
  const otherResult = cb.attest(different.request, different.ownerLease).floor;
  const { signature: otherSignature, ...otherPayload } = otherResult;
  assert.ok(crypto.verify(null, signatureBytes(DOMAIN_FLOOR, otherPayload),
    b.custodian.publicKey, Buffer.from(otherSignature, "base64url")));
  assert.equal(crypto.verify(null, signatureBytes(DOMAIN_FLOOR, otherPayload),
    a.custodian.publicKey, Buffer.from(otherSignature, "base64url")), false);
  assert.equal(ca.independentOffServerCustodyProven, false);
});

test("owner grants monotonic sequence/lease serial; stale/replayed/mismatched/forged heads fail closed", (t) => {
  const x = setup(t);
  const c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const first = x.offer();
  assert.ok(c.attest(first.request, first.ownerLease).floor.signature);
  for (const [request, ownerLease] of [
    [first.request, first.ownerLease],
    (() => { const a = x.offer({ lease_serial: 1 }); return [a.request, a.ownerLease]; })(),
    (() => { const a = x.offer({ sequence: 0 }); return [a.request, a.ownerLease]; })(),
    (() => { const a = x.offer({ head_digest: sha(9) }); return [a.request, a.ownerLease]; })(),
    (() => { const a = x.offer(); return [{ ...a.request, nonce: b64(crypto.randomBytes(32)) }, a.ownerLease]; })(),
    (() => { const a = x.offer({ lease_expires_at_ms: Date.now() - 1 }); return [a.request, a.ownerLease]; })(),
    (() => { const a = x.offer(); return [a.request, { ...a.ownerLease, signature: b64(Buffer.alloc(64)) }]; })(),
  ]) {
    assert.throws(() => c.attest(request, ownerLease), /ZK10_CUSTODIAN_UNAVAILABLE/);
  }
  assert.equal(c.retainedMinimum().lease_serial, 1);
  const advance = x.offer({ sequence: 2, head_digest: sha(5), enrollment_root: sha(6),
    lease_serial: 2 });
  assert.equal(c.attest(advance.request, advance.ownerLease).floor.sequence, 2);
  assert.equal(c.retainedMinimum().head_digest, sha(5));
  const reuseNonce = x.offer({ sequence: 2, head_digest: sha(5),
    enrollment_root: sha(6), lease_serial: 3, nonce: first.request.nonce });
  assert.throws(() => c.attest(reuseNonce.request, reuseNonce.ownerLease),
    /ZK10_CUSTODIAN_UNAVAILABLE/);
  const reuseLease = x.offer({ sequence: 2, head_digest: sha(5),
    enrollment_root: sha(6), lease_serial: 3, lease_id: first.request.lease_id });
  assert.throws(() => c.attest(reuseLease.request, reuseLease.ownerLease),
    /ZK10_CUSTODIAN_UNAVAILABLE/);
  assert.equal(c.retainedMinimum().lease_serial, 2,
    "used challenge must be rejected before high-water writes");
});

test("concurrent same lease signs once; high-water survives restart and catches rolled-back primary SQLite", (t) => {
  const x = setup(t);
  let c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const first = x.offer();
  const results = [() => c.attest(first.request, first.ownerLease),
    () => c.attest(first.request, first.ownerLease)].map(fn => {
    try { return { value: fn() }; } catch (e) { return { error: e.code }; }
  });
  assert.equal(results.filter(r => r.value).length, 1);
  assert.equal(results.filter(r => r.error === "ZK10_CUSTODIAN_UNAVAILABLE").length, 1);
  const backup = path.join(x.root, "earlier-primary.sqlite");
  fs.copyFileSync(x.paths.databasePath, backup);
  const second = x.offer({ sequence: 2, head_digest: sha(8), enrollment_root: sha(9) });
  assert.equal(c.attest(second.request, second.ownerLease).floor.sequence, 2);
  assert.equal(c.retainedMinimum().lease_serial, 2);
  c.close();
  c = x.track(createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined }));
  assert.equal(c.retainedMinimum().lease_serial, 2);
  c.close();
  fs.copyFileSync(backup, x.paths.databasePath);
  assert.throws(() => createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined }), /ZK10_CUSTODIAN_UNAVAILABLE/);
});

test("P2: retained minimum never reports an obsolete signed head after a second writer commits", (t) => {
  const x = setup(t, "cross-writer-retained");
  const observer = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const writer = x.track(createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined,
  }));
  assert.equal(observer.retainedMinimum().lease_serial, 0);
  const newer = x.offer({
    sequence: 2, head_digest: sha(15), enrollment_root: sha(16),
  });
  const issued = writer.attest(newer.request, newer.ownerLease).floor;
  assert.equal(issued.sequence, 2);
  assert.ok(crypto.verify(null, signatureBytes(DOMAIN_FLOOR, Object.fromEntries(
    Object.entries(issued).filter(([field]) => field !== "signature"))),
  x.custodian.publicKey, Buffer.from(issued.signature, "base64url")));
  assert.equal(writer.retainedMinimum().lease_serial, 1);
  // An old in-memory snapshot cannot be offered as a CURRENT retained floor
  // after another legitimate, owner-authorized writer advanced both journals.
  // In particular the obsolete sequence=1 is potentially pre-revocation.
  assert.throws(() => observer.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/);
  assert.throws(() => observer.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/,
    "once divergence is observed the old handle stays unavailable");
  observer.close();
  const refreshed = x.track(createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined,
  }));
  assert.equal(refreshed.retainedMinimum().lease_serial, 1);
  assert.equal(refreshed.retainedMinimum().head_digest, sha(15));
});

test("two genuinely parallel worker-thread SQLite handles cannot both attest the same signed lease", async (t) => {
  const x = setup(t);
  const first = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  first.close();
  const offer = x.offer();
  const workerPath = path.join(__dirname, "support/issue-65-zk10-floor-custodian-worker.js");
  const race = () => new Promise((resolve, reject) => {
    let answer;
    const worker = new Worker(workerPath, { workerData: {
      config: { ...x.config, bootstrap: undefined },
      request: offer.request, ownerLease: offer.ownerLease,
    } });
    worker.once("message", message => { answer = message; });
    worker.once("error", reject);
    worker.once("exit", code => {
      if (code !== 0 || !answer) reject(new Error("disposable worker did not finish"));
      else resolve(answer);
    });
  });
  const results = await Promise.all([race(), race()]);
  assert.equal(results.filter(item => item.signed).length, 1);
  assert.equal(results.filter(item => !item.signed).length, 1);
  const restarted = x.track(createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined }));
  assert.equal(restarted.retainedMinimum().lease_serial, 1);
});

test("erased independent anchor, mismatched key or incomplete bootstrap fails closed on restart", (t) => {
  const x = setup(t);
  const c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const first = x.offer();
  c.attest(first.request, first.ownerLease);
  c.close();
  const alternate = crypto.generateKeyPairSync("ed25519");
  assert.throws(() => createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined,
    custodianPrivateKey: alternate.privateKey,
    custodianSpkiSha256: keyHash(alternate.publicKey) }), /ZK10_CUSTODIAN_UNAVAILABLE/);
  fs.renameSync(x.paths.anchorDatabasePath, path.join(x.root, "missing-anchor.fixture"));
  assert.throws(() => createDevOffZk10MonotonicFloorCustodian(x.config),
    /ZK10_CUSTODIAN_UNAVAILABLE/);
});

test("P2 regression: deleting consumed nonce journal in primary alone fails closed on restart", (t) => {
  const x = setup(t, "deleted-primary-journal");
  const c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const initial = x.offer();
  c.attest(initial.request, initial.ownerLease);
  c.close();
  const db = new Database(x.paths.databasePath);
  try {
    assert.equal(db.prepare("SELECT COUNT(*) AS total FROM used_lease").get().total, 1);
    db.prepare("DELETE FROM used_lease").run();
  } finally { db.close(); }
  // Independent minimum retains the authentic high-water row. Omitting a
  // single consumed nonce must be detected before the next lease is signed.
  assert.throws(() => createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined }), /ZK10_CUSTODIAN_UNAVAILABLE/);
});

test("P2 regression: modified/reordered journal bytes fail closed with intact anchored count", (t) => {
  const x = setup(t, "edited-primary-journal");
  const c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const first = x.offer();
  c.attest(first.request, first.ownerLease);
  const second = x.offer();
  c.attest(second.request, second.ownerLease);
  c.close();
  const db = new Database(x.paths.databasePath);
  try {
    const rows = db.prepare("SELECT nonce, lease_id, lease_serial FROM used_lease ORDER BY lease_serial").all();
    assert.equal(rows.length, 2);
    // Mutating one consumed nonce while preserving the serial/count cannot
    // impersonate a valid historical chain or defeat the anchor commitment.
    db.prepare("UPDATE used_lease SET nonce = ? WHERE lease_serial = 1")
      .run(b64(crypto.randomBytes(32)));
  } finally { db.close(); }
  assert.throws(() => createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined }), /ZK10_CUSTODIAN_UNAVAILABLE/);
});

test("P2 regression: swapping serial order of two consumed leases cannot match original chain tip", (t) => {
  const x = setup(t, "reordered-primary-journal");
  const c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  for (let i = 0; i < 2; i += 1) {
    const offer = x.offer();
    c.attest(offer.request, offer.ownerLease);
  }
  c.close();
  const db = new Database(x.paths.databasePath);
  try {
    db.transaction(() => {
      db.prepare("UPDATE used_lease SET lease_serial = 3 WHERE lease_serial = 1").run();
      db.prepare("UPDATE used_lease SET lease_serial = 1 WHERE lease_serial = 2").run();
      db.prepare("UPDATE used_lease SET lease_serial = 2 WHERE lease_serial = 3").run();
    }).immediate();
    assert.deepEqual(db.prepare("SELECT lease_serial FROM used_lease ORDER BY lease_serial").all()
      .map(row => row.lease_serial), [1, 2]);
  } finally { db.close(); }
  assert.throws(() => createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined }), /ZK10_CUSTODIAN_UNAVAILABLE/);
});

test("P2 regression: two actual OS processes cannot both commit the same signed journal serial", async (t) => {
  const x = setup(t, "os-process-race");
  x.track(createDevOffZk10MonotonicFloorCustodian(x.config)).close();
  const signed = x.offer();
  const childPath = path.join(__dirname, "support/issue-65-zk10-floor-custodian-worker.js");
  function processRace() {
    const child = fork(childPath, [], {
      cwd: path.join(__dirname, ".."),
      env: { ...process.env, ROOTARK_ZK10_CUSTODIAN_PROCESS_FIXTURE: "1" },
      stdio: ["ignore", "ignore", "ignore", "ipc"],
    });
    t.after(() => { if (child.connected) child.kill(); });
    let readyResolve, readyReject, finishResolve, finishReject;
    let readySettled = false, finishSettled = false;
    const ready = new Promise((resolve, reject) => {
      readyResolve = resolve;
      readyReject = reject;
    });
    const finished = new Promise((resolve, reject) => {
      finishResolve = resolve;
      finishReject = reject;
    });
    child.on("message", (message) => {
      if (typeof message.ready === "boolean" && !readySettled) {
        readySettled = true;
        if (message.ready) readyResolve();
        else readyReject(new Error("disposable process refused to start"));
      }
      if (typeof message.signed === "boolean" && !finishSettled) {
        finishSettled = true;
        finishResolve(message.signed);
      }
    });
    child.once("error", (error) => {
      if (!readySettled) { readySettled = true; readyReject(error); }
      if (!finishSettled) { finishSettled = true; finishReject(error); }
    });
    child.once("exit", () => {
      if (!readySettled) { readySettled = true; readyReject(new Error("process exited before ready")); }
      if (!finishSettled) { finishSettled = true; finishReject(new Error("process exited before result")); }
    });
    child.send({
      kind: "init",
      config: { ...x.config, ownerPublicKey: undefined,
        custodianPrivateKey: undefined, bootstrap: undefined },
      ownerSpki: b64(x.owner.publicKey.export({ type: "spki", format: "der" })),
      custodianPkcs8: b64(x.custodian.privateKey.export({ type: "pkcs8", format: "der" })),
      request: signed.request, ownerLease: signed.ownerLease,
    });
    return { ready, finished, start: () => child.send({ kind: "sign" }) };
  }
  // Open the two independent SQLite handles before releasing the race gate.
  const first = processRace();
  await first.ready;
  const second = processRace();
  await second.ready;
  first.start();
  second.start();
  const results = await Promise.all([first.finished, second.finished]);
  assert.deepEqual(results.sort(), [false, true]);
  const restarted = x.track(createDevOffZk10MonotonicFloorCustodian({
    ...x.config, bootstrap: undefined }));
  assert.equal(restarted.retainedMinimum().journal_count, 1);
  assert.equal(restarted.retainedMinimum().lease_serial, 1);
});

test("P2 regression: dangling direct symlinks never redirect either SQLite store", (t) => {
  const x = setup(t, "dangling-link");
  const redirect = path.join(x.root, "outside-expected-anchor.sqlite");
  const anchor = x.paths.anchorDatabasePath;
  try {
    fs.symlinkSync(redirect, anchor, "file");
  } catch (error) {
    if (process.platform === "win32" && ["EPERM", "EACCES"].includes(error.code)) {
      t.skip("Windows symlink privileges unavailable; POSIX/WSL test is mandatory");
      return;
    }
    throw error;
  }
  assert.equal(fs.existsSync(anchor), false, "dangling link is invisible to existsSync");
  assert.ok(fs.lstatSync(anchor).isSymbolicLink());
  assert.throws(() => createDevOffZk10MonotonicFloorCustodian(x.config),
    /ZK10_CUSTODIAN_UNAVAILABLE/);
  assert.equal(fs.existsSync(redirect), false, "SQLite must not follow the hostile link");
  assert.equal(fs.existsSync(x.paths.databasePath), false,
    "failure must happen before any DB is created");
});

test("P2 regression: an existing parent symlink is refused without creating database", (t) => {
  const x = setup(t, "symlink-parent");
  const realDir = path.join(x.root, "real");
  fs.mkdirSync(realDir);
  const linkDir = path.join(x.root, "alias");
  try {
    fs.symlinkSync(realDir, linkDir, process.platform === "win32" ? "junction" : "dir");
  } catch (error) {
    if (process.platform === "win32" && ["EPERM", "EACCES"].includes(error.code)) {
      t.skip("Windows junction privileges unavailable; POSIX/WSL test is mandatory");
      return;
    }
    throw error;
  }
  const aliasDb = path.join(linkDir, "hidden.sqlite");
  assert.throws(() => createDevOffZk10MonotonicFloorCustodian({
    ...x.config, anchorDatabasePath: aliasDb }), /ZK10_CUSTODIAN_UNAVAILABLE/);
  assert.equal(fs.existsSync(path.join(realDir, "hidden.sqlite")), false);
  assert.equal(fs.existsSync(x.paths.databasePath), false);
});

for (const store of ["databasePath", "anchorDatabasePath"]) {
  test(`P1: ${store} swapped for another inode during signed lease verification never attests`, (t) => {
    if (process.platform === "win32") return t.skip("POSIX rename of open SQLite inode required");
    const x = setup(t, `swapped-${store}`);
    const c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
    const challenge = x.offer();
    const original = x.paths[store];
    const oldInode = path.join(x.root, `orphan-${store}.sqlite`);
    const substituted = path.join(x.root, `foreign-${store}.sqlite`);
    fs.copyFileSync(original, substituted);
    const verify = crypto.verify;
    const transaction = Database.prototype.transaction;
    let swapped = false;
    let attemptedWrites = 0;
    Database.prototype.transaction = function (...args) {
      attemptedWrites += 1;
      return transaction.apply(this, args);
    };
    crypto.verify = (...args) => {
      const valid = verify(...args);
      if (valid && !swapped) {
        swapped = true;
        fs.renameSync(original, oldInode);
        fs.renameSync(substituted, original);
      }
      return valid;
    };
    try {
      assert.throws(() => c.attest(challenge.request, challenge.ownerLease),
        /ZK10_CUSTODIAN_UNAVAILABLE/);
    } finally {
      crypto.verify = verify;
      Database.prototype.transaction = transaction;
    }
    assert.equal(swapped, true, "real replacement occurs after owner lease verification");
    assert.equal(attemptedWrites, 0, "identity mismatch must deny before any SQLite write transaction");
    assert.notEqual(fs.statSync(original).ino, fs.statSync(oldInode).ino);
    assert.equal(c.independentOffServerCustodyProven, false);
    assert.throws(() => c.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/,
      "a detected path replacement permanently invalidates this handle");
    const actual = new Database(oldInode, { readonly: true, fileMustExist: true });
    try { assert.equal(actual.prepare("SELECT lease_serial FROM floor").get().lease_serial, 0); }
    finally { actual.close(); }
  });
}

test("P1 POSIX: symlinked primary during lease verification is rejected before signing", (t) => {
  if (process.platform === "win32") return t.skip("POSIX symlink after opened SQLite handle required");
  const x = setup(t, "lease-symlink");
  const c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const challenge = x.offer();
  const previous = path.join(x.root, "orphan-primary.sqlite");
  const original = x.paths.databasePath;
  const verify = crypto.verify;
  let swapped = false;
  crypto.verify = (...args) => {
    const valid = verify(...args);
    if (valid && !swapped) {
      swapped = true;
      fs.renameSync(original, previous);
      fs.symlinkSync(x.paths.anchorDatabasePath, original);
    }
    return valid;
  };
  try {
    assert.throws(() => c.attest(challenge.request, challenge.ownerLease),
      /ZK10_CUSTODIAN_UNAVAILABLE/);
  } finally { crypto.verify = verify; }
  assert.equal(swapped, true);
  assert.equal(fs.lstatSync(original).isSymbolicLink(), true);
  assert.throws(() => c.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/);
});

test("P1 POSIX: anchor switched inside signer callback cannot return a signed attestation", (t) => {
  if (process.platform === "win32") return t.skip("POSIX rename of opened SQLite required");
  const x = setup(t, "sign-time-anchor-swap");
  const c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const challenge = x.offer();
  const original = x.paths.anchorDatabasePath;
  const previous = path.join(x.root, "orphan-anchor.sqlite");
  const signFloor = crypto.sign;
  let swapped = false;
  crypto.sign = (...args) => {
    const signature = signFloor(...args);
    if (!swapped) {
      swapped = true;
      fs.renameSync(original, previous);
      fs.symlinkSync(x.paths.databasePath, original);
    }
    return signature;
  };
  try {
    assert.throws(() => c.attest(challenge.request, challenge.ownerLease),
      /ZK10_CUSTODIAN_UNAVAILABLE/);
  } finally { crypto.sign = signFloor; }
  assert.equal(swapped, true);
  assert.equal(fs.lstatSync(original).isSymbolicLink(), true);
  assert.throws(() => c.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/,
    "ambiguous post-write commit must poison instance");
});

test("P1 Windows: simulated reparse during signed lease is rejected without another database open", (t) => {
  if (process.platform !== "win32") return t.skip("Windows path-validation regression");
  const x = setup(t, "win-reparse-late");
  const c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config));
  const challenge = x.offer();
  const lstat = fs.lstatSync;
  const open = fs.openSync;
  const verify = crypto.verify;
  let redirected = false;
  let openCalls = 0;
  fs.openSync = (...args) => {
    if (args[0] === x.paths.databasePath || args[0] === x.paths.anchorDatabasePath) openCalls += 1;
    return open(...args);
  };
  fs.lstatSync = (file, ...args) => {
    const stat = lstat(file, ...args);
    if (redirected && file === x.paths.anchorDatabasePath) {
      return new Proxy(stat, { get(target, field) {
        if (field === "isSymbolicLink") return () => true;
        const value = Reflect.get(target, field, target);
        return typeof value === "function" ? value.bind(target) : value;
      } });
    }
    return stat;
  };
  crypto.verify = (...args) => {
    const valid = verify(...args);
    if (valid) redirected = true;
    return valid;
  };
  try {
    assert.throws(() => c.attest(challenge.request, challenge.ownerLease),
      /ZK10_CUSTODIAN_UNAVAILABLE/);
  } finally {
    crypto.verify = verify;
    fs.lstatSync = lstat;
    fs.openSync = open;
  }
  assert.equal(redirected, true);
  assert.equal(openCalls, 0, "late reparse must be rejected without opening another path");
  assert.throws(() => c.retainedMinimum(), /ZK10_CUSTODIAN_UNAVAILABLE/,
    "observed fake reparse must permanently poison the affected pin");
});

test("P1: both SQLite identity descriptors remain pinned until close without leaking", (t) => {
  const x = setup(t, "live-fd-pins");
  const originalOpen = fs.openSync;
  const pins = new Map();
  fs.openSync = (...args) => {
    const fd = originalOpen(...args);
    if ([x.paths.databasePath, x.paths.anchorDatabasePath].includes(args[0])) pins.set(args[0], fd);
    return fd;
  };
  let c;
  try { c = x.track(createDevOffZk10MonotonicFloorCustodian(x.config)); }
  finally { fs.openSync = originalOpen; }
  assert.equal(pins.size, 2);
  for (const fd of pins.values()) assert.ok(fs.fstatSync(fd).isFile(), "pin stays open after bootstrap");
  const first = x.offer();
  assert.ok(c.attest(first.request, first.ownerLease).floor.signature);
  for (const fd of pins.values()) assert.ok(fs.fstatSync(fd).isFile(), "pin survives signed transaction");
  c.close();
  for (const fd of pins.values()) assert.throws(() => fs.fstatSync(fd), { code: "EBADF" });
  c.close();
});
