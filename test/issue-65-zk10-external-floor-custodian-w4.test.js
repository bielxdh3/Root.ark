"use strict";

// All signers and SQLite files are disposable. This does not prove off-host custody.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
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
