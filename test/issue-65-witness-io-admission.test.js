"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const z = require("../src/crypto/rootark-zk-1");
const { Zk1DurableWitnessLedger } = require("../src/services/zk1DurableWitnessLedger");

const STATUS_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-cas-status/v1\0", "ascii");

async function setup(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-witness-admit-"));
  const instances = [];
  t.after(() => {
    for (const entry of instances) entry.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const witnessKeys = crypto.generateKeyPairSync("ed25519");
  const statusKeys = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const statusKeyId = crypto.randomBytes(16);
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("isolated-lab"), keyring_id: crypto.randomBytes(16) };
  const digest = crypto.randomBytes(32);
  const initial = {
    ...scope, reservation_id: crypto.randomBytes(16), operation_id: crypto.randomBytes(16),
    expected_revision: null, expected_manifest_digest: null,
    proposed_revision: 1, proposed_manifest_digest: digest,
    request_digest: crypto.randomBytes(32), package_envelope_digest: null, expires_at: 1000,
  };
  const statusProvider = { async getTerminalProof({ query, nonce }) {
    const unsigned = { type: "rootark-recovery-cas-status/v1",
      status_authority_key_id: statusKeyId, ...query,
      observed_revision: query.proposed_revision,
      observed_manifest_digest: query.proposed_manifest_digest,
      terminal_status: "committed", observed_at: 900, nonce };
    const signature = crypto.sign(null, Buffer.concat([STATUS_DOMAIN,
      Buffer.from(await z.encodeDeterministic(unsigned))]), statusKeys.privateKey);
    return Buffer.from(await z.encodeDeterministic({ ...unsigned, signature }));
  } };
  const filename = path.join(dir, "witness.sqlite");
  let clockNow = 900;
  const options = { bootstrapNew: true, witnessKeyId,
    witnessPrivateKey: witnessKeys.privateKey,
    statusPinned: { keyId: statusKeyId, publicKey: statusKeys.publicKey },
    statusProvider, nowSeconds: () => clockNow };
  const reopen = () => {
    const instance = new Zk1DurableWitnessLedger(filename,
      { ...options, bootstrapNew: !fs.existsSync(filename) });
    instances.push(instance);
    return instance;
  };
  const ledger = reopen();
  await ledger.reserve(initial);
  await ledger.resolve({ scope });
  const next = { ...initial, reservation_id: crypto.randomBytes(16),
    operation_id: crypto.randomBytes(16), expected_revision: 1,
    expected_manifest_digest: digest, proposed_revision: 2,
    proposed_manifest_digest: crypto.randomBytes(32),
    request_digest: crypto.randomBytes(32) };
  return { ledger, reopen, scope, digest, next, setNow(value) { clockNow = value; } };
}

test("durable I/O admission refuses concurrent revocation until the authenticated worker finishes", async (t) => {
  const f = await setup(t);
  const workerId = crypto.randomBytes(16);
  const principal = "AA:".repeat(31) + "AA";
  const request = { scope: f.scope, revision: 1, digest: f.digest,
    action: "get", objectId: crypto.randomBytes(16).toString("base64url"),
    workerId, principal };
  const admission = await f.ledger.beginIoAdmission(request);
  assert.equal(Buffer.from(admission.admissionId).length, 16);
  assert.deepEqual(await f.ledger.beginIoAdmission(request), admission,
    "lost start ACK returns the exact admission, never another worker");
  await assert.rejects(f.ledger.reserve(f.next), /WITNESS_IO_ACTIVE/);
  await assert.rejects(f.ledger.finishIoAdmission({ scope: f.scope,
    admissionId: admission.admissionId, workerId,
    principal: "BB:".repeat(31) + "BB" }), /WITNESS_IO_DENIED/);
  await assert.rejects(f.ledger.beginIoAdmission({ ...request,
    action: "put" }), /WITNESS_IO_DENIED/);
  f.ledger.close();
  const restored = f.reopen();
  await assert.rejects(restored.reserve(f.next), /WITNESS_IO_ACTIVE/,
    "process restart cannot erase a live worker fence");
  assert.deepEqual(await restored.finishIoAdmission({ scope: f.scope,
    admissionId: admission.admissionId, workerId, principal }),
  { status: "completed" });
  assert.deepEqual(await restored.finishIoAdmission({ scope: f.scope,
    admissionId: admission.admissionId, workerId, principal }),
  { status: "completed" }, "lost finish ACK can retry safely");
  await assert.rejects(restored.beginIoAdmission(request), /WITNESS_IO_DENIED/,
    "old worker ID cannot be used for a second admission");
  await restored.reserve(f.next);
  await assert.rejects(restored.beginIoAdmission({ ...request,
    workerId: crypto.randomBytes(16) }), /WITNESS_IO_DENIED/,
    "pending revocation blocks every new admission");
});

test("I/O admission checks exact current head and cannot be replayed under another object or scope", async (t) => {
  const f = await setup(t);
  const principal = "CC:".repeat(31) + "CC";
  const request = { scope: f.scope, revision: 1, digest: f.digest,
    action: "put", objectId: crypto.randomBytes(16).toString("base64url"),
    workerId: crypto.randomBytes(16), principal };
  await assert.rejects(f.ledger.beginIoAdmission({ ...request,
    digest: crypto.randomBytes(32) }), /WITNESS_IO_DENIED/);
  await assert.rejects(f.ledger.beginIoAdmission({ ...request,
    revision: 2 }), /WITNESS_IO_DENIED/);
  const admission = await f.ledger.beginIoAdmission(request);
  await assert.rejects(f.ledger.beginIoAdmission({ ...request,
    objectId: crypto.randomBytes(16).toString("base64url") }), /WITNESS_IO_DENIED/);
  await assert.rejects(f.ledger.finishIoAdmission({ scope: f.scope,
    admissionId: admission.admissionId, workerId: crypto.randomBytes(16),
    principal }), /WITNESS_IO_DENIED/);
  await f.ledger.finishIoAdmission({ scope: f.scope,
    admissionId: admission.admissionId, workerId: request.workerId, principal });
});

test("QUIESCING is durable, denies fresh heads and admissions, then exact drain resumes reservation", async (t) => {
  const f = await setup(t);
  const principal = "AA:".repeat(31) + "AA";
  const request = { scope: f.scope, revision: 1, digest: f.digest,
    action: "get", objectId: crypto.randomBytes(16).toString("base64url"),
    workerId: crypto.randomBytes(16), principal };
  const admitted = await f.ledger.beginIoAdmission(request);
  const initial = await z.decodeDeterministic(await f.ledger.freshHead({
    scope: f.scope, nonce: crypto.randomBytes(32) }));
  assert.equal(initial.status, "committed");
  assert.deepEqual(await f.ledger.prepareQuiesce(f.next),
    { status: "QUIESCING", activeCount: 1 });
  assert.deepEqual(await f.ledger.prepareQuiesce(f.next),
    { status: "QUIESCING", activeCount: 1 }, "duplicate start must be idempotent");
  await assert.rejects(f.ledger.freshHead({ scope: f.scope, nonce: crypto.randomBytes(32) }),
    /WITNESS_QUIESCING/, "fresh old heads cannot be issued after quiescence");
  await assert.rejects(f.ledger.beginIoAdmission({ ...request,
    workerId: crypto.randomBytes(16) }), /WITNESS_IO_DENIED/);
  const unrelated = { ...f.next, operation_id: crypto.randomBytes(16) };
  await assert.rejects(f.ledger.prepareQuiesce(unrelated), /WITNESS_QUIESCING/);
  await assert.rejects(f.ledger.reserve(unrelated), /WITNESS_QUIESCING/);
  await assert.rejects(f.ledger.reserve(f.next), /WITNESS_IO_ACTIVE/);
  f.ledger.close();
  const restarted = f.reopen();
  await assert.rejects(restarted.freshHead({ scope: f.scope, nonce: crypto.randomBytes(32) }),
    /WITNESS_QUIESCING/, "crash/restart must not reopen the old committed head");
  await restarted.finishIoAdmission({ scope: f.scope, admissionId: admitted.admissionId,
    workerId: request.workerId, principal });
  await assert.rejects(restarted.beginIoAdmission({ ...request,
    workerId: crypto.randomBytes(16) }), /WITNESS_IO_DENIED/,
  "no new worker may enter between the last completion and durable reservation");
  assert.deepEqual(await restarted.prepareQuiesce(f.next),
    { status: "DRAINED", activeCount: 0 });
  const ticket = await restarted.reserve(f.next);
  assert.ok(ticket.length > 64);
  const pending = await z.decodeDeterministic(await restarted.freshHead({
    scope: f.scope, nonce: crypto.randomBytes(32) }));
  assert.equal(pending.status, "pending");
});

test("DRAINED from zero active workers closes the gate before a new worker can race reserve", async (t) => {
  const f = await setup(t);
  assert.deepEqual(await f.ledger.prepareQuiesce(f.next),
    { status: "DRAINED", activeCount: 0 });
  await assert.rejects(f.ledger.freshHead({ scope: f.scope, nonce: crypto.randomBytes(32) }),
    /WITNESS_QUIESCING/);
  await assert.rejects(f.ledger.beginIoAdmission({ scope: f.scope,
    revision: 1, digest: f.digest, action: "put",
    objectId: crypto.randomBytes(16).toString("base64url"),
    workerId: crypto.randomBytes(16), principal: "CC:".repeat(31) + "CC" }),
  /WITNESS_IO_DENIED/);
  await f.ledger.reserve(f.next);
  const receipt = await z.decodeDeterministic(await f.ledger.freshHead({
    scope: f.scope, nonce: crypto.randomBytes(32) }));
  assert.equal(receipt.status, "pending");
});

test("a concurrent QUIESCING write invalidates a committed head even after its signature was computed", async (t) => {
  const f = await setup(t);
  const signed = f.ledger.sign.bind(f.ledger);
  let injected = 0;
  f.ledger.sign = async (data, domain) => {
    const wire = await signed(data, domain);
    if (data.type === "rootark-recovery-witness-head/v1") {
      injected += 1;
      assert.equal((await f.ledger.prepareQuiesce(f.next)).status, "DRAINED");
    }
    return wire;
  };
  await assert.rejects(f.ledger.freshHead({ scope: f.scope, nonce: crypto.randomBytes(32) }),
    /WITNESS_QUIESCING/);
  assert.equal(injected, 1, "quiescence must race exactly between signature and final SQLite check");
});

test("expired pre-ticket quiescence requires explicit exact-op cancellation after 30s skew, surviving restart", async (t) => {
  const f = await setup(t);
  await assert.rejects(f.ledger.cancelExpiredQuiesce(f.next), /WITNESS_QUIESCING/);
  assert.equal((await f.ledger.prepareQuiesce(f.next)).status, "DRAINED");
  f.setNow(1029);
  await assert.rejects(f.ledger.cancelExpiredQuiesce(f.next), /WITNESS_QUIESCE_NOT_EXPIRED/);
  f.setNow(1030);
  await assert.rejects(f.ledger.cancelExpiredQuiesce({ ...f.next,
    operation_id: crypto.randomBytes(16) }), /WITNESS_QUIESCING/,
  "an unrelated operation must never release the frozen gate");
  f.ledger.close();
  const restarted = f.reopen();
  assert.deepEqual(await restarted.cancelExpiredQuiesce(f.next),
    { status: "ABORTED_EXPIRED" });
  f.setNow(900);
  await assert.rejects(restarted.reserve(f.next), /WITNESS_CLOCK_ROLLBACK/,
    "clock rollback must not revive an expired, explicitly canceled ticket");
  await assert.rejects(restarted.freshHead({ scope: f.scope,
    nonce: crypto.randomBytes(32) }), /WITNESS_CLOCK_ROLLBACK/);
  f.setNow(1030);
  const opened = await z.decodeDeterministic(await restarted.freshHead({
    scope: f.scope, nonce: crypto.randomBytes(32) }));
  assert.equal(opened.status, "committed");
  assert.equal(opened.current_revision, 1);
  const replacement = { ...f.next, reservation_id: crypto.randomBytes(16),
    operation_id: crypto.randomBytes(16), expires_at: 1200 };
  assert.ok((await restarted.reserve(replacement)).length > 64,
    "a fresh exact operation can reserve after verified expiry cancellation");
});

test("expired QUIESCING cannot clear active I/O or reissue head until the exact worker finishes", async (t) => {
  const f = await setup(t);
  const principal = "AA:".repeat(31) + "AA";
  const request = { scope: f.scope, revision: 1, digest: f.digest,
    action: "get", objectId: crypto.randomBytes(16).toString("base64url"),
    workerId: crypto.randomBytes(16), principal };
  const admission = await f.ledger.beginIoAdmission(request);
  assert.equal((await f.ledger.prepareQuiesce(f.next)).status, "QUIESCING");
  f.setNow(1030);
  await assert.rejects(f.ledger.cancelExpiredQuiesce(f.next), /WITNESS_IO_ACTIVE/);
  await assert.rejects(f.ledger.freshHead({ scope: f.scope, nonce: crypto.randomBytes(32) }),
    /WITNESS_QUIESCING/);
  await f.ledger.finishIoAdmission({ scope: f.scope,
    admissionId: admission.admissionId, workerId: request.workerId, principal });
  assert.deepEqual(await f.ledger.cancelExpiredQuiesce(f.next),
    { status: "ABORTED_EXPIRED" });
});

test("lost START ACK retry during QUIESCING recovers the same admission for safe stop, never a new I/O permit", async (t) => {
  const f = await setup(t);
  const principal = "AA:".repeat(31) + "AA";
  const request = { scope: f.scope, revision: 1, digest: f.digest, action: "get",
    objectId: crypto.randomBytes(16).toString("base64url"),
    workerId: crypto.randomBytes(16), principal };
  const first = await f.ledger.beginIoAdmission(request);
  assert.equal(first.proceed, true);
  assert.equal((await f.ledger.prepareQuiesce(f.next)).status, "QUIESCING");
  const replay = await f.ledger.beginIoAdmission(request);
  assert.deepEqual(replay, { admissionId: first.admissionId, proceed: false },
    "post-quiescence retry identifies only its original worker and must not start new I/O");
  await assert.rejects(f.ledger.beginIoAdmission({ ...request,
    workerId: crypto.randomBytes(16) }), /WITNESS_IO_DENIED/);
  await f.ledger.finishIoAdmission({ scope: f.scope,
    admissionId: replay.admissionId, workerId: request.workerId, principal });
  assert.ok((await f.ledger.reserve(f.next)).length > 64);
});
