"use strict";
// Signed wire vectors only. No authority server, off-host witness, or production grant.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const { signOwnerCutover, digestOwnerCutover, buildSparseEnrollmentProof } =
  require("../src/crypto/rootark-zk10-account-cutover-v1");
const { createZk10ExternalOwnerCutoverCasClient } =
  require("../src/services/zk10ExternalOwnerCutoverCasClient");

const HEAD_DOMAIN = Buffer.from("Root.ark/zk10/operator-account-head/v1\0");
const CURRENT_DOMAIN = Buffer.from("Root.ark/zk10/operator-account-current/v1\0");
const RECEIPT_DOMAIN = Buffer.from("Root.ark/zk10/operator-cutover-receipt/v1\0");
const READBACK_DOMAIN = Buffer.from("Root.ark/zk10/operator-cutover-readback/v1\0");
const hash = (s) => crypto.createHash("sha256").update(s).digest("hex");
const uuid = (n) => Buffer.alloc(16, n).toString("base64url");
const signature = (domain, payload, key) => crypto.sign(null,
  Buffer.concat([domain, Buffer.from(JSON.stringify(payload))]), key).toString("base64url");
const signed = (domain, payload, privateKey) => ({
  ...payload, signature: signature(domain, payload, privateKey),
});
const headDigest = (wire) => {
  const { signature: sig, ...payload } = wire;
  return crypto.createHash("sha256").update(HEAD_DOMAIN)
    .update(JSON.stringify(payload)).update(Buffer.from(sig, "base64url")).digest("hex");
};
const FP = Array(32).fill("AB").join(":");
const OP = "operator-custodian-a";
const now = () => Date.now();

function scenario() {
  const owner = crypto.generateKeyPairSync("ed25519");
  const operator = crypto.generateKeyPairSync("ed25519");
  const accountId = uuid(1), zkAccountId = uuid(2), identityDigest = hash("immutable-bound-identity");
  const empty = buildSparseEnrollmentProof([], accountId);
  const ownerStatement = signOwnerCutover({
    type: "rootark-zk10-owner-account-cutover/v1",
    immutable_account_id: accountId, zk_account_id: zkAccountId,
    generation: 1, previous_cutover_digest: null,
    inventory_head: hash("verified-external-inventory-unproven-in-test"),
    complete_corpus: true, covered_compartments: [uuid(3)],
    legacy_egress_scope: "all", reference_disposition: "fully_accounted",
    migration_disposition: "closed", grant: "protected_enforced", grants: [],
    suite: "zk1-v2", nonce: crypto.randomBytes(32).toString("base64url"),
    issued_at: Math.floor(now() / 1000),
  }, owner.privateKey);
  const ownerDigest = digestOwnerCutover(ownerStatement);
  const enrolled = buildSparseEnrollmentProof([{ accountId, cutoverDigest: ownerDigest }], accountId);
  const head = (sequence, previousHeadDigest, root, physicalDigest, everEnrolled, ownerGeneration, ownerCutoverDigest) =>
    signed(HEAD_DOMAIN, {
      type: "rootark-zk10-operator-account-head/v1", operator_id: OP,
      immutable_account_id: accountId, sequence, previous_head_digest: previousHeadDigest,
      enrollment_root: root, physical_digest: physicalDigest, ever_enrolled: everEnrolled,
      owner_generation: ownerGeneration, owner_cutover_digest: ownerCutoverDigest,
    }, operator.privateKey);
  const before = head(1, "0".repeat(64), empty.root, hash("PG18-physical-prev"), false, 0, null);
  const beforeDigest = headDigest(before);
  const after = head(2, beforeDigest, enrolled.root, hash("PG18-physical-next"), true, 1, ownerDigest);
  const afterDigest = headDigest(after);
  const minimum = Object.freeze({
    sequence: 1, headDigest: beforeDigest, enrollmentRoot: empty.root,
    physicalDigest: hash("PG18-physical-prev"), everEnrolled: false,
    ownerGeneration: 0, ownerCutoverDigest: null,
  });
  let phase = "before";
  let commitCount = 0, currentCount = 0, readbackCount = 0, casRequest = null;
  let outcome = "lost-ack";
  let mutateCurrent = (x) => x;
  let mutateReadback = (x) => x;
  const transport = {
    operatorHostId: OP, tlsServerFingerprint256: FP,
    async exchange(path, request) {
      if (path === "/v1/zk10/current") {
        currentCount++;
        const advanced = phase !== "before";
        const h = advanced ? after : before;
        const proof = advanced ? enrolled : empty;
        const c = {
          type: "rootark-zk10-operator-account-current/v1", operator_id: OP,
          immutable_account_id: accountId, identity_digest: identityDigest,
          head_sequence: advanced ? 2 : 1, head_digest: headDigest(h),
          enrollment_root: proof.root, physical_digest: h.physical_digest,
          ever_enrolled: advanced, status: advanced ? "protected_enforced" : "never_enrolled",
          owner_generation: advanced ? 1 : 0,
          owner_cutover_digest: advanced ? ownerDigest : null,
          owner_statement: advanced ? ownerStatement : null,
          siblings: proof.siblings,
          challenge: request.challenge,
          issued_at_ms: now(), expires_at_ms: now() + 8000,
        };
        const changed = mutateCurrent(c);
        // Fixture signer is intentionally local ephemeral test-only key material.
        return { head_chain: advanced ? [after] : [],
          current: signed(CURRENT_DOMAIN, changed, operator.privateKey) };
      }
      if (path === "/v1/zk10/cutover/readback") {
        readbackCount++;
        const p = {
          type: "rootark-zk10-operator-cutover-readback/v1", operator_id: OP,
          immutable_account_id: accountId, identity_digest: identityDigest,
          lease_id: casRequest?.lease_id ?? request.lease_id,
          fencing_epoch: casRequest?.fencing_epoch ?? request.fencing_epoch,
          owner_cutover_digest: ownerDigest,
          expected_head_digest: beforeDigest,
          lease_expires_at_ms: casRequest?.lease_expires_at_ms ?? request.lease_expires_at_ms,
          observed_head_digest: afterDigest,
          observed_physical_digest: after.physical_digest,
          challenge: request.challenge, decision: "committed",
        };
        return { readback: signed(READBACK_DOMAIN, mutateReadback(p), operator.privateKey) };
      }
      if (path === "/v1/zk10/cutover/cas") {
        commitCount++;
        casRequest = request;
        if (outcome === "lost-ack") {
          phase = "after";
          throw Error("DISPOSABLE_TRANSPORT_ACK_LOST");
        }
        if (outcome === "partial") return { partial: "unknown" };
        phase = "after";
        const receipt = signed(RECEIPT_DOMAIN, {
          type: "rootark-zk10-operator-cutover-receipt/v1", operator_id: OP,
          immutable_account_id: accountId, owner_cutover_digest: ownerDigest,
          expected_sequence: 1, expected_head_digest: beforeDigest,
          lease_id: request.lease_id, fencing_epoch: request.fencing_epoch,
          lease_expires_at_ms: request.lease_expires_at_ms,
          challenge: request.challenge, status: "committed",
        }, operator.privateKey);
        return { receipt };
      }
      throw Error("UNEXPECTED_ROUTE");
    },
  };
  const client = (options = {}) => createZk10ExternalOwnerCutoverCasClient({
    immutableAccountId: accountId, identityDigest,
    pinnedOperator: { operatorId: OP, tlsServerFingerprint256: FP,
      signingPublicKey: operator.publicKey },
    pinnedOwner: { canonicalZkAccountId: zkAccountId, signingPublicKey: owner.publicKey },
    independentlyRetainedMinimum: minimum, transport,
    ...options,
  });
  return { client, transport, accountId, owner, operator, ownerStatement, ownerDigest,
    minimum, before, after, afterDigest, empty, enrolled, get commitCount() { return commitCount; },
    get currentCount() { return currentCount; },
    get readbackCount() { return readbackCount; },
    set phase(v) { phase = v; }, set outcome(v) { outcome = v; },
    set mutateCurrent(v) { mutateCurrent = v; },
    set mutateReadback(v) { mutateReadback = v; } };
}
const lease = () => ({
  leaseId: crypto.randomBytes(16).toString("base64url"),
  fencingEpoch: 7, leaseExpiresAtMs: now() + 8000,
});

test("lost CAS acknowledgment quarantines; nonce-signed CURRENT reconciliation is nonauthorizing and no auto-retry", async () => {
  const s = scenario(), c = s.client();
  assert.equal(c.authorizesProductionCutover, false);
  assert.equal((await c.readCurrent()).status, "never_enrolled");
  await assert.rejects(c.submitCutover({ ownerStatement: s.ownerStatement, ...lease() }),
    /ZK10_EXTERNAL_CAS_UNCERTAIN/);
  assert.equal(c.state, "uncertain");
  assert.equal(s.commitCount, 1);
  await assert.rejects(c.submitCutover({ ownerStatement: s.ownerStatement, ...lease() }),
    /ZK10_EXTERNAL_CAS_UNCERTAIN/);
  assert.equal(s.commitCount, 1, "never auto-retry a potentially committed CAS");
  const result = await c.reconcile();
  assert.equal(result.state, "observed_protected");
  assert.equal(result.authorizesProductionCutover, false);
  assert.equal(c.state, "observed_protected");
  assert.equal(s.commitCount, 1);
  assert.equal(s.readbackCount, 1, "must prove exact operation lease/epoch against signed successor HEAD");
});

test("signed replayed challenge, account swap and identity swap fail before an allow", async () => {
  for (const changed of [
    (p) => ({ ...p, challenge: crypto.randomBytes(32).toString("base64url") }),
    (p) => ({ ...p, immutable_account_id: uuid(9) }),
    (p) => ({ ...p, identity_digest: hash("another account") }),
  ]) {
    const s = scenario(); s.mutateCurrent = changed;
    await assert.rejects(s.client().readCurrent(), /ZK10_EXTERNAL_CAS_UNAVAILABLE/);
    assert.equal(s.commitCount, 0);
  }
});

test("same-sequence fork cannot erase pinned minimum even with operator signature", async () => {
  const s = scenario();
  const different = { ...s.minimum, headDigest: hash("fork-with-same-seq") };
  await assert.rejects(s.client({ independentlyRetainedMinimum: different }).submitCutover(
    { ownerStatement: s.ownerStatement, ...lease() }), /ZK10_EXTERNAL_CAS_UNAVAILABLE/);
  await assert.rejects(s.client({ independentlyRetainedMinimum: different }).readCurrent(),
    /ZK10_EXTERNAL_CAS_UNAVAILABLE/);
});

test("stale or substituted owner signer, account and generation cannot submit CAS", async () => {
  const s = scenario();
  const untrusted = crypto.generateKeyPairSync("ed25519");
  const wrongSigner = s.client({ pinnedOwner: { canonicalZkAccountId: uuid(2),
    signingPublicKey: untrusted.publicKey } });
  await assert.rejects(wrongSigner.submitCutover({ ownerStatement: s.ownerStatement, ...lease() }),
    /ZK10_EXTERNAL_CAS_UNAVAILABLE/);
  const invalidOwner = { ...s.ownerStatement, generation: 2 };
  await assert.rejects(s.client().submitCutover({ ownerStatement: invalidOwner, ...lease() }),
    /ZK10_EXTERNAL_CAS_UNAVAILABLE/);
  await assert.rejects(s.client({ immutableAccountId: uuid(8) })
    .submitCutover({ ownerStatement: s.ownerStatement, ...lease() }),
  /ZK10_EXTERNAL_CAS_UNAVAILABLE/);
  assert.equal(s.commitCount, 0);
});

test("never-enrolled negative membership under rollback of protected minimum rejects", async () => {
  const s = scenario();
  const protectedMinimum = {
    sequence: 2, headDigest: s.afterDigest, enrollmentRoot: s.enrolled.root,
    physicalDigest: s.after.physical_digest, everEnrolled: true,
    ownerGeneration: 1, ownerCutoverDigest: s.ownerDigest,
  };
  await assert.rejects(s.client({ independentlyRetainedMinimum: protectedMinimum }).readCurrent(),
    /ZK10_EXTERNAL_CAS_UNAVAILABLE/, "old signed negative HEAD cannot override retained protected floor");
});

test("partial CAS response leaves quarantine without automatic retry or granted authority", async () => {
  const s = scenario(); s.outcome = "partial";
  const c = s.client();
  await assert.rejects(c.submitCutover({ ownerStatement: s.ownerStatement, ...lease() }),
    /ZK10_EXTERNAL_CAS_UNCERTAIN/);
  assert.equal(c.state, "uncertain");
  const r = await c.reconcile();
  assert.equal(r.state, "uncertain");
  assert.equal(r.authorizesProductionCutover, false);
  assert.equal(s.commitCount, 1);
});

test("wrong operator host identity pin, untrusted transport, and claimed production flags deny", () => {
  const s = scenario();
  assert.throws(() => s.client({ pinnedOperator: {
    operatorId: OP, tlsServerFingerprint256: Array(32).fill("CD").join(":"),
    signingPublicKey: s.operator.publicKey,
  } }), /ZK10_EXTERNAL_CAS_UNAVAILABLE/);
  assert.throws(() => s.client({ transport: { ...s.transport, operatorHostId: "another-host" } }),
    /ZK10_EXTERNAL_CAS_UNAVAILABLE/);
  assert.throws(() => s.client({ authorizesProductionCutover: true }),
    /ZK10_EXTERNAL_CAS_UNAVAILABLE/);
});

test("concurrent owner CAS calls cannot preflight the same generation twice", async () => {
  const s = scenario();
  const first = s.client();
  const requests = await Promise.allSettled([
    first.submitCutover({ ownerStatement: s.ownerStatement, ...lease() }),
    first.submitCutover({ ownerStatement: s.ownerStatement, ...lease() }),
  ]);
  assert.equal(requests.filter((x) => x.status === "fulfilled").length, 0);
  assert.equal(s.commitCount, 1, "only one potentially committed operation may leave this client");
  assert.equal(first.state, "uncertain");
});

test("expired lease after slow signed CURRENT preflight cannot issue physical CAS", async () => {
  const s = scenario();
  const native = s.transport.exchange.bind(s.transport);
  s.transport.exchange = async (path, req) => {
    if (path === "/v1/zk10/current")
      await new Promise((resolve) => setTimeout(resolve, 170));
    return native(path, req);
  };
  const c = s.client();
  await assert.rejects(c.submitCutover({
    ownerStatement: s.ownerStatement,
    ...lease(),
    leaseExpiresAtMs: now() + 120,
  }), /ZK10_EXTERNAL_CAS_UNAVAILABLE/);
  assert.equal(s.commitCount, 0, "expired/fenced lease cannot reach the operator CAS");
  assert.equal(c.state, "idle", "no remote commit was attempted during failed preflight");
});

test("positive signed transport receipt is only a hint; separate signed CURRENT readback remains mandatory", async () => {
  const s = scenario(); s.outcome = "signed-ack";
  const c = s.client();
  const ack = await c.submitCutover({ ownerStatement: s.ownerStatement, ...lease() });
  assert.equal(ack.state, "uncertain");
  assert.equal(ack.requiresReadback, true);
  assert.equal(ack.authorizesProductionCutover, false);
  assert.equal(c.state, "uncertain");
  const observed = await c.reconcile();
  assert.equal(observed.state, "observed_protected");
  assert.equal(observed.authorizesProductionCutover, false);
  assert.equal(s.readbackCount, 1);
});

test("operation readback cannot substitute another lease or replay an older signed challenge", async () => {
  for (const change of [
    (p) => ({ ...p, lease_id: uuid(9) }),
    (p) => ({ ...p, challenge: crypto.randomBytes(32).toString("base64url") }),
    (p) => ({ ...p, observed_physical_digest: hash("different physical admission") }),
    (p) => ({ ...p, lease_expires_at_ms: p.lease_expires_at_ms - 1000 }),
  ]) {
    const s = scenario();
    const c = s.client();
    await assert.rejects(c.submitCutover({ ownerStatement: s.ownerStatement, ...lease() }),
      /ZK10_EXTERNAL_CAS_UNCERTAIN/);
    s.mutateReadback = change;
    await assert.rejects(c.reconcile(), /ZK10_EXTERNAL_CAS_UNAVAILABLE/);
    assert.equal(c.state, "quarantined");
    assert.equal(s.commitCount, 1);
  }
});

test("legitimately signed but stale owner approval cannot be replayed months later", async () => {
  const s = scenario();
  const { signature: _unusedSignature, ...payload } = s.ownerStatement;
  const stale = signOwnerCutover({ ...payload, issued_at: Math.floor(now() / 1000) - 86400 },
    s.owner.privateKey);
  await assert.rejects(s.client().submitCutover({ ownerStatement: stale, ...lease() }),
    /ZK10_EXTERNAL_CAS_UNAVAILABLE/);
  assert.equal(s.commitCount, 0);
});
