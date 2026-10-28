"use strict";

// DEV-OFF protocol client. There is deliberately NO authority/server, TLS
// service, key provisioning, PG adapter, application route, or production grant.
// Only an independently operated authority can make custody and CAS real.
const crypto = require("node:crypto");
const { verifyOwnerCutover, digestOwnerCutover, verifySparseEnrollmentProof } =
  require("../crypto/rootark-zk10-account-cutover-v1");

const HEAD_DOMAIN = Buffer.from("Root.ark/zk10/operator-account-head/v1\0");
const CURRENT_DOMAIN = Buffer.from("Root.ark/zk10/operator-account-current/v1\0");
const RECEIPT_DOMAIN = Buffer.from("Root.ark/zk10/operator-cutover-receipt/v1\0");
const READBACK_DOMAIN = Buffer.from("Root.ark/zk10/operator-cutover-readback/v1\0");
const HEAD_FIELDS = Object.freeze(["type", "operator_id", "immutable_account_id",
  "sequence", "previous_head_digest", "enrollment_root", "physical_digest",
  "ever_enrolled", "owner_generation", "owner_cutover_digest"]);
const CURRENT_FIELDS = Object.freeze(["type", "operator_id", "immutable_account_id",
  "identity_digest", "head_sequence", "head_digest", "enrollment_root",
  "physical_digest", "ever_enrolled", "status", "owner_generation",
  "owner_cutover_digest", "owner_statement", "siblings", "challenge",
  "issued_at_ms", "expires_at_ms"]);
const RECEIPT_FIELDS = Object.freeze(["type", "operator_id", "immutable_account_id",
  "owner_cutover_digest", "expected_sequence", "expected_head_digest",
  "lease_id", "fencing_epoch", "lease_expires_at_ms", "challenge", "status"]);
const READBACK_FIELDS = Object.freeze(["type", "operator_id", "immutable_account_id",
  "identity_digest", "lease_id", "fencing_epoch", "owner_cutover_digest",
  "expected_head_digest", "lease_expires_at_ms",
  "observed_head_digest", "observed_physical_digest",
  "challenge", "decision"]);
const MINIMUM_FIELDS = Object.freeze(["sequence", "headDigest", "enrollmentRoot",
  "physicalDigest", "everEnrolled", "ownerGeneration", "ownerCutoverDigest"]);
const PIN_FIELDS = Object.freeze(["operatorId", "tlsServerFingerprint256",
  "signingPublicKey"]);
const OWNER_PIN_FIELDS = Object.freeze(["canonicalZkAccountId", "signingPublicKey"]);
const HEX = /^[0-9a-f]{64}$/;
const FP = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i;
const B64 = /^[A-Za-z0-9_-]+$/;
const ID = /^[a-z][a-z0-9_-]{2,63}$/;
const CURRENT_PATH = "/v1/zk10/current";
const CAS_PATH = "/v1/zk10/cutover/cas";
const APPLY = Reflect.apply;
const VERIFY = crypto.verify;
const HASH = crypto.createHash;
const CLOCK = Date.now.bind(Date);

function unavailable() {
  const e = new Error("ZK10_EXTERNAL_CAS_UNAVAILABLE");
  e.code = e.message;
  throw e;
}
function uncertain() {
  const e = new Error("ZK10_EXTERNAL_CAS_UNCERTAIN");
  e.code = e.message;
  throw e;
}
function exact(record, fields) {
  if (record === null || typeof record !== "object" || Array.isArray(record)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(record))
    || Reflect.ownKeys(record).length !== fields.length) unavailable();
  const output = {};
  for (const field of fields) {
    const desc = Object.getOwnPropertyDescriptor(record, field);
    if (!desc || !Object.hasOwn(desc, "value")) unavailable();
    output[field] = desc.value;
  }
  return output;
}
function hex(v) { if (typeof v !== "string" || !HEX.test(v)) unavailable(); return v; }
function integer(v, low, high) {
  if (!Number.isSafeInteger(v) || v < low || v > high) unavailable();
  return v;
}
function bool(v) { if (typeof v !== "boolean") unavailable(); return v; }
function bytes(v, n) {
  if (typeof v !== "string" || !B64.test(v)) unavailable();
  const b = Buffer.from(v, "base64url");
  if (b.length !== n || b.toString("base64url") !== v) unavailable();
  return v;
}
function publicKey(k) {
  if (!(k instanceof crypto.KeyObject) || k.type !== "public"
    || k.asymmetricKeyType !== "ed25519") unavailable();
  return k;
}
function signatureParts(wire, fields, domain, key) {
  const { signature, ...others } = exact(wire, [...fields, "signature"]);
  const data = Object.fromEntries(fields.map((field) => [field, others[field]]));
  const sig = Buffer.from(bytes(signature, 64), "base64url");
  if (!APPLY(VERIFY, crypto, [null, Buffer.concat([domain,
    Buffer.from(JSON.stringify(data), "utf8")]), key, sig])) unavailable();
  return { data, sig };
}
function digestHead(wire, operatorKey) {
  const { data, sig } = signatureParts(wire, HEAD_FIELDS, HEAD_DOMAIN, operatorKey);
  const digest = HASH("sha256").update(HEAD_DOMAIN).update(JSON.stringify(data))
    .update(sig).digest("hex");
  return { data, digest };
}
function floor(v) {
  const f = exact(v, MINIMUM_FIELDS);
  integer(f.sequence, 1, Number.MAX_SAFE_INTEGER - 1024);
  hex(f.headDigest);
  hex(f.enrollmentRoot);
  hex(f.physicalDigest);
  bool(f.everEnrolled);
  integer(f.ownerGeneration, 0, Number.MAX_SAFE_INTEGER - 1024);
  // Initial cutover only. Owner rotation/second-generation transitions need
  // their own independently validated history protocol.
  if (f.ownerGeneration > 1) unavailable();
  if ((f.everEnrolled !== (f.ownerGeneration > 0))
    || ((f.ownerCutoverDigest === null) !== (f.ownerGeneration === 0))) unavailable();
  if (f.ownerCutoverDigest !== null) hex(f.ownerCutoverDigest);
  return Object.freeze(f);
}
function validateHead(h, accountId, operatorId) {
  if (h.type !== "rootark-zk10-operator-account-head/v1"
    || h.operator_id !== operatorId || h.immutable_account_id !== accountId) unavailable();
  integer(h.sequence, 1, Number.MAX_SAFE_INTEGER - 1024);
  hex(h.previous_head_digest);
  hex(h.enrollment_root);
  hex(h.physical_digest);
  bool(h.ever_enrolled);
  integer(h.owner_generation, 0, Number.MAX_SAFE_INTEGER - 1024);
  if (h.owner_generation > 1) unavailable();
  if (h.ever_enrolled !== (h.owner_generation > 0)
    || (h.owner_cutover_digest === null) !== (h.owner_generation === 0)) unavailable();
  if (h.owner_cutover_digest !== null) hex(h.owner_cutover_digest);
  return h;
}
function snapshotOwner(wire) {
  // Clone before any await: application objects/arrays are otherwise mutable.
  try { return JSON.parse(JSON.stringify(wire)); }
  catch (_) { unavailable(); }
}

class Zk10ExternalOwnerCutoverCasClient {
  #operatorId;
  #operatorKey;
  #ownerKey;
  #zkAccount;
  #accountId;
  #identityDigest;
  #minimum;
  #exchange;
  #state = "idle";
  #pending = null;
  constructor({ immutableAccountId, identityDigest, pinnedOperator, pinnedOwner,
    independentlyRetainedMinimum, transport } = {}) {
    this.#accountId = bytes(immutableAccountId, 16);
    this.#identityDigest = hex(identityDigest);
    const op = exact(pinnedOperator, PIN_FIELDS);
    const owner = exact(pinnedOwner, OWNER_PIN_FIELDS);
    if (typeof op.operatorId !== "string" || !ID.test(op.operatorId)
      || typeof op.tlsServerFingerprint256 !== "string"
      || !FP.test(op.tlsServerFingerprint256)) unavailable();
    this.#operatorId = op.operatorId;
    this.#operatorKey = publicKey(op.signingPublicKey);
    this.#ownerKey = publicKey(owner.signingPublicKey);
    this.#zkAccount = bytes(owner.canonicalZkAccountId, 16);
    this.#minimum = floor(independentlyRetainedMinimum);
    if (!transport || typeof transport !== "object" || Array.isArray(transport)
      || Object.getPrototypeOf(transport) !== Object.prototype
      || Reflect.ownKeys(transport).length !== 3
      || transport.operatorHostId !== op.operatorId
      || transport.tlsServerFingerprint256?.toUpperCase()
        !== op.tlsServerFingerprint256.toUpperCase()
      || typeof transport.exchange !== "function") unavailable();
    // This injected transport is NOT a verified TLS channel by itself.
    // Production code must provision real mTLS, independent pins and custody.
    this.#exchange = transport.exchange.bind(transport);
    Object.freeze(this);
  }
  get authorizesProductionCutover() { return false; }
  get state() { return this.#state; }
  async #send(path, body) {
    try {
      // A remote timeout/partition must be bounded; cancelling the transport
      // does not prove that its remote CAS did not already commit.
      let timer;
      return await Promise.race([
        Promise.resolve().then(() => this.#exchange(path, body)),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(Error("REMOTE_UNAVAILABLE")), 5000);
        }),
      ]).finally(() => clearTimeout(timer));
    } catch (_) { unavailable(); }
  }
  async readCurrent() {
    try {
      const challenge = crypto.randomBytes(32).toString("base64url");
      const request = {
        immutable_account_id: this.#accountId,
        identity_digest: this.#identityDigest,
        minimum_sequence: this.#minimum.sequence,
        minimum_head_digest: this.#minimum.headDigest,
        challenge,
      };
      const wire = exact(await this.#send(CURRENT_PATH, Object.freeze(request)),
        ["head_chain", "current"]);
      if (!Array.isArray(wire.head_chain) || wire.head_chain.length > 128
        || Reflect.ownKeys(wire.head_chain).length !== wire.head_chain.length + 1) unavailable();
      let head = { sequence: this.#minimum.sequence,
        digest: this.#minimum.headDigest,
        enrollment_root: this.#minimum.enrollmentRoot,
        physical_digest: this.#minimum.physicalDigest,
        ever_enrolled: this.#minimum.everEnrolled,
        owner_generation: this.#minimum.ownerGeneration,
        owner_cutover_digest: this.#minimum.ownerCutoverDigest };
      for (const signedHead of wire.head_chain) {
        const next = digestHead(signedHead, this.#operatorKey);
        validateHead(next.data, this.#accountId, this.#operatorId);
        if (next.data.sequence !== head.sequence + 1
          || next.data.previous_head_digest !== head.digest
          || (head.ever_enrolled && !next.data.ever_enrolled)
          || next.data.owner_generation < head.owner_generation
          || (head.ever_enrolled && next.data.owner_generation === head.owner_generation
            && next.data.owner_cutover_digest !== head.owner_cutover_digest)) unavailable();
        head = { ...next.data, digest: next.digest };
      }
      const cur = signatureParts(wire.current, CURRENT_FIELDS, CURRENT_DOMAIN, this.#operatorKey).data;
      const at = CLOCK();
      if (cur.type !== "rootark-zk10-operator-account-current/v1"
        || cur.operator_id !== this.#operatorId || cur.immutable_account_id !== this.#accountId
        || cur.identity_digest !== this.#identityDigest || cur.challenge !== challenge
        || cur.head_sequence !== head.sequence || cur.head_digest !== head.digest
        || cur.enrollment_root !== head.enrollment_root
        || cur.physical_digest !== head.physical_digest
        || cur.ever_enrolled !== head.ever_enrolled
        || cur.owner_generation !== head.owner_generation
        || cur.owner_cutover_digest !== head.owner_cutover_digest
        || !Number.isSafeInteger(cur.issued_at_ms) || cur.issued_at_ms < at - 30000
        || cur.issued_at_ms > at + 1000
        || !Number.isSafeInteger(cur.expires_at_ms)
        || cur.expires_at_ms <= at || cur.expires_at_ms > at + 10000) unavailable();
      if (cur.status === "never_enrolled") {
        if (cur.ever_enrolled !== false || cur.owner_statement !== null
          || cur.owner_generation !== 0 || cur.owner_cutover_digest !== null) unavailable();
      } else if (cur.status === "protected_enforced") {
        if (!cur.ever_enrolled || cur.owner_generation < 1) unavailable();
        const owner = verifyOwnerCutover(cur.owner_statement, this.#ownerKey);
        if (owner.immutable_account_id !== this.#accountId
          || owner.zk_account_id !== this.#zkAccount
          || owner.generation !== cur.owner_generation
          || digestOwnerCutover(cur.owner_statement) !== cur.owner_cutover_digest) unavailable();
      } else unavailable();
      try {
        verifySparseEnrollmentProof(this.#accountId, cur.owner_cutover_digest,
          cur.siblings, cur.enrollment_root);
      } catch (_) { unavailable(); }
      return Object.freeze({
        status: cur.status, sequence: head.sequence,
        headDigest: head.digest, enrollmentRoot: head.enrollment_root,
        physicalDigest: head.physical_digest, everEnrolled: head.ever_enrolled,
        ownerGeneration: head.owner_generation,
        ownerCutoverDigest: head.owner_cutover_digest,
        authorizesProductionCutover: false,
      });
    } catch (_) { unavailable(); }
  }
  async submitCutover({ ownerStatement, leaseId, fencingEpoch, leaseExpiresAtMs } = {}) {
    if (this.#state !== "idle") uncertain();
    let owner, ownerDigest, statement;
    try {
      statement = snapshotOwner(ownerStatement);
      owner = verifyOwnerCutover(statement, this.#ownerKey);
      ownerDigest = digestOwnerCutover(statement);
      if (owner.immutable_account_id !== this.#accountId
        || owner.zk_account_id !== this.#zkAccount
        || this.#minimum.everEnrolled
        || owner.generation !== this.#minimum.ownerGeneration + 1
        || owner.previous_cutover_digest !== this.#minimum.ownerCutoverDigest
        || owner.issued_at > Math.floor(CLOCK() / 1000) + 60
        || owner.issued_at < Math.floor(CLOCK() / 1000) - 300) unavailable();
      bytes(leaseId, 16);
      integer(fencingEpoch, 1, Number.MAX_SAFE_INTEGER - 1024);
      integer(leaseExpiresAtMs, CLOCK() + 100, CLOCK() + 10000);
      // Reserve this client's sole mutation slot before the first await.
      // A second local caller must never issue another simultaneous CAS.
      this.#state = "preflighting";
      const observed = await this.readCurrent();
      if (observed.status !== "never_enrolled"
        || observed.sequence !== this.#minimum.sequence
        || observed.headDigest !== this.#minimum.headDigest
        || observed.physicalDigest !== this.#minimum.physicalDigest) unavailable();
      // Preflight may consume most of a short physical lease. Do not issue a
      // CAS after its expiry even if the request was valid before the await.
      integer(leaseExpiresAtMs, CLOCK() + 100, CLOCK() + 10000);
    } catch (_) {
      if (this.#state === "preflighting") this.#state = "idle";
      unavailable();
    }
    const challenge = crypto.randomBytes(32).toString("base64url");
    const request = Object.freeze({
      type: "rootark-zk10-operator-cutover-cas-intent/v1",
      immutable_account_id: this.#accountId, identity_digest: this.#identityDigest,
      owner_statement: statement, owner_cutover_digest: ownerDigest,
      expected_sequence: this.#minimum.sequence,
      expected_head_digest: this.#minimum.headDigest,
      expected_enrollment_root: this.#minimum.enrollmentRoot,
      expected_physical_digest: this.#minimum.physicalDigest,
      lease_id: leaseId, fencing_epoch: fencingEpoch,
      lease_expires_at_ms: leaseExpiresAtMs,
      challenge,
    });
    this.#state = "uncertain"; // BEFORE the outbound CAS; loss of ACK is indeterminate.
    this.#pending = Object.freeze({ ownerDigest, expected: this.#minimum.headDigest,
      leaseId, fencingEpoch, leaseExpiresAtMs, challenge });
    try {
      const response = exact(await this.#send(CAS_PATH, request), ["receipt"]);
      const receipt = signatureParts(response.receipt,
        RECEIPT_FIELDS, RECEIPT_DOMAIN, this.#operatorKey).data;
      if (receipt.type !== "rootark-zk10-operator-cutover-receipt/v1"
        || receipt.operator_id !== this.#operatorId
        || receipt.immutable_account_id !== this.#accountId
        || receipt.owner_cutover_digest !== ownerDigest
        || receipt.expected_sequence !== this.#minimum.sequence
        || receipt.expected_head_digest !== this.#minimum.headDigest
        || receipt.lease_id !== leaseId || receipt.fencing_epoch !== fencingEpoch
        || receipt.lease_expires_at_ms !== leaseExpiresAtMs
        || receipt.challenge !== challenge || receipt.status !== "committed") uncertain();
      // Even a correctly signed receipt proves neither independent retention
      // nor physical PG fencing. Require a NEW signed CURRENT readback.
      return Object.freeze({ state: "uncertain",
        authorizesProductionCutover: false, requiresReadback: true });
    } catch (_) { uncertain(); }
  }
  async reconcile() {
    if (this.#pending === null) unavailable();
    let current;
    try { current = await this.readCurrent(); }
    catch (_) { this.#state = "quarantined"; unavailable(); }
    if (current.sequence === this.#minimum.sequence
      && current.headDigest === this.#minimum.headDigest
      && current.status === "never_enrolled") {
      // The remote request might still be in flight. Never retry automatically.
      return Object.freeze({ state: "uncertain", authorizesProductionCutover: false });
    }
    if (current.status !== "protected_enforced"
      || current.sequence !== this.#minimum.sequence + 1
      || current.ownerCutoverDigest !== this.#pending.ownerDigest) {
      this.#state = "quarantined"; unavailable();
    }
    // A signed account CURRENT alone cannot attribute the successor HEAD to
    // *this* lost-ACK CAS. Demand another nonce-signed, operation-specific
    // readback tying the original lease/epoch/owner digest to the same HEAD.
    try {
      const challenge = crypto.randomBytes(32).toString("base64url");
      const request = Object.freeze({
        immutable_account_id: this.#accountId,
        identity_digest: this.#identityDigest,
        owner_cutover_digest: this.#pending.ownerDigest,
        expected_head_digest: this.#pending.expected,
        lease_id: this.#pending.leaseId,
        fencing_epoch: this.#pending.fencingEpoch,
        lease_expires_at_ms: this.#pending.leaseExpiresAtMs,
        challenge,
      });
      const wire = exact(await this.#send("/v1/zk10/cutover/readback", request), ["readback"]);
      const readback = signatureParts(wire.readback, READBACK_FIELDS,
        READBACK_DOMAIN, this.#operatorKey).data;
      if (readback.type !== "rootark-zk10-operator-cutover-readback/v1"
        || readback.operator_id !== this.#operatorId
        || readback.immutable_account_id !== this.#accountId
        || readback.identity_digest !== this.#identityDigest
        || readback.lease_id !== this.#pending.leaseId
        || readback.fencing_epoch !== this.#pending.fencingEpoch
        || readback.owner_cutover_digest !== this.#pending.ownerDigest
        || readback.expected_head_digest !== this.#pending.expected
        || readback.lease_expires_at_ms !== this.#pending.leaseExpiresAtMs
        || readback.observed_head_digest !== current.headDigest
        || readback.observed_physical_digest !== current.physicalDigest
        || readback.challenge !== challenge
        || readback.decision !== "committed") unavailable();
    } catch (_) {
      this.#state = "quarantined";
      unavailable();
    }
    this.#state = "observed_protected";
    return Object.freeze({
      state: "observed_protected", observedSequence: current.sequence,
      observedHeadDigest: current.headDigest,
      observedPhysicalDigest: current.physicalDigest,
      authorizesProductionCutover: false,
    });
  }
}
function createZk10ExternalOwnerCutoverCasClient(args) {
  exact(args, ["immutableAccountId", "identityDigest", "pinnedOperator",
    "pinnedOwner", "independentlyRetainedMinimum", "transport"]);
  return new Zk10ExternalOwnerCutoverCasClient(args);
}
module.exports = { createZk10ExternalOwnerCutoverCasClient };
