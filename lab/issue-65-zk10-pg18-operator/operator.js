"use strict";

// DEV-OFF ONLY: a disposable PostgreSQL18-backed protocol fixture.
// The retained PG row is NOT an externally held floor or a physical I/O stop.
const crypto = require("node:crypto");
const https = require("node:https");
const { verifyOwnerCutover, digestOwnerCutover, buildSparseEnrollmentProof } =
  require("../../src/crypto/rootark-zk10-account-cutover-v1");

const HEAD = Buffer.from("Root.ark/zk10/operator-account-head/v1\0");
const CURRENT = Buffer.from("Root.ark/zk10/operator-account-current/v1\0");
const RECEIPT = Buffer.from("Root.ark/zk10/operator-cutover-receipt/v1\0");
const READBACK = Buffer.from("Root.ark/zk10/operator-cutover-readback/v1\0");
const HEAD_FIELDS = ["type", "operator_id", "immutable_account_id", "sequence",
  "previous_head_digest", "enrollment_root", "physical_digest", "ever_enrolled",
  "owner_generation", "owner_cutover_digest"];
const RECEIPT_FIELDS = ["type", "operator_id", "immutable_account_id",
  "owner_cutover_digest", "expected_sequence", "expected_head_digest",
  "lease_id", "fencing_epoch", "lease_expires_at_ms", "challenge", "status"];
const MAX_BODY = 65536;
const B64 = /^[A-Za-z0-9_-]+$/;
const HEX = /^[a-f0-9]{64}$/;
const fail = () => { throw Error("ZK10_DEV_OPERATOR_REJECTED"); };
function id(v, size) {
  if (typeof v !== "string" || !B64.test(v)) fail();
  const b = Buffer.from(v, "base64url");
  if (b.length !== size || b.toString("base64url") !== v) fail();
  return v;
}
function hex(v) { if (typeof v !== "string" || !HEX.test(v)) fail(); return v; }
function integer(v, min, max) { if (!Number.isSafeInteger(v) || v < min || v > max) fail(); return v; }
function exactly(obj, keys) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(obj))
    || Reflect.ownKeys(obj).length !== keys.length) fail();
  for (const k of keys) {
    const prop = Object.getOwnPropertyDescriptor(obj, k);
    if (!prop || !Object.hasOwn(prop, "value")) fail();
  }
  return obj;
}
function sign(domain, payload, key) {
  return { ...payload, signature: crypto.sign(null, Buffer.concat([
    domain, Buffer.from(JSON.stringify(payload), "utf8"),
  ]), key).toString("base64url") };
}
function headDigest(wire) {
  const { signature, ...head } = wire;
  return crypto.createHash("sha256").update(HEAD).update(JSON.stringify(head))
    .update(Buffer.from(id(signature, 64), "base64url")).digest("hex");
}
function assertHeadSignature(wire, publicKey) {
  exactly(wire, [...HEAD_FIELDS, "signature"]);
  const { signature, ...payload } = wire;
  if (!crypto.verify(null, Buffer.concat([HEAD,
    Buffer.from(JSON.stringify(payload), "utf8")]), publicKey,
  Buffer.from(id(signature, 64), "base64url"))) fail();
}
function assertReceiptSignature(wire, publicKey) {
  exactly(wire, [...RECEIPT_FIELDS, "signature"]);
  const { signature, ...payload } = wire;
  if (payload.type !== "rootark-zk10-operator-cutover-receipt/v1"
    || payload.status !== "committed") fail();
  id(payload.immutable_account_id, 16);
  id(payload.lease_id, 16);
  id(payload.challenge, 32);
  hex(payload.owner_cutover_digest);
  hex(payload.expected_head_digest);
  integer(payload.expected_sequence, 1, 2);
  integer(payload.fencing_epoch, 1, Number.MAX_SAFE_INTEGER - 1024);
  integer(payload.lease_expires_at_ms, 1, Number.MAX_SAFE_INTEGER);
  if (!crypto.verify(null, Buffer.concat([RECEIPT,
    Buffer.from(JSON.stringify(payload), "utf8")]), publicKey,
  Buffer.from(id(signature, 64), "base64url"))) fail();
  return payload;
}
function assertOperatorIdentity(config) {
  id(config.immutableAccountId, 16);
  id(config.canonicalZkAccountId, 16);
  hex(config.identityDigest); hex(config.initialPhysicalDigest);
  if (!/^[a-z][a-z0-9_-]{2,63}$/.test(config.operatorId)) fail();
  for (const [key, kind] of [[config.operatorPrivateKey, "private"],
    [config.operatorPublicKey, "public"], [config.ownerPublicKey, "public"]]) {
    if (!(key instanceof crypto.KeyObject) || key.type !== kind
      || key.asymmetricKeyType !== "ed25519") fail();
  }
}
function createZk10Pg18Operator(config) {
  exactly(config, ["pool", "operatorId", "immutableAccountId",
    "canonicalZkAccountId", "identityDigest", "initialPhysicalDigest",
    "operatorPrivateKey", "operatorPublicKey", "ownerPublicKey"]);
  assertOperatorIdentity(config);
  const account = config.immutableAccountId;
  const opId = config.operatorId;
  const pool = config.pool;
  if (!pool || typeof pool.connect !== "function" || typeof pool.query !== "function") fail();

  function getFloor(record) {
    const h = JSON.parse(record.head_json);
    assertHeadSignature(h, config.operatorPublicKey);
    if (h.immutable_account_id !== account || h.operator_id !== opId
      || h.sequence !== Number(record.sequence)) fail();
    return h;
  }
  async function initialize() {
    // Schema is local-lab only; never run this DDL against a production pool.
    await pool.query(`CREATE SCHEMA IF NOT EXISTS zk10_dev_operator;
      CREATE TABLE IF NOT EXISTS zk10_dev_operator.account_head (
        account_id TEXT PRIMARY KEY, sequence BIGINT NOT NULL,
        head_json TEXT NOT NULL, previous_head_json TEXT,
        owner_statement_json TEXT, owner_digest TEXT,
        cas_receipt_json TEXT
      )`);
    const proof = buildSparseEnrollmentProof([], account);
    const genesis = sign(HEAD, {
      type: "rootark-zk10-operator-account-head/v1",
      operator_id: opId, immutable_account_id: account,
      sequence: 1, previous_head_digest: "0".repeat(64),
      enrollment_root: proof.root,
      physical_digest: config.initialPhysicalDigest,
      ever_enrolled: false, owner_generation: 0, owner_cutover_digest: null,
    }, config.operatorPrivateKey);
    await pool.query(`INSERT INTO zk10_dev_operator.account_head
      (account_id, sequence, head_json) VALUES ($1, 1, $2)
      ON CONFLICT (account_id) DO NOTHING`, [account, JSON.stringify(genesis)]);
    const r = await pool.query(`SELECT * FROM zk10_dev_operator.account_head
      WHERE account_id=$1`, [account]);
    if (r.rowCount !== 1) fail();
    const existing = getFloor(r.rows[0]);
    if (existing.sequence < 1 || existing.sequence > 2
      || (existing.sequence === 1 && headDigest(existing) !== headDigest(genesis))) fail();
    return minimum();
  }
  async function minimum() {
    const r = await pool.query(`SELECT * FROM zk10_dev_operator.account_head
      WHERE account_id=$1`, [account]);
    if (r.rowCount !== 1) fail();
    const h = getFloor(r.rows[0]);
    return Object.freeze({ sequence: h.sequence, headDigest: headDigest(h),
      enrollmentRoot: h.enrollment_root, physicalDigest: h.physical_digest,
      everEnrolled: h.ever_enrolled, ownerGeneration: h.owner_generation,
      ownerCutoverDigest: h.owner_cutover_digest });
  }
  function identity(req) {
    if (req.immutable_account_id !== account
      || req.identity_digest !== config.identityDigest) fail();
  }
  async function current(req) {
    exactly(req, ["immutable_account_id", "identity_digest", "minimum_sequence",
      "minimum_head_digest", "challenge"]);
    identity(req); id(req.challenge, 32);
    integer(req.minimum_sequence, 1, 2); hex(req.minimum_head_digest);
    const r = await pool.query(`SELECT * FROM zk10_dev_operator.account_head
      WHERE account_id=$1`, [account]);
    if (r.rowCount !== 1) fail();
    const entry = r.rows[0]; const h = getFloor(entry);
    let headChain;
    if (h.sequence === req.minimum_sequence && headDigest(h) === req.minimum_head_digest) {
      headChain = [];
    } else if (h.sequence === req.minimum_sequence + 1 && entry.previous_head_json) {
      const previous = JSON.parse(entry.previous_head_json);
      assertHeadSignature(previous, config.operatorPublicKey);
      if (headDigest(previous) !== req.minimum_head_digest) fail();
      headChain = [h];
    } else fail();
    const ownerStatement = entry.owner_statement_json
      ? JSON.parse(entry.owner_statement_json) : null;
    const entries = h.ever_enrolled
      ? [{ accountId: account, cutoverDigest: h.owner_cutover_digest }] : [];
    const proof = buildSparseEnrollmentProof(entries, account);
    if (proof.root !== h.enrollment_root) fail();
    const now = Date.now();
    const current = sign(CURRENT, {
      type: "rootark-zk10-operator-account-current/v1",
      operator_id: opId, immutable_account_id: account,
      identity_digest: config.identityDigest, head_sequence: h.sequence,
      head_digest: headDigest(h), enrollment_root: h.enrollment_root,
      physical_digest: h.physical_digest, ever_enrolled: h.ever_enrolled,
      status: h.ever_enrolled ? "protected_enforced" : "never_enrolled",
      owner_generation: h.owner_generation,
      owner_cutover_digest: h.owner_cutover_digest,
      owner_statement: ownerStatement, siblings: proof.siblings,
      challenge: req.challenge, issued_at_ms: now, expires_at_ms: now + 5000,
    }, config.operatorPrivateKey);
    return { head_chain: headChain, current };
  }
  async function cas(req) {
    exactly(req, ["type", "immutable_account_id", "identity_digest",
      "owner_statement", "owner_cutover_digest", "expected_sequence",
      "expected_head_digest", "expected_enrollment_root", "expected_physical_digest",
      "lease_id", "fencing_epoch", "lease_expires_at_ms", "challenge"]);
    if (req.type !== "rootark-zk10-operator-cutover-cas-intent/v1") fail();
    identity(req); id(req.challenge, 32); id(req.lease_id, 16);
    integer(req.fencing_epoch, 1, Number.MAX_SAFE_INTEGER - 1024);
    const now = Date.now();
    integer(req.lease_expires_at_ms, now + 100, now + 10000);
    const owner = verifyOwnerCutover(req.owner_statement, config.ownerPublicKey);
    const digest = digestOwnerCutover(req.owner_statement);
    if (owner.immutable_account_id !== account
      || owner.zk_account_id !== config.canonicalZkAccountId
      || owner.generation !== 1 || owner.previous_cutover_digest !== null
      || owner.issued_at < Math.floor(now / 1000) - 300
      || owner.issued_at > Math.floor(now / 1000) + 60
      || req.owner_cutover_digest !== digest) fail();
    const conn = await pool.connect();
    try {
      await conn.query("BEGIN");
      const r = await conn.query(`SELECT * FROM zk10_dev_operator.account_head
        WHERE account_id=$1 FOR UPDATE`, [account]);
      if (r.rowCount !== 1) fail();
      const row = r.rows[0], previous = getFloor(row);
      if (previous.sequence !== 1 || previous.ever_enrolled
        || req.expected_sequence !== 1
        || req.expected_head_digest !== headDigest(previous)
        || req.expected_enrollment_root !== previous.enrollment_root
        || req.expected_physical_digest !== previous.physical_digest
        || Date.now() + 100 >= req.lease_expires_at_ms) fail();
      const proof = buildSparseEnrollmentProof([
        { accountId: account, cutoverDigest: digest }], account);
      const next = sign(HEAD, {
        type: "rootark-zk10-operator-account-head/v1",
        operator_id: opId, immutable_account_id: account, sequence: 2,
        previous_head_digest: headDigest(previous),
        enrollment_root: proof.root, physical_digest: previous.physical_digest,
        ever_enrolled: true, owner_generation: 1, owner_cutover_digest: digest,
      }, config.operatorPrivateKey);
      const receipt = sign(RECEIPT, {
        type: "rootark-zk10-operator-cutover-receipt/v1",
        operator_id: opId, immutable_account_id: account,
        owner_cutover_digest: digest, expected_sequence: 1,
        expected_head_digest: headDigest(previous),
        lease_id: req.lease_id, fencing_epoch: req.fencing_epoch,
        lease_expires_at_ms: req.lease_expires_at_ms,
        challenge: req.challenge, status: "committed",
      }, config.operatorPrivateKey);
      await conn.query(`UPDATE zk10_dev_operator.account_head
        SET sequence=2, previous_head_json=$2, head_json=$3,
          owner_statement_json=$4, owner_digest=$5, cas_receipt_json=$6
        WHERE account_id=$1`, [account, JSON.stringify(previous),
        JSON.stringify(next), JSON.stringify(req.owner_statement),
        digest, JSON.stringify(receipt)]);
      // Best-effort local expiry recheck before SQL COMMIT. This is not a
      // physical account-wide lease or a guarantee about post-COMMIT egress.
      if (Date.now() + 100 >= req.lease_expires_at_ms) fail();
      await conn.query("COMMIT");
      return { receipt };
    } catch (error) {
      try { await conn.query("ROLLBACK"); } catch (_) { /* original failure */ }
      fail();
    } finally { conn.release(); }
  }
  async function readback(req) {
    exactly(req, ["immutable_account_id", "identity_digest",
      "owner_cutover_digest", "expected_head_digest", "lease_id",
      "fencing_epoch", "lease_expires_at_ms", "challenge"]);
    identity(req); id(req.challenge, 32); id(req.lease_id, 16);
    hex(req.owner_cutover_digest); hex(req.expected_head_digest);
    integer(req.fencing_epoch, 1, Number.MAX_SAFE_INTEGER - 1024);
    integer(req.lease_expires_at_ms, 1, Number.MAX_SAFE_INTEGER);
    const r = await pool.query(`SELECT * FROM zk10_dev_operator.account_head
      WHERE account_id=$1`, [account]);
    if (r.rowCount !== 1 || !r.rows[0].cas_receipt_json
      || !r.rows[0].previous_head_json || !r.rows[0].owner_statement_json) fail();
    const row = r.rows[0];
    const receipt = assertReceiptSignature(JSON.parse(row.cas_receipt_json),
      config.operatorPublicKey);
    const h = getFloor(row);
    const previous = JSON.parse(row.previous_head_json);
    assertHeadSignature(previous, config.operatorPublicKey);
    const owner = JSON.parse(row.owner_statement_json);
    const signedOwner = verifyOwnerCutover(owner, config.ownerPublicKey);
    if (previous.sequence !== 1 || previous.ever_enrolled !== false
      || previous.owner_generation !== 0 || previous.owner_cutover_digest !== null
      || previous.immutable_account_id !== account || previous.operator_id !== opId
      || h.previous_head_digest !== headDigest(previous)
      || h.sequence !== 2 || h.ever_enrolled !== true
      || h.owner_generation !== 1 || h.physical_digest !== previous.physical_digest
      || signedOwner.immutable_account_id !== account
      || signedOwner.zk_account_id !== config.canonicalZkAccountId
      || signedOwner.generation !== 1 || signedOwner.previous_cutover_digest !== null
      || digestOwnerCutover(owner) !== h.owner_cutover_digest
      || row.owner_digest !== h.owner_cutover_digest
      || receipt.operator_id !== opId || receipt.immutable_account_id !== account
      || receipt.expected_sequence !== previous.sequence
      || receipt.expected_head_digest !== headDigest(previous)
      || h.owner_cutover_digest !== req.owner_cutover_digest
      || receipt.owner_cutover_digest !== req.owner_cutover_digest
      || receipt.expected_head_digest !== req.expected_head_digest
      || receipt.lease_id !== req.lease_id
      || receipt.fencing_epoch !== req.fencing_epoch
      || receipt.lease_expires_at_ms !== req.lease_expires_at_ms) fail();
    return { readback: sign(READBACK, {
      type: "rootark-zk10-operator-cutover-readback/v1",
      operator_id: opId, immutable_account_id: account,
      identity_digest: config.identityDigest,
      lease_id: receipt.lease_id, fencing_epoch: receipt.fencing_epoch,
      owner_cutover_digest: receipt.owner_cutover_digest,
      expected_head_digest: receipt.expected_head_digest,
      lease_expires_at_ms: receipt.lease_expires_at_ms,
      observed_head_digest: headDigest(h),
      observed_physical_digest: h.physical_digest,
      challenge: req.challenge, decision: "committed",
    }, config.operatorPrivateKey) };
  }
  return Object.freeze({ initialize, minimum, current, cas, readback,
    authorizesProductionCutover: false });
}

function createZk10Pg18OperatorHttpsServer({ operator, tls, clientFingerprint256,
  dropCasAckOnce = false }) {
  let drop = dropCasAckOnce;
  const server = https.createServer({
    key: tls.key, cert: tls.cert, ca: tls.ca, requestCert: true,
    rejectUnauthorized: true, minVersion: "TLSv1.3", maxVersion: "TLSv1.3",
  }, (req, res) => {
    const peer = req.socket.getPeerCertificate();
    if (req.method !== "POST" || !req.socket.authorized
      || req.socket.getProtocol() !== "TLSv1.3"
      || peer.fingerprint256 !== clientFingerprint256) {
      res.writeHead(403); res.end(); return;
    }
    let size = 0; const chunks = [];
    req.on("data", (part) => {
      size += part.length;
      if (size > MAX_BODY) req.destroy(); else chunks.push(part);
    });
    req.on("end", async () => {
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        const result = req.url === "/v1/zk10/current"
          ? await operator.current(body)
          : req.url === "/v1/zk10/cutover/cas"
            ? await operator.cas(body)
            : req.url === "/v1/zk10/cutover/readback"
              ? await operator.readback(body) : fail();
        if (drop && req.url === "/v1/zk10/cutover/cas") {
          drop = false;
          req.socket.destroy(); // Simulated lost ACK AFTER a committed PG transaction.
          return;
        }
        const bytes = Buffer.from(JSON.stringify(result));
        res.writeHead(200, { "content-type": "application/json",
          "content-length": bytes.length }); res.end(bytes);
      } catch (_) {
        res.writeHead(503, { "content-type": "application/json" });
        res.end('{"error":"ZK10_DEV_OPERATOR_REJECTED"}');
      }
    });
  });
  return server;
}
module.exports = { createZk10Pg18Operator, createZk10Pg18OperatorHttpsServer };
